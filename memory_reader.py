"""
memory_reader.py — Leitura de memória do AoE2DE em tempo real via pymem.

Não usa endereços absolutos: todos os valores são resolvidos por
signature scanning sobre as regiões de memória do processo.
O polling roda em background thread e emite eventos via callback
quando o estado do jogo muda de forma relevante.
"""

from __future__ import annotations

import json
import logging
import struct
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

try:
    import pymem
    import pymem.process
    import pymem.pattern
    import pymem.exception
except ImportError:
    raise ImportError("pymem não encontrado. Execute: pip install pymem")

logger = logging.getLogger(__name__)

OFFSETS_FILE = Path(__file__).parent / "offsets.json"
PROCESS_NAME = "AoE2DE_s.exe"
POLL_INTERVAL = 3.0  # segundos

AGE_NAMES = {0: "Dark", 1: "Feudal", 2: "Castle", 3: "Imperial"}


# ---------------------------------------------------------------------------
# Estado do jogo
# ---------------------------------------------------------------------------

@dataclass
class GameState:
    game_time_seconds: int = 0
    current_age: int = 0          # 0=Dark 1=Feudal 2=Castle 3=Imperial
    researching_age: bool = False  # True se um age-up está em progresso
    tc_count: int = 0
    idle_tc: int = 0
    tc_queue: int = 0              # total de unidades em fila em todos os TCs
    villagers: int = 0
    villagers_producing: int = 0   # aldeões sendo produzidos (em fila)
    food: float = 0.0
    wood: float = 0.0
    gold: float = 0.0
    stone: float = 0.0

    def age_name(self) -> str:
        return AGE_NAMES.get(self.current_age, "?")

    def game_time_str(self) -> str:
        m, s = divmod(self.game_time_seconds, 60)
        return f"{m:02d}:{s:02d}"

    def as_dict(self) -> dict:
        return {
            "game_time": self.game_time_str(),
            "age": self.age_name(),
            "researching_age": self.researching_age,
            "tc_count": self.tc_count,
            "idle_tcs": self.idle_tc,
            "tc_queue": self.tc_queue,
            "villagers": self.villagers,
            "villagers_producing": self.villagers_producing,
            "food": int(self.food),
            "wood": int(self.wood),
            "gold": int(self.gold),
            "stone": int(self.stone),
        }

    def is_significant_change(self, other: "GameState") -> bool:
        """Retorna True quando a mudança justifica chamar o coach."""
        if self.idle_tc != other.idle_tc:
            return True
        if self.current_age != other.current_age:
            return True
        if self.researching_age != other.researching_age:
            return True
        # mudança de >=5 aldeões
        if abs(self.villagers - other.villagers) >= 5:
            return True
        # recurso caiu abaixo de 0 (não deve acontecer, mas serve como gate)
        for attr in ("food", "wood", "gold", "stone"):
            new_val = getattr(self, attr)
            old_val = getattr(other, attr)
            if new_val <= 0 < old_val:
                return True
        return False


# ---------------------------------------------------------------------------
# Signature scanning
# ---------------------------------------------------------------------------

def _parse_signature(sig_str: str) -> bytes:
    """Converte '48 8B 05 ?? ?? ?? ??' em bytes com ?? → 0x00 (máscara separada)."""
    return bytes(int(b, 16) if b != "??" else 0 for b in sig_str.split())


def _build_mask(sig_str: str) -> bytes:
    """Máscara: 0xFF para bytes fixos, 0x00 para wildcards."""
    return bytes(0xFF if b != "??" else 0x00 for b in sig_str.split())


def _scan_pattern(pm: pymem.Pymem, pattern: bytes, mask: bytes,
                  start: int = 0, size: int = 0x7FFFFFFF) -> Optional[int]:
    """
    Varre a memória do processo procurando pelo padrão com máscara.
    Retorna o endereço da primeira ocorrência ou None.
    """
    pat_len = len(pattern)
    region_base = pm.base_address

    try:
        # Itera sobre as regiões de memória MEM_COMMIT com permissão de leitura
        import ctypes
        from ctypes import wintypes

        class MEMORY_BASIC_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("BaseAddress",       ctypes.c_void_p),
                ("AllocationBase",    ctypes.c_void_p),
                ("AllocationProtect", wintypes.DWORD),
                ("RegionSize",        ctypes.c_size_t),
                ("State",             wintypes.DWORD),
                ("Protect",           wintypes.DWORD),
                ("Type",              wintypes.DWORD),
            ]

        MEM_COMMIT  = 0x1000
        PAGE_READABLE = (0x02 | 0x04 | 0x20 | 0x40 | 0x80)  # R, RW, ER, ERW, ERWC

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        mbi = MEMORY_BASIC_INFORMATION()
        addr = start

        while addr < start + size:
            result = kernel32.VirtualQueryEx(
                pm.process_handle,
                ctypes.c_void_p(addr),
                ctypes.byref(mbi),
                ctypes.sizeof(mbi),
            )
            if not result:
                break

            region_end = (mbi.BaseAddress or 0) + (mbi.RegionSize or 0)

            if (mbi.State == MEM_COMMIT and mbi.Protect & PAGE_READABLE
                    and mbi.RegionSize > 0):
                try:
                    chunk = pm.read_bytes(mbi.BaseAddress, mbi.RegionSize)
                    for i in range(len(chunk) - pat_len):
                        if all(
                            (chunk[i + j] & mask[j]) == (pattern[j] & mask[j])
                            for j in range(pat_len)
                        ):
                            return (mbi.BaseAddress or 0) + i
                except Exception:
                    pass

            addr = region_end if region_end > addr else addr + 0x1000

    except Exception as exc:
        logger.debug("Erro ao varrer memória: %s", exc)

    return None


def resolve_rip_relative(pm: pymem.Pymem, instr_addr: int,
                          offset_field: int = 3, instr_size: int = 7) -> int:
    """
    Resolve um endereço RIP-relative típico de instruções x86-64.

      MOV RAX, [RIP + disp32]   →   48 8B 05 <disp32>
      offset_field = 3  (bytes até o disp32)
      instr_size   = 7  (tamanho total da instrução)
    """
    raw = pm.read_bytes(instr_addr + offset_field, 4)
    disp32 = struct.unpack("<i", raw)[0]
    return instr_addr + instr_size + disp32


# ---------------------------------------------------------------------------
# MemoryReader
# ---------------------------------------------------------------------------

class MemoryReader:
    """
    Anexa ao processo AoE2DE.exe e lê o estado do jogo periodicamente.

    Uso:
        reader = MemoryReader(on_state_change=minha_callback)
        reader.start()
        ...
        reader.stop()
    """

    def __init__(self, on_state_change: Optional[Callable[[GameState], None]] = None,
                 poll_interval: float = POLL_INTERVAL):
        self.on_state_change = on_state_change
        self.poll_interval = poll_interval

        self._pm: Optional[pymem.Pymem] = None
        self._resolved: dict[str, int] = {}   # nome → endereço virtual resolvido
        self._sigs: dict[str, str] = {}
        self._offsets_raw: dict[str, str] = {}

        self._state = GameState()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

        self._load_offsets()

    # ------------------------------------------------------------------
    # Offsets
    # ------------------------------------------------------------------

    def _load_offsets(self) -> None:
        try:
            data = json.loads(OFFSETS_FILE.read_text(encoding="utf-8"))
            self._sigs        = data.get("signatures", {})
            self._offsets_raw = data.get("offsets", {})
            # Campos marcados como "direct" foram obtidos via Cheat Engine —
            # endereço final já conhecido, sem necessidade de RIP-relative.
            self._direct: set[str] = set(data.get("direct", []))
            logger.info("Offsets carregados (patch %s)", data.get("patch_version", "?"))
        except FileNotFoundError:
            logger.warning("offsets.json não encontrado — calibração necessária.")
            self._direct: set[str] = set()

    def _resolve_addresses(self) -> None:
        """
        Para cada campo, tenta resolver o endereço real de duas formas:
          1. Se o offset salvo != 0x0, usa-o diretamente.
          2. Senão, faz signature scanning e extrai o endereço RIP-relative.
        """
        if self._pm is None:
            return

        for name, sig_str in self._sigs.items():
            saved = int(self._offsets_raw.get(name, "0x0"), 16)

            if saved != 0:
                # Endereço direto (Cheat Engine) — usa sem qualquer resolução
                if name in self._direct:
                    self._resolved[name] = saved
                    logger.debug("%-20s → 0x%X (direto)", name, saved)
                    continue

                # Endereço resolvido pelo calibrate — usa direto também
                self._resolved[name] = saved
                logger.debug("%-20s → 0x%X (calibrado)", name, saved)
                continue

            # Nenhum endereço salvo — tenta signature scanning
            pattern = _parse_signature(sig_str)
            mask    = _build_mask(sig_str)
            addr    = _scan_pattern(self._pm, pattern, mask,
                                    self._pm.base_address)
            if addr is None:
                logger.warning("Signature não encontrada: %s", name)
                continue

            try:
                resolved = resolve_rip_relative(self._pm, addr)
                self._resolved[name] = resolved
                logger.debug("%-20s → 0x%X (scan)", name, resolved)
            except Exception as exc:
                logger.warning("Falha ao resolver %s: %s", name, exc)

    # ------------------------------------------------------------------
    # Leitura de valores
    # ------------------------------------------------------------------

    def _read_int(self, name: str, default: int = 0) -> int:
        addr = self._resolved.get(name)
        if addr is None or self._pm is None:
            return default
        try:
            return self._pm.read_int(addr)
        except Exception:
            return default

    def _read_float(self, name: str, default: float = 0.0) -> float:
        addr = self._resolved.get(name)
        if addr is None or self._pm is None:
            return default
        try:
            return self._pm.read_float(addr)
        except Exception:
            return default

    def _read_bool(self, name: str) -> bool:
        addr = self._resolved.get(name)
        if addr is None or self._pm is None:
            return False
        try:
            return bool(self._pm.read_uchar(addr))
        except Exception:
            return False

    def _read_state(self) -> GameState:
        s = GameState()
        s.tc_count            = self._read_int("tc_count")
        s.villagers           = self._read_int("villager_count")
        s.villagers_producing = self._read_int("tc_queue")
        s.tc_queue            = self._read_int("tc_queue")
        s.idle_tc             = self._read_int("idle_tc")
        s.food                = self._read_float("food")
        s.wood                = self._read_float("wood")
        s.gold                = self._read_float("gold")
        s.stone               = self._read_float("stone")
        s.game_time_seconds   = self._read_int("game_time")
        s.current_age         = max(0, min(3, self._read_int("current_age")))
        s.researching_age     = self._read_bool("age_research")
        return s

    # ------------------------------------------------------------------
    # Thread de polling
    # ------------------------------------------------------------------

    def _attach(self) -> bool:
        try:
            self._pm = pymem.Pymem(PROCESS_NAME)
            logger.info("Anexado ao processo %s (PID %d)",
                        PROCESS_NAME, self._pm.process_id)
            self._resolve_addresses()
            return True
        except pymem.exception.ProcessNotFound:
            logger.warning("Processo %s não encontrado. Aguardando...", PROCESS_NAME)
            return False
        except Exception as exc:
            logger.error("Erro ao anexar: %s", exc)
            return False

    def _poll_loop(self) -> None:
        while self._running:
            if self._pm is None:
                if not self._attach():
                    time.sleep(5)
                    continue

            try:
                new_state = self._read_state()
            except pymem.exception.ProcessError:
                logger.warning("Processo encerrado. Tentando reanexar...")
                self._pm = None
                time.sleep(5)
                continue
            except Exception as exc:
                logger.debug("Erro de leitura: %s", exc)
                time.sleep(self.poll_interval)
                continue

            with self._lock:
                old_state = self._state
                self._state = new_state

            if self.on_state_change and new_state.is_significant_change(old_state):
                try:
                    self.on_state_change(new_state)
                except Exception as exc:
                    logger.error("Erro no callback on_state_change: %s", exc)

            time.sleep(self.poll_interval)

    # ------------------------------------------------------------------
    # API pública
    # ------------------------------------------------------------------

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._poll_loop,
                                        name="MemoryReader", daemon=True)
        self._thread.start()
        logger.info("MemoryReader iniciado.")

    def stop(self) -> None:
        self._running = False
        if self._thread:
            self._thread.join(timeout=10)
        logger.info("MemoryReader parado.")

    @property
    def state(self) -> GameState:
        with self._lock:
            return self._state

    @property
    def connected(self) -> bool:
        return self._pm is not None
