"""
find_player.py — Usa o CT do Recifense para encontrar o ponteiro estático do jogador.

O CT revela:
  - MOHP hook: instrução `MOV RAX, [R15+0x108]` onde R15 = pPlayer
  - pPlayer+0x108 = ponteiro para o bloco de recursos (pRes)
  - pRes+0x00 = food, +0x08 = wood, +0x10 = gold, +0x18 = stone (valores criptografados)
  - Decriptação: XOR key1, ADD key2, XOR key3, ADD key4

  Constantes de decriptação do CT (patch 63482):
    ENR0 = 0x0A0EAF5AD8EDFA7D  (XOR)
    ENR1 = 0x28E80EFC7B994CFA  (ADD)
    ENR2 = 0xE61E551E72771845  (XOR)
    ENR3 = 0x7A196A1176CC8745  (ADD)

  Este script:
  1. Encontra a instrução MOHP via signature scan
  2. Varre os arredores procurando onde R15 é carregado (MOV R15, [RIP+disp32])
  3. Se encontrar, resolve o ponteiro estático e lê recursos por ele
  4. Também tenta decriptação com as constantes ENR do CT
"""

import struct
import sys
import ctypes
from ctypes import wintypes

try:
    import pymem
    import pymem.exception
except ImportError:
    print("Instale: pip install pymem pywin32")
    sys.exit(1)

PROCESS = "AoE2DE_s.exe"

# Signature do hook MOHP (CT do Recifense, patch 63482)
# MOV RAX,[R15+108] | MOV RCX,[RAX+20] | MOV [RSP+70],RCX | MOV RAX,[RSP+70] | XOR RAX,RDI
MOHP_SIG  = bytes.fromhex("498B870801000048 8B 48 20 48 89 4C 24 70 48 8B 44 24 70 48 33 C7".replace(" ",""))
MOHP_MASK = bytes([0xFF]*len(MOHP_SIG))

# Padrões de carregamento de R15 em x86-64:
#   MOV R15, [RIP+disp32]  →  4C 8B 3D XX XX XX XX
#   MOV R15, [REG+disp32]  →  4D 8B BC XX XX XX XX XX (várias formas)
R15_PATTERNS = [
    (bytes.fromhex("4C8B3D"), 3, 7),   # MOV R15, [RIP+disp32]
    (bytes.fromhex("4D8BBF"), 3, 7),   # MOV R15, [R15+disp32]
    (bytes.fromhex("4C8B7D"), 3, 4),   # MOV R15, [RBP+disp8]
    (bytes.fromhex("4C8BBD"), 3, 7),   # MOV R15, [RBP+disp32]
]

# Constantes de decriptação do CT (para patch 63482)
ENR0 = 0x0A0EAF5AD8EDFA7D
ENR1 = 0x28E80EFC7B994CFA
ENR2 = 0xE61E551E72771845
ENR3 = 0x7A196A1176CC8745
MASK64 = 0xFFFFFFFFFFFFFFFF


def decrypt_resource(raw64: int) -> float:
    """Decriptação: XOR ENR0, ADD ENR1, XOR ENR2, ADD ENR3 → float."""
    v = raw64
    v = (v ^ ENR0) & MASK64
    v = (v + ENR1) & MASK64
    v = (v ^ ENR2) & MASK64
    v = (v + ENR3) & MASK64
    return struct.unpack("<f", struct.pack("<I", v & 0xFFFFFFFF))[0]


def _get_regions(pm):
    class MBI(ctypes.Structure):
        _fields_ = [("BaseAddress", ctypes.c_void_p), ("AllocationBase", ctypes.c_void_p),
                    ("AllocationProtect", wintypes.DWORD), ("RegionSize", ctypes.c_size_t),
                    ("State", wintypes.DWORD), ("Protect", wintypes.DWORD), ("Type", wintypes.DWORD)]
    k32 = ctypes.WinDLL("kernel32")
    mbi, addr = MBI(), 0
    while addr < 0x7FFFFFFFFFFF:
        if not k32.VirtualQueryEx(pm.process_handle, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)):
            break
        base, size = mbi.BaseAddress or 0, mbi.RegionSize or 0
        if mbi.State == 0x1000 and mbi.Protect & (0x02|0x04|0x20|0x40|0x80) and size > 0:
            is_module = pm.base_address <= base < pm.base_address + 0x5000000
            yield base, size, is_module
        nxt = base + size
        addr = nxt if nxt > addr else addr + 0x1000


def scan_signature(pm, sig: bytes) -> int | None:
    pat_len = len(sig)
    print(f"  Procurando MOHP signature ({pat_len} bytes)...", end="", flush=True)
    for base, size, is_module in _get_regions(pm):
        if not is_module:
            continue   # MOHP está no módulo do executável
        try:
            chunk = pm.read_bytes(base, size)
        except Exception:
            continue
        for i in range(len(chunk) - pat_len):
            if chunk[i:i+pat_len] == sig:
                print(f" OK → 0x{base+i:X}")
                return base + i
    print(" NÃO ENCONTRADA")
    return None


def find_r15_source(pm, mohp_addr: int, scan_back: int = 0x800) -> list[int]:
    """
    Varre os `scan_back` bytes ANTES de mohp_addr buscando instruções
    que carregam R15 via RIP-relative (MOV R15, [RIP+disp32]).
    Retorna lista de endereços estáticos candidatos.
    """
    search_start = max(pm.base_address, mohp_addr - scan_back)
    try:
        chunk = pm.read_bytes(search_start, mohp_addr - search_start + 0x10)
    except Exception:
        return []

    candidates = []
    for i in range(len(chunk) - 7):
        # MOV R15, [RIP+disp32] = 4C 8B 3D XX XX XX XX
        if chunk[i:i+3] == bytes.fromhex("4C8B3D"):
            instr_addr = search_start + i
            disp32 = struct.unpack_from("<i", chunk, i + 3)[0]
            target  = instr_addr + 7 + disp32
            candidates.append(target)
            print(f"    MOV R15,[RIP+0x{disp32:X}]  @0x{instr_addr:X}  →  static=0x{target:X}")

    return candidates


def try_read_resources(pm, p_player: int) -> None:
    """Tenta ler recursos via pPlayer → [+0x108] → pRes → recursos."""
    try:
        p_res_raw = pm.read_longlong(p_player + 0x108)
        print(f"    [pPlayer+0x108] = 0x{p_res_raw:X}")
    except Exception as e:
        print(f"    ERRO lendo [pPlayer+0x108]: {e}")
        return

    if not (0x10000 < p_res_raw < 0x7FFFFFFFFFFF):
        print(f"    Valor inválido como ponteiro.")
        return

    p_res = p_res_raw
    labels = ["food", "wood", "gold", "stone"]
    offsets = [0x00, 0x08, 0x10, 0x18]

    print(f"\n    {'Campo':<8} {'Raw (hex)':<20} {'Float bruto':>14} {'Decriptado':>14}")
    print(f"    {'-'*60}")
    for label, off in zip(labels, offsets):
        try:
            raw = pm.read_longlong(p_res + off) & MASK64
            as_float_raw  = struct.unpack("<f", struct.pack("<I", raw & 0xFFFFFFFF))[0]
            as_float_dec  = decrypt_resource(raw)
            plausible_raw = 0 <= as_float_raw < 100000
            plausible_dec = 0 <= as_float_dec < 100000
            tag_r = " ✓" if plausible_raw else ""
            tag_d = " ✓" if plausible_dec else ""
            print(f"    {label:<8} 0x{raw:<18X} {as_float_raw:>12.1f}{tag_r}  {as_float_dec:>12.1f}{tag_d}")
        except Exception as e:
            print(f"    {label:<8} ERRO: {e}")


def main():
    try:
        pm = pymem.Pymem(PROCESS)
        print(f"Conectado — PID {pm.process_id}  base 0x{pm.base_address:X}\n")
    except pymem.exception.ProcessNotFound:
        print(f"Processo '{PROCESS}' não encontrado.")
        sys.exit(1)

    print("=" * 60)
    print("  PASSO 1 — Encontrar instrução MOHP")
    print("=" * 60)
    mohp_addr = scan_signature(pm, MOHP_SIG)

    if mohp_addr is None:
        print("\n  MOHP não encontrada neste patch.")
        print("  O patch atual pode ter bytecodes diferentes.")
        sys.exit(0)

    print(f"\n  MOHP em: 0x{mohp_addr:X}  (RVA: exe+0x{mohp_addr - pm.base_address:X})")

    print("\n" + "=" * 60)
    print("  PASSO 2 — Encontrar onde R15 (pPlayer) é carregado")
    print("=" * 60)
    candidates = find_r15_source(pm, mohp_addr)

    if not candidates:
        print("  Nenhuma instrução MOV R15,[RIP+disp] encontrada nos 2KB anteriores.")
        print("  R15 pode ser carregado mais longe ou por outro padrão.")
    else:
        print(f"\n  {len(candidates)} candidato(s) encontrado(s).")

        print("\n" + "=" * 60)
        print("  PASSO 3 — Tentando ler recursos via cada candidato")
        print("=" * 60)
        for i, cand in enumerate(candidates, 1):
            print(f"\n  Candidato {i}: static ptr @ 0x{cand:X}")
            try:
                p_player = pm.read_longlong(cand)
                print(f"    *ptr = 0x{p_player:X}")
                if 0x10000 < p_player < 0x7FFFFFFFFFFF:
                    try_read_resources(pm, p_player)
                else:
                    print(f"    Valor não parece um ponteiro válido.")
            except Exception as e:
                print(f"    ERRO: {e}")

    print("\n" + "=" * 60)
    print("  Cole a saída completa aqui.")
    print("=" * 60)


if __name__ == "__main__":
    main()
