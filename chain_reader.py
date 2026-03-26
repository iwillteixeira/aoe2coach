"""
chain_reader.py — Lê recursos via cadeia de ponteiros do SDK AoE2DE.

Cadeia A (jogador local, via tribePanelInven):
  *[base + TRIBEPANEL_RVA]   →  TribePanelInven*
  TribePanelInven + 0x208    →  Player*  (local)
  Player + 0x070             →  Resources*
  Resources + 0x000          →  food   (float32)
  Resources + 0x004          →  wood   (float32)
  Resources + 0x008          →  stone  (float32)
  Resources + 0x00C          →  gold   (float32)
  Resources + 0x018          →  age    (float32, 0=Dark…3=Imperial)
  Resources + 0x02C          →  currentPop (float32)

Cadeia B (todos os jogadores, via PathfindingSystem → World → PlayerArray):
  *[base + PATHFINDING_RVA]  →  PathfindingSystem*
  PathfindingSystem + 0x018  →  World*
  World + 0x080              →  gameTime (int32)
  World + 0x2A8              →  PlayerArray*  (entries de 0x10 bytes)
  PlayerArray[i] + 0x000     →  Player*  (0=Gaia, 1-8=jogadores)

Offsets de struct baseados no Age_of_Empires_II_Definitive-Edition-SDK.

Uso:
    python chain_reader.py
    python chain_reader.py --all-players
    python chain_reader.py --tribepanel-rva 0x2BA7190
    python chain_reader.py --pathfinding-rva 0x2BB80D0
"""

import argparse
import json
import struct
import sys
import time
from pathlib import Path

try:
    import pymem
    import pymem.exception
except ImportError:
    print("pip install pymem pywin32")
    sys.exit(1)

OFFSETS_FILE = Path(__file__).parent / "offsets.json"

PROCESS = "AoE2DE_s.exe"
MASK64  = 0xFFFFFFFFFFFFFFFF
PTR_MIN = 0x10000
PTR_MAX = 0x7FFFFFFFFFFF

# RVAs do SDK (relativos ao base do módulo).
# Podem quebrar após patches; use --tribepanel-rva / --pathfinding-rva para corrigir.
TRIBEPANEL_RVA   = 0x2BA7190   # tribePanelInven
PATHFINDING_RVA  = 0x2BB80D0   # pathfindingSystem

# Assinaturas AOB para re-escaneamento após patches (do SDK)
AOB_TRIBEPANEL        = "48 8B 0D ?? ?? ?? ?? 48 85 C9 0F 84 ?? ?? ?? ?? 40"
AOB_PATHFINDING       = "48 8D 0D ?? ?? ?? ?? 41 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0"
# Offset do jogador local dentro de TribePanelInven (lido como bytes literais)
AOB_LOCALPLAYER_OFF   = "48 8B 83 ?? ?? ?? ?? 48 8B 48 70 F3 0F 10"

# Offsets de struct — carregados dinamicamente do offsets.json (fallback abaixo)
OFF_TRIBEPANEL_LOCALPLAYER = 0x208   # TribePanelInven → Player* (pode variar por patch)
OFF_PLAYER_RESOURCES       = 0x070   # Player → Resources*
OFF_PATHFINDING_WORLD      = 0x018   # PathfindingSystem → World*
OFF_WORLD_GAMETIME         = 0x080   # World → int32 game time
OFF_WORLD_PLAYERARRAY      = 0x2A8   # World → PlayerArray*
SIZEOF_PLAYERARRAY_ENTRY   = 0x10    # cada entrada da PlayerArray

# Offsets dentro de Resources (todos float32)
OFF_RES_FOOD    = 0x00
OFF_RES_WOOD    = 0x04
OFF_RES_STONE   = 0x08
OFF_RES_GOLD    = 0x0C
OFF_RES_AGE     = 0x18
OFF_RES_POP     = 0x2C

AGE_NAMES = {0: "Dark", 1: "Feudal", 2: "Castle", 3: "Imperial"}


# ---------------------------------------------------------------------------
# Helpers de leitura
# ---------------------------------------------------------------------------

def rptr(pm, addr):
    """Lê ponteiro de 64 bits; retorna None se inválido."""
    try:
        v = pm.read_longlong(addr) & MASK64
        return v if PTR_MIN < v < PTR_MAX else None
    except Exception:
        return None


def rint(pm, addr):
    try:
        return pm.read_int(addr)
    except Exception:
        return None


def rfloat(pm, addr):
    try:
        return pm.read_float(addr)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Scan direto por valor float32 na memória do processo
# ---------------------------------------------------------------------------

def direct_scan_resources(pm, food_hint, tol=2.0):
    """
    Escaneia toda a memória do processo procurando float32 ≈ food_hint.
    Para cada hit, verifica se os floats vizinhos parecem wood/stone/gold.
    Retorna lista de (food_addr, food, wood, stone, gold) ordenada por plausibilidade.
    """
    import ctypes
    from ctypes import wintypes

    class MBI(ctypes.Structure):
        _fields_ = [
            ("BaseAddress",       ctypes.c_void_p),
            ("AllocationBase",    ctypes.c_void_p),
            ("AllocationProtect", wintypes.DWORD),
            ("RegionSize",        ctypes.c_size_t),
            ("State",             wintypes.DWORD),
            ("Protect",           wintypes.DWORD),
            ("Type",              wintypes.DWORD),
        ]

    MEM_COMMIT    = 0x1000
    PAGE_READABLE = 0x02 | 0x04 | 0x20 | 0x40 | 0x80
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)

    target = struct.pack("<f", food_hint)
    results = []
    addr = 0

    print(f"  Escaneando memória por food≈{food_hint:.0f}...", flush=True)

    while addr < 0x7FFFFFFFFFFF:
        mbi = MBI()
        if not k32.VirtualQueryEx(pm.process_handle, ctypes.c_void_p(addr),
                                  ctypes.byref(mbi), ctypes.sizeof(mbi)):
            break
        base = mbi.BaseAddress or 0
        size = mbi.RegionSize or 0

        if mbi.State == MEM_COMMIT and mbi.Protect & PAGE_READABLE and size >= 4:
            try:
                chunk = pm.read_bytes(base, size)
                for i in range(0, len(chunk) - 15, 4):
                    f = struct.unpack_from("<f", chunk, i)[0]
                    if abs(f - food_hint) > tol or f != f:
                        continue
                    # Lê wood/stone/gold nos 4 bytes seguintes
                    wood  = struct.unpack_from("<f", chunk, i +  4)[0] if i +  8 <= len(chunk) else None
                    stone = struct.unpack_from("<f", chunk, i +  8)[0] if i + 12 <= len(chunk) else None
                    gold  = struct.unpack_from("<f", chunk, i + 12)[0] if i + 16 <= len(chunk) else None
                    if wood is None or stone is None or gold is None:
                        continue
                    if wood != wood or stone != stone or gold != gold:
                        continue  # NaN
                    if not (0 <= wood <= 100000 and 0 <= stone <= 100000 and 0 <= gold <= 100000):
                        continue
                    results.append((base + i, f, wood, stone, gold))
            except Exception:
                pass

        end = base + size
        addr = end if end > addr else addr + 0x1000

    return results


# ---------------------------------------------------------------------------
# AOB scanning — usa scanner.exe (C++) se disponível, senão Python puro
# ---------------------------------------------------------------------------

SCANNER_EXE = Path(__file__).parent / "scanner.exe"


def _scanner_exe_scan(patterns) -> dict[str, int | None]:
    """
    Chama scanner.exe com os padrões e retorna {label: valor | None}.
    patterns: lista de (label, aob_str, field, param, mode)
      mode: "rip" (padrão) ou "bytes"
    """
    import subprocess

    args = [str(SCANNER_EXE), PROCESS]
    for entry in patterns:
        label, sig, field, param = entry[:4]
        mode = entry[4] if len(entry) > 4 else "rip"
        args.append(f"{label}:{sig}:{mode}:{field}:{param}")

    try:
        out = subprocess.check_output(args, timeout=120, text=True)
        data = json.loads(out.strip())
        return {k: int(v, 16) if v else None for k, v in data.items()}
    except Exception as e:
        print(f"  scanner.exe falhou ({e}) — usando scan Python como fallback")
        return {}


def _parse_aob(sig_str):
    pat  = bytes(int(b, 16) if b != "??" else 0 for b in sig_str.split())
    mask = bytes(0xFF        if b != "??" else 0  for b in sig_str.split())
    return pat, mask


def _aob_scan_python(pm, sig_str):
    """Scan AOB em Python puro (lento, fallback quando scanner.exe não existe)."""
    import ctypes
    from ctypes import wintypes

    class MBI(ctypes.Structure):
        _fields_ = [
            ("BaseAddress",       ctypes.c_void_p),
            ("AllocationBase",    ctypes.c_void_p),
            ("AllocationProtect", wintypes.DWORD),
            ("RegionSize",        ctypes.c_size_t),
            ("State",             wintypes.DWORD),
            ("Protect",           wintypes.DWORD),
            ("Type",              wintypes.DWORD),
        ]

    MEM_COMMIT    = 0x1000
    PAGE_READABLE = 0x02 | 0x04 | 0x20 | 0x40 | 0x80
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)

    pat, mask = _parse_aob(sig_str)
    plen = len(pat)
    addr = 0

    while addr < 0x7FFFFFFFFFFF:
        mbi = MBI()
        if not k32.VirtualQueryEx(pm.process_handle, ctypes.c_void_p(addr),
                                  ctypes.byref(mbi), ctypes.sizeof(mbi)):
            break
        base = mbi.BaseAddress or 0
        size = mbi.RegionSize or 0
        end  = base + size

        if mbi.State == MEM_COMMIT and mbi.Protect & PAGE_READABLE and size > plen:
            try:
                chunk = pm.read_bytes(base, size)
                for i in range(len(chunk) - plen):
                    if all((chunk[i+j] & mask[j]) == (pat[j] & mask[j])
                           for j in range(plen)):
                        return base + i
            except Exception:
                pass

        addr = end if end > addr else addr + 0x1000

    return None


def resolve_rip(pm, instr_addr, field=3, instr_size=7):
    """Resolve disp32 RIP-relative."""
    try:
        raw = pm.read_bytes(instr_addr + field, 4)
        disp = struct.unpack("<i", raw)[0]
        return instr_addr + instr_size + disp
    except Exception:
        return None


def save_rva(key, value, section="static_rvas"):
    """Persiste valor no offsets.json (_sdk_chain.<section>)."""
    try:
        data = json.loads(OFFSETS_FILE.read_text(encoding="utf-8"))
        data.setdefault("_sdk_chain", {}).setdefault(section, {})[key] = hex(value)
        OFFSETS_FILE.write_text(json.dumps(data, indent=2, ensure_ascii=False),
                                encoding="utf-8")
        print(f"  → offsets.json atualizado: [{section}] {key} = 0x{value:X}")
    except Exception as e:
        print(f"  → aviso: não foi possível salvar em offsets.json: {e}")


def aob_scan_all(pm, base, patterns) -> dict[str, int]:
    """
    Escaneia múltiplos padrões em uma única passagem pela memória.
    patterns: [(label, aob_str, field, param[, mode]), ...]
      mode: "rip" (padrão) → retorna RVA  |  "bytes" → retorna valor literal
    Retorna {label: valor} para os encontrados.
    Usa scanner.exe (C++, rápido) se disponível; caso contrário, Python puro.
    """
    if not patterns:
        return {}

    if SCANNER_EXE.exists():
        print(f"  AOB scan via scanner.exe (C++)")
        results = _scanner_exe_scan(patterns)
    else:
        print(f"  AOB scan via Python puro (compile scanner/ para acelerar)")
        results = {}

    if not results:
        # Fallback Python — suporta apenas modo "rip" (resolve_rip)
        for entry in patterns:
            label, sig, field, param = entry[:4]
            mode = entry[4] if len(entry) > 4 else "rip"
            hit = _aob_scan_python(pm, sig)
            if hit:
                if mode == "bytes":
                    try:
                        raw = pm.read_bytes(hit + field, param)
                        val = int.from_bytes(raw, "little")
                        results[label] = val
                    except Exception:
                        pass
                else:
                    resolved = resolve_rip(pm, hit, field, param)
                    if resolved:
                        results[label] = resolved - base

    return results


def find_static_ptr(pm, base, rva, aob_sig, aob_field=3, aob_instr_size=7, label="",
                    offsets_key=None):
    """Tenta base+rva primeiro; se falhar, faz AOB scan e salva o novo RVA."""
    static_addr = base + rva
    ptr = rptr(pm, static_addr)
    if ptr is not None:
        print(f"  {label}: base + 0x{rva:X}  →  0x{static_addr:X}  →  ptr=0x{ptr:X}  [RVA ok]")
        return static_addr, ptr

    print(f"  {label}: RVA 0x{rva:X} inválido — iniciando AOB scan...", flush=True)
    results = aob_scan_all(pm, base, [(label, aob_sig, aob_field, aob_instr_size)])
    new_rva = results.get(label)
    if not new_rva:
        print(f"  {label}: não encontrado.")
        return None, None

    resolved = base + new_rva
    ptr = rptr(pm, resolved)
    if ptr is None:
        print(f"  {label}: new_rva=0x{new_rva:X}  ptr=inválido")
        return None, None
    print(f"  {label}: new_rva=0x{new_rva:X}  ptr=0x{ptr:X}")
    return resolved, ptr


# ---------------------------------------------------------------------------
# Busca por força bruta do offset Player* dentro de TribePanelInven
# ---------------------------------------------------------------------------

def probe_localplayer_offset(pm, tribe_ptr,
                              off_start=0x000, off_end=0x800, step=8,
                              food_hint=None, tol=5.0):
    """
    Varre offsets dentro de tribe_ptr procurando Player* válido.
    Para cada candidato Player*, testa múltiplos offsets possíveis de Resources*
    (não assume 0x70 — tenta 0x40..0x180).

    Se food_hint fornecido, filtra pelo valor de food.
    """
    def sane(v):
        return v is not None and 0.0 <= v <= 100_000.0

    # Offsets candidatos para Resources* dentro de Player*
    res_offsets = list(range(0x40, 0x180, 8))

    print(f"  Sondando offsets 0x{off_start:X}..0x{off_end:X} em TribePanelInven, "
          f"testando {len(res_offsets)} offsets de Resources* por candidato...", flush=True)

    candidates = []
    for off in range(off_start, off_end, step):
        candidate = rptr(pm, tribe_ptr + off)
        if candidate is None:
            continue

        for res_off in res_offsets:
            p_res = rptr(pm, candidate + res_off)
            if p_res is None:
                continue
            food  = rfloat(pm, p_res + OFF_RES_FOOD)
            wood  = rfloat(pm, p_res + OFF_RES_WOOD)
            stone = rfloat(pm, p_res + OFF_RES_STONE)
            gold  = rfloat(pm, p_res + OFF_RES_GOLD)
            age   = rfloat(pm, p_res + OFF_RES_AGE)

            if not (sane(food) and sane(wood) and sane(stone) and sane(gold)):
                continue
            try:
                if age is None or age != age or round(age) not in (0, 1, 2, 3):
                    continue
            except (ValueError, OverflowError):
                continue
            if food_hint is not None and abs(food - food_hint) > tol:
                continue

            candidates.append((off, res_off, candidate, p_res, food, wood, stone, gold, age))
            print(f"  Candidato Player*+0x{off:X}  Resources*+0x{res_off:X}  "
                  f"food={food:.0f} wood={wood:.0f} stone={stone:.0f} "
                  f"gold={gold:.0f} age={int(round(age))}")

    if not candidates:
        if food_hint is not None:
            print(f"  Nenhum candidato com food≈{food_hint:.0f}.")
            print(f"  Dica: rode sem --food-hint para listar todos, "
                  f"ou aumente o range com --probe-end 0xC00")
        else:
            print("  Nenhum candidato encontrado.")
        return None, None

    # Prefere candidato com food mais próximo do hint (ou maior food)
    if food_hint is not None:
        best = min(candidates, key=lambda c: abs(c[4] - food_hint))
    else:
        best = max(candidates, key=lambda c: c[4])

    off, res_off, ptr, p_res, food, *_ = best

    if res_off != OFF_PLAYER_RESOURCES:
        print(f"\n  *** ATENÇÃO: Resources* está em Player+0x{res_off:X} "
              f"(SDK dizia 0x{OFF_PLAYER_RESOURCES:X}) ***")
        print(f"  Salvando novo offset de Resources* em offsets.json...")
        save_rva("Player_Resources", res_off, section="struct_offsets")

    return off, ptr


# ---------------------------------------------------------------------------
# Leitura de recursos de um Player*
# ---------------------------------------------------------------------------

def read_resources(pm, p_player):
    """Lê Resources de um Player*. Retorna dict ou None."""
    p_res = rptr(pm, p_player + OFF_PLAYER_RESOURCES)
    if p_res is None:
        return None
    d = {}
    d["food"]  = rfloat(pm, p_res + OFF_RES_FOOD)
    d["wood"]  = rfloat(pm, p_res + OFF_RES_WOOD)
    d["stone"] = rfloat(pm, p_res + OFF_RES_STONE)
    d["gold"]  = rfloat(pm, p_res + OFF_RES_GOLD)
    age_raw    = rfloat(pm, p_res + OFF_RES_AGE)
    d["age"]   = AGE_NAMES.get(int(age_raw) if age_raw is not None else -1, "?")
    d["pop"]   = rfloat(pm, p_res + OFF_RES_POP)
    d["_resources_ptr"] = p_res
    return d


def print_resources(label, d):
    if d is None:
        print(f"  {label}: falha ao ler Resources")
        return
    print(f"  {label}:")
    print(f"    food={d['food']:.0f}  wood={d['wood']:.0f}  "
          f"stone={d['stone']:.0f}  gold={d['gold']:.0f}")
    print(f"    age={d['age']}  pop={d['pop']:.0f}")
    print(f"    (Resources* = 0x{d['_resources_ptr']:X})")


# ---------------------------------------------------------------------------
# Cadeia A: tribePanelInven → jogador local
# ---------------------------------------------------------------------------

def _probe_resources_offset(pm, p_player, food_hint=None, tol=5.0):
    """Testa offsets 0x40..0x200 (step 8) dentro de Player* procurando Resources*."""
    def sane(v):
        return v is not None and v == v and 0.0 <= v <= 100_000.0

    for res_off in range(0x40, 0x200, 8):
        p_res = rptr(pm, p_player + res_off)
        if p_res is None:
            continue
        food  = rfloat(pm, p_res + OFF_RES_FOOD)
        wood  = rfloat(pm, p_res + OFF_RES_WOOD)
        stone = rfloat(pm, p_res + OFF_RES_STONE)
        gold  = rfloat(pm, p_res + OFF_RES_GOLD)
        age   = rfloat(pm, p_res + OFF_RES_AGE)
        if not (sane(food) and sane(wood) and sane(stone) and sane(gold)):
            continue
        try:
            if age is None or round(age) not in (0, 1, 2, 3):
                continue
        except (ValueError, OverflowError):
            continue
        if food_hint is not None and abs(food - food_hint) > tol:
            continue
        print(f"  *** Novo offset encontrado: Player+0x{res_off:X}  "
              f"food={food:.0f} wood={wood:.0f} stone={stone:.0f} gold={gold:.0f} ***")
        save_rva("Player_Resources", res_off, section="struct_offsets")
        global OFF_PLAYER_RESOURCES
        OFF_PLAYER_RESOURCES = res_off
        d = {"food": food, "wood": wood, "stone": stone, "gold": gold,
             "age": AGE_NAMES.get(int(round(age)), "?"),
             "pop": rfloat(pm, p_res + OFF_RES_POP),
             "_resources_ptr": p_res}
        return d
    print("  Nenhum offset de Resources* encontrado.")
    return None


def chain_local_player(pm, base, tribepanel_rva, localplayer_off=None, food_hint=None):
    print("\n[Cadeia A] tribePanelInven → jogador local")
    static_addr, tribe_ptr = find_static_ptr(
        pm, base, tribepanel_rva, AOB_TRIBEPANEL,
        aob_field=3, aob_instr_size=7, label="tribePanelInven",
        offsets_key="tribePanelInven"
    )
    if tribe_ptr is None:
        return None

    def _needs_rescan(p_player, hint):
        """Retorna True se o ponteiro é inválido ou se food não bate com o hint."""
        if p_player is None:
            return True
        if hint is None:
            return False
        res = read_resources(pm, p_player)
        if res is None:
            return True
        return abs(res["food"] - hint) > 5.0

    off = localplayer_off if localplayer_off is not None else OFF_TRIBEPANEL_LOCALPLAYER
    p_player = rptr(pm, tribe_ptr + off)

    if _needs_rescan(p_player, food_hint):
        reason = "ponteiro inválido" if p_player is None else \
                 f"food={rfloat(pm, rptr(pm, p_player+OFF_PLAYER_RESOURCES) or 0) or '?':.0f} ≠ hint {food_hint:.0f}"
        print(f"  TribePanelInven + 0x{off:X}: {reason} — re-escaneando offset...")

        results = aob_scan_all(pm, base,
            [("TribePanelInven_localPlayer", AOB_LOCALPLAYER_OFF, 3, 4, "bytes")])
        new_off = results.get("TribePanelInven_localPlayer")

        if not new_off:
            new_off, p_player = probe_localplayer_offset(pm, tribe_ptr,
                                                          food_hint=food_hint)
            if new_off is None:
                print("  Offset do jogador local não encontrado.")
                return None
        else:
            p_player = rptr(pm, tribe_ptr + new_off)

        if p_player is None:
            print(f"  TribePanelInven + 0x{new_off:X}: ponteiro inválido.")
            return None

        save_rva("TribePanelInven_localPlayer", new_off, section="struct_offsets")
        off = new_off

    print(f"  Player* (local) = 0x{p_player:X}")
    res = read_resources(pm, p_player)
    if res is None:
        print("  Resources* inválido no offset padrão — sondando offsets 0x40..0x200...")
        res = _probe_resources_offset(pm, p_player, food_hint)
    print_resources("Recursos (jogador local)", res)
    return res


# ---------------------------------------------------------------------------
# Cadeia B: PathfindingSystem → World → PlayerArray → todos os jogadores
# ---------------------------------------------------------------------------

def chain_all_players(pm, base, pathfinding_rva):
    print("\n[Cadeia B] PathfindingSystem → World → PlayerArray → todos os jogadores")
    static_addr, pfs_ptr = find_static_ptr(
        pm, base, pathfinding_rva, AOB_PATHFINDING,
        aob_field=3, aob_instr_size=7, label="pathfindingSystem",
        offsets_key="pathfindingSystem"
    )
    if pfs_ptr is None:
        return

    p_world = rptr(pm, pfs_ptr + OFF_PATHFINDING_WORLD)
    if p_world is None:
        print(f"  PathfindingSystem + 0x{OFF_PATHFINDING_WORLD:X}: ponteiro inválido")
        return

    print(f"  World* = 0x{p_world:X}")

    game_time = rint(pm, p_world + OFF_WORLD_GAMETIME)
    if game_time is not None:
        m, s = divmod(game_time // 1000, 60)  # assumindo milissegundos
        print(f"  gameTime = {game_time}  ({m:02d}:{s:02d})")

    # PlayerArray: dois ponteiros (begin, end)
    pa_begin = rptr(pm, p_world + OFF_WORLD_PLAYERARRAY)
    pa_end   = rptr(pm, p_world + OFF_WORLD_PLAYERARRAY + 8)
    if pa_begin is None or pa_end is None:
        print("  PlayerArray: ponteiros inválidos")
        return

    count = (pa_end - pa_begin) // SIZEOF_PLAYERARRAY_ENTRY
    print(f"  PlayerArray: begin=0x{pa_begin:X}  end=0x{pa_end:X}  count={count}")

    for i in range(min(count, 9)):  # 0=Gaia, 1-8=jogadores
        entry_addr = pa_begin + i * SIZEOF_PLAYERARRAY_ENTRY
        p_player   = rptr(pm, entry_addr)
        if p_player is None:
            continue
        label = "Gaia" if i == 0 else f"Jogador {i}"
        res = read_resources(pm, p_player)
        print_resources(label, res)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def _load_saved_rvas():
    """Carrega RVAs e offsets de struct salvos do offsets.json."""
    try:
        data  = json.loads(OFFSETS_FILE.read_text(encoding="utf-8"))
        chain = data.get("_sdk_chain", {})
        rvas  = chain.get("static_rvas", {})
        offs  = chain.get("struct_offsets", {})
        tp  = int(rvas["tribePanelInven"],   16) if "tribePanelInven"   in rvas else TRIBEPANEL_RVA
        pf  = int(rvas["pathfindingSystem"], 16) if "pathfindingSystem" in rvas else PATHFINDING_RVA
        lp  = int(offs["TribePanelInven_localPlayer"], 16) \
              if "TribePanelInven_localPlayer" in offs else OFF_TRIBEPANEL_LOCALPLAYER
        pr  = int(offs["Player_Resources"], 16) \
              if "Player_Resources" in offs else OFF_PLAYER_RESOURCES
        return tp, pf, lp, pr
    except Exception:
        return TRIBEPANEL_RVA, PATHFINDING_RVA, OFF_TRIBEPANEL_LOCALPLAYER, OFF_PLAYER_RESOURCES


def main():
    saved_tp, saved_pf, saved_lp, saved_pr = _load_saved_rvas()
    # Aplica offset de Resources* descoberto dinamicamente
    global OFF_PLAYER_RESOURCES
    OFF_PLAYER_RESOURCES = saved_pr

    ap = argparse.ArgumentParser(
        description="Lê recursos AoE2DE via cadeia de ponteiros do SDK.")
    ap.add_argument("--all-players", action="store_true",
                    help="Lista recursos de todos os jogadores (Cadeia B)")
    ap.add_argument("--tribepanel-rva", type=lambda x: int(x, 16),
                    default=saved_tp,
                    help=f"RVA do tribePanelInven (padrão: 0x{saved_tp:X})")
    ap.add_argument("--pathfinding-rva", type=lambda x: int(x, 16),
                    default=saved_pf,
                    help=f"RVA do pathfindingSystem (padrão: 0x{saved_pf:X})")
    ap.add_argument("--loop", type=float, default=0,
                    help="Repete a leitura a cada N segundos (0 = uma vez)")
    ap.add_argument("--food-hint", type=float, default=None,
                    help="Valor de food atual (visível no jogo) para filtrar candidatos")
    ap.add_argument("--wood-hint", type=float, default=None,
                    help="Valor de wood atual para filtrar candidatos no --direct-scan")
    ap.add_argument("--stone-hint", type=float, default=None,
                    help="Valor de stone atual para filtrar candidatos no --direct-scan")
    ap.add_argument("--gold-hint", type=float, default=None,
                    help="Valor de gold atual para filtrar candidatos no --direct-scan")
    ap.add_argument("--direct-scan", action="store_true",
                    help="Escaneia memória diretamente pelo valor de --food-hint (requer --food-hint)")
    ap.add_argument("--dump-addr", type=lambda x: int(x, 16), default=None,
                    help="Dumpa floats em ±128 bytes ao redor de um endereço (hex)")
    ap.add_argument("--dump-range", type=int, default=128,
                    help="Raio em bytes para --dump-addr (padrão: 128)")
    args = ap.parse_args()

    try:
        pm = pymem.Pymem(PROCESS)
        print(f"Conectado — PID {pm.process_id}  base 0x{pm.base_address:X}")
    except pymem.exception.ProcessNotFound:
        print(f"'{PROCESS}' não encontrado.")
        sys.exit(1)

    base = pm.base_address

    # Pré-scan: se algum RVA estiver inválido, escaneia ambos de uma vez
    # (uma única passagem pela memória para todos os padrões necessários)
    tp_rva = args.tribepanel_rva
    pf_rva = args.pathfinding_rva

    missing = []
    if rptr(pm, base + tp_rva) is None:
        missing.append(("tribePanelInven",   AOB_TRIBEPANEL,   3, 7))
    if args.all_players and rptr(pm, base + pf_rva) is None:
        missing.append(("pathfindingSystem", AOB_PATHFINDING,  3, 7))

    if missing:
        labels = [m[0] for m in missing]
        print(f"\nRVAs inválidos para: {', '.join(labels)}")
        print(f"Iniciando AOB scan {'via scanner.exe (C++)' if SCANNER_EXE.exists() else 'Python puro'}...")
        found = aob_scan_all(pm, base, missing)
        if "tribePanelInven"   in found: tp_rva = found["tribePanelInven"]
        if "pathfindingSystem" in found: pf_rva = found["pathfindingSystem"]

    def run_once():
        if args.dump_addr is not None:
            r = args.dump_range
            start = max(0, args.dump_addr - r)
            size  = r * 2
            try:
                data = pm.read_bytes(start, size)
            except Exception as e:
                print(f"Erro ao ler 0x{start:X}: {e}")
                return
            print(f"Floats em 0x{args.dump_addr:X} ± {r} bytes:")
            print(f"  {'offset':>6}  {'addr':>16}  {'float32':>12}  {'int32':>12}")
            for i in range(0, len(data) - 3, 4):
                f = struct.unpack_from("<f", data, i)[0]
                iv = struct.unpack_from("<i", data, i)[0]
                addr_i = start + i
                rel = addr_i - args.dump_addr
                marker = " <<<<" if rel == 0 else ""
                if f == f and -1e7 < f < 1e7:  # ignora NaN e inf
                    print(f"  {rel:+7d}  0x{addr_i:016X}  {f:12.2f}  {iv:12d}{marker}")
            return

        if args.direct_scan:
            if args.food_hint is None:
                print("--direct-scan requer --food-hint=<valor>")
                return
            hits = direct_scan_resources(pm, args.food_hint)
            if not hits:
                print("  Nenhum resultado encontrado.")
                return
            # Filtra por wood/stone/gold se fornecidos
            tol = 5.0
            if args.wood_hint is not None:
                hits = [h for h in hits if abs(h[2] - args.wood_hint) <= tol]
            if args.stone_hint is not None:
                hits = [h for h in hits if abs(h[3] - args.stone_hint) <= tol]
            if args.gold_hint is not None:
                hits = [h for h in hits if abs(h[4] - args.gold_hint) <= tol]
            if not hits:
                print("  Nenhum resultado após filtros de wood/stone/gold.")
                return
            print(f"  {len(hits)} resultado(s):")
            for addr, food, wood, stone, gold in hits[:20]:
                print(f"    0x{addr:X}  food={food:.0f} wood={wood:.0f} "
                      f"stone={stone:.0f} gold={gold:.0f}")
            if len(hits) > 20:
                print(f"    ... (+{len(hits)-20} mais)")
            return

        chain_local_player(pm, base, tp_rva, localplayer_off=saved_lp,
                           food_hint=args.food_hint)
        if args.all_players:
            chain_all_players(pm, base, pf_rva)

    if args.loop > 0:
        while True:
            print(f"\n{'='*60}  {time.strftime('%H:%M:%S')}")
            run_once()
            time.sleep(args.loop)
    else:
        run_once()


if __name__ == "__main__":
    main()
