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
AOB_TRIBEPANEL   = "48 8B 0D ?? ?? ?? ?? 48 85 C9 0F 84 ?? ?? ?? ?? 40"
AOB_PATHFINDING  = "48 8D 0D ?? ?? ?? ?? 41 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0"

# Offsets de struct fixos (estáveis entre patches)
OFF_TRIBEPANEL_LOCALPLAYER = 0x208   # TribePanelInven → Player*
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
# AOB scanning para localizar RVAs após patches
# ---------------------------------------------------------------------------

def _parse_aob(sig_str):
    pat  = bytes(int(b, 16) if b != "??" else 0 for b in sig_str.split())
    mask = bytes(0xFF        if b != "??" else 0  for b in sig_str.split())
    return pat, mask


def aob_scan(pm, sig_str):
    """Retorna o endereço da primeira ocorrência do padrão AOB no processo."""
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

    MEM_COMMIT   = 0x1000
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
    """Resolve disp32 RIP-relative: addr + field = disp32 → target = addr + instr_size + disp32."""
    try:
        raw = pm.read_bytes(instr_addr + field, 4)
        disp = struct.unpack("<i", raw)[0]
        return instr_addr + instr_size + disp
    except Exception:
        return None


def save_rva(key, new_rva):
    """Persiste novo RVA no offsets.json (seção _sdk_chain.static_rvas)."""
    try:
        data = json.loads(OFFSETS_FILE.read_text(encoding="utf-8"))
        data.setdefault("_sdk_chain", {}).setdefault("static_rvas", {})[key] = hex(new_rva)
        OFFSETS_FILE.write_text(json.dumps(data, indent=2, ensure_ascii=False),
                                encoding="utf-8")
        print(f"  → offsets.json atualizado: {key} = 0x{new_rva:X}")
    except Exception as e:
        print(f"  → aviso: não foi possível salvar RVA em offsets.json: {e}")


def find_static_ptr(pm, base, rva, aob_sig, aob_field=3, aob_instr_size=7, label="",
                    offsets_key=None):
    """Tenta base+rva primeiro; se falhar, faz AOB scan e salva o novo RVA."""
    static_addr = base + rva
    ptr = rptr(pm, static_addr)
    if ptr is not None:
        print(f"  {label}: base + 0x{rva:X}  →  0x{static_addr:X}  →  ptr=0x{ptr:X}  [RVA ok]")
        return static_addr, ptr

    print(f"  {label}: RVA 0x{rva:X} inválido — tentando AOB scan...", end=" ", flush=True)
    hit = aob_scan(pm, aob_sig)
    if hit is None:
        print("não encontrado.")
        return None, None
    resolved = resolve_rip(pm, hit, aob_field, aob_instr_size)
    if resolved is None:
        print("resolve_rip falhou.")
        return None, None
    new_rva = resolved - base
    ptr = rptr(pm, resolved)
    print(f"encontrado  new_rva=0x{new_rva:X}  ptr=0x{ptr:X}")
    if offsets_key:
        save_rva(offsets_key, new_rva)
    return resolved, ptr


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

def chain_local_player(pm, base, tribepanel_rva):
    print("\n[Cadeia A] tribePanelInven → jogador local")
    static_addr, tribe_ptr = find_static_ptr(
        pm, base, tribepanel_rva, AOB_TRIBEPANEL,
        aob_field=3, aob_instr_size=7, label="tribePanelInven",
        offsets_key="tribePanelInven"
    )
    if tribe_ptr is None:
        return None

    p_player = rptr(pm, tribe_ptr + OFF_TRIBEPANEL_LOCALPLAYER)
    if p_player is None:
        print(f"  TribePanelInven + 0x{OFF_TRIBEPANEL_LOCALPLAYER:X}: ponteiro inválido")
        return None

    print(f"  Player* (local) = 0x{p_player:X}")
    res = read_resources(pm, p_player)
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
    """Carrega RVAs salvos do offsets.json; retorna (tribepanel_rva, pathfinding_rva)."""
    try:
        data = json.loads(OFFSETS_FILE.read_text(encoding="utf-8"))
        rvas = data.get("_sdk_chain", {}).get("static_rvas", {})
        tp  = int(rvas["tribePanelInven"],   16) if "tribePanelInven"   in rvas else TRIBEPANEL_RVA
        pf  = int(rvas["pathfindingSystem"], 16) if "pathfindingSystem" in rvas else PATHFINDING_RVA
        return tp, pf
    except Exception:
        return TRIBEPANEL_RVA, PATHFINDING_RVA


def main():
    saved_tp, saved_pf = _load_saved_rvas()

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
    args = ap.parse_args()

    try:
        pm = pymem.Pymem(PROCESS)
        print(f"Conectado — PID {pm.process_id}  base 0x{pm.base_address:X}")
    except pymem.exception.ProcessNotFound:
        print(f"'{PROCESS}' não encontrado.")
        sys.exit(1)

    base = pm.base_address

    def run_once():
        chain_local_player(pm, base, args.tribepanel_rva)
        if args.all_players:
            chain_all_players(pm, base, args.pathfinding_rva)

    if args.loop > 0:
        while True:
            print(f"\n{'='*60}  {time.strftime('%H:%M:%S')}")
            run_once()
            time.sleep(args.loop)
    else:
        run_once()


if __name__ == "__main__":
    main()
