"""
probe_player.py — Lê o ponteiro estático encontrado pelo scan_resources.py
e faz dump da memória ao redor de pPlayer+0x000 como ponteiros de 64 bits
e float32, para identificar sub-structs que levam ao bloco de recursos.

Uso:
    python probe_player.py
    python probe_player.py --rva 0x41CD3A0 --start 0x000 --size 0x300
"""

import struct
import sys
import argparse

try:
    import pymem
    import pymem.exception
except ImportError:
    print("pip install pymem pywin32")
    sys.exit(1)

PROCESS  = "AoE2DE_s.exe"
MASK64   = 0xFFFFFFFFFFFFFFFF
PTR_MIN  = 0x10000
PTR_MAX  = 0x7FFFFFFFFFFF

# RVA calculado a partir de scan_resources.py (build anterior)
DEFAULT_RVA = 0x041CD3A0

# RVAs do SDK (simonsan/Age_of_Empires_II_Definitive-Edition-SDK)
# Para o jogador local: *[base + 0x2BA7190] + 0x208 → Player*
# Para todos os jogadores: *[base + 0x2BB80D0] + 0x18 → World, +0x2A8 → PlayerArray
SDK_RVA_TRIBEPANEL  = 0x2BA7190
SDK_RVA_PATHFINDING = 0x2BB80D0

# Offsets de struct conhecidos (estáveis entre patches):
#   Player + 0x070 → Resources*
#   Resources: food@+0x00, wood@+0x04, stone@+0x08, gold@+0x0C, age@+0x18, pop@+0x2C


def is_heap_ptr(v):
    return PTR_MIN < v < PTR_MAX and (v >> 40) in (0x150, 0x14F, 0x151, 0x14E, 0x152)


def main():
    ap = argparse.ArgumentParser(
        description="Dump de pPlayer como ponteiros 64-bit e float32.")
    ap.add_argument("--rva", type=lambda x: int(x, 16),
                    default=DEFAULT_RVA,
                    help=f"RVA do ponteiro estático (padrão: 0x{DEFAULT_RVA:X})")
    ap.add_argument("--sdk", action="store_true",
                    help="Usa RVA do SDK (tribePanelInven=0x2BA7190) e dereference +0x208 → Player*")
    ap.add_argument("--start", type=lambda x: int(x, 16), default=0x000,
                    help="Offset inicial no struct pPlayer (padrão: 0x000)")
    ap.add_argument("--size",  type=lambda x: int(x, 16), default=0x300,
                    help="Tamanho em bytes para dumpar (padrão: 0x300)")
    args = ap.parse_args()

    try:
        pm = pymem.Pymem(PROCESS)
        print(f"Conectado — PID {pm.process_id}  base 0x{pm.base_address:X}\n")
    except pymem.exception.ProcessNotFound:
        print(f"'{PROCESS}' não encontrado.")
        sys.exit(1)

    rva = SDK_RVA_TRIBEPANEL if args.sdk else args.rva
    static_ptr_addr = pm.base_address + rva
    print(f"Ponteiro estático @ 0x{static_ptr_addr:X}  (base + 0x{rva:X})")

    try:
        intermediate = pm.read_longlong(static_ptr_addr) & MASK64
    except Exception as e:
        print(f"Erro lendo *static_ptr: {e}")
        sys.exit(1)

    if args.sdk:
        # tribePanelInven → *ptr + 0x208 → Player*
        print(f"*tribePanelInven = 0x{intermediate:X}")
        if not (PTR_MIN < intermediate < PTR_MAX):
            print("tribePanelInven inválido — tente sem --sdk ou com --rva correto.")
            sys.exit(1)
        try:
            p_player = pm.read_longlong(intermediate + 0x208) & MASK64
        except Exception as e:
            print(f"Erro lendo tribePanelInven+0x208: {e}")
            sys.exit(1)
    else:
        p_player = intermediate

    print(f"Player* = 0x{p_player:X}")
    if not (PTR_MIN < p_player < PTR_MAX):
        print("Valor não parece um ponteiro válido — tente outro --rva ou use --sdk.")
        sys.exit(1)

    # Se --sdk, mostra Resources* em Player+0x70 como dica
    if args.sdk and args.start == 0x000:
        try:
            p_res = pm.read_longlong(p_player + 0x70) & MASK64
            if PTR_MIN < p_res < PTR_MAX:
                import struct as _s
                food  = _s.unpack("<f", pm.read_bytes(p_res + 0x00, 4))[0]
                wood  = _s.unpack("<f", pm.read_bytes(p_res + 0x04, 4))[0]
                stone = _s.unpack("<f", pm.read_bytes(p_res + 0x08, 4))[0]
                gold  = _s.unpack("<f", pm.read_bytes(p_res + 0x0C, 4))[0]
                print(f"\n  [SDK] Resources* @ 0x{p_res:X}")
                print(f"  food={food:.0f}  wood={wood:.0f}  stone={stone:.0f}  gold={gold:.0f}\n")
        except Exception:
            pass

    size = (args.size + 7) & ~7   # arredonda para múltiplo de 8
    try:
        data = pm.read_bytes(p_player + args.start, size)
    except Exception as e:
        print(f"Erro lendo memória: {e}")
        sys.exit(1)

    print(f"\nDump  Player* + 0x{args.start:X}  até  +0x{args.start + size:X}")
    print(f"  {'Off':6}  {'--- 64-bit value ---':22}  {'float32[0]':>12}  {'float32[1]':>12}")
    print(f"  {'-'*68}")

    for i in range(0, size, 8):
        off = args.start + i
        q   = struct.unpack_from("<Q", data, i)[0]
        f0, f1 = struct.unpack_from("<ff", data, i)

        # Ponteiro de heap?
        if is_heap_ptr(q):
            ptr_tag = f"→ 0x{q:016X}  (heap ptr)"
            print(f"  +0x{off:04X}  {ptr_tag}")
        else:
            # Mostra como dois float32
            def fmt(v):
                if 0.0 < v < 99999.0:   return f"{v:12.2f}"
                elif v == 0.0:            return f"{'0.0':>12}"
                else:                     return f"{'(?)':>12}"
            print(f"  +0x{off:04X}  0x{q:016X}   {fmt(f0)}   {fmt(f1)}")

    print("\n  Ponteiros de heap acima levam a sub-structs que podem conter os recursos.")
    print("  Use: python probe_subptr.py <ptr_addr> para seguir um ponteiro.")
    print("="*60)


if __name__ == "__main__":
    main()
