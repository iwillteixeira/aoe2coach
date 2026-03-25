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

# RVA calculado a partir de scan_resources.py (base 0x7FF75BF00000, ptr 0x7FF7600CD3A0)
DEFAULT_RVA = 0x041CD3A0


def is_heap_ptr(v):
    return PTR_MIN < v < PTR_MAX and (v >> 40) in (0x150, 0x14F, 0x151, 0x14E, 0x152)


def main():
    ap = argparse.ArgumentParser(
        description="Dump de pPlayer como ponteiros 64-bit e float32.")
    ap.add_argument("--rva", type=lambda x: int(x, 16),
                    default=DEFAULT_RVA,
                    help=f"RVA do ponteiro estático (padrão: 0x{DEFAULT_RVA:X})")
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

    static_ptr_addr = pm.base_address + args.rva
    print(f"Ponteiro estático @ 0x{static_ptr_addr:X}  (base + 0x{args.rva:X})")

    try:
        p_player = pm.read_longlong(static_ptr_addr) & MASK64
    except Exception as e:
        print(f"Erro lendo *static_ptr: {e}")
        sys.exit(1)

    print(f"*static_ptr (pPlayer) = 0x{p_player:X}")
    if not (PTR_MIN < p_player < PTR_MAX):
        print("Valor não parece um ponteiro válido — tente outro --rva.")
        sys.exit(1)

    size = (args.size + 7) & ~7   # arredonda para múltiplo de 8
    try:
        data = pm.read_bytes(p_player + args.start, size)
    except Exception as e:
        print(f"Erro lendo memória: {e}")
        sys.exit(1)

    print(f"\nDump  pPlayer + 0x{args.start:X}  até  +0x{args.start + size:X}")
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
