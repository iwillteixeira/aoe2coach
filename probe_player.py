"""
probe_player.py — Lê o ponteiro estático encontrado pelo scan_resources.py
e faz dump dos float32 próximos a pPlayer+0x108 para identificar recursos.

Uso:
    python probe_player.py
    python probe_player.py --rva 0x41CD3A0 --count 48
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


def main():
    ap = argparse.ArgumentParser(
        description="Dump float32 ao redor de pPlayer+0x108 para identificar recursos.")
    ap.add_argument("--rva", type=lambda x: int(x, 16),
                    default=DEFAULT_RVA,
                    help=f"RVA do ponteiro estático (padrão: 0x{DEFAULT_RVA:X})")
    ap.add_argument("--count", type=int, default=48,
                    help="Quantidade de float32 para dumpar a partir de pPlayer+0x100 (padrão: 48)")
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

    # Lê 'count' float32 começando em pPlayer+0x100
    start_off = 0x100
    try:
        data = pm.read_bytes(p_player + start_off, args.count * 4)
    except Exception as e:
        print(f"Erro lendo memória do player em 0x{p_player + start_off:X}: {e}")
        sys.exit(1)

    floats = struct.unpack(f"<{args.count}f", data)

    print(f"\nDump float32  pPlayer + 0x{start_off:X}  até  +0x{start_off + args.count*4:X}")
    print(f"  {'Offset':<8}  {'Hex raw':<12}  {'Valor float'}")
    print(f"  {'-'*44}")

    for i, v in enumerate(floats):
        off = start_off + i * 4
        raw = struct.unpack("<I", struct.pack("<f", v))[0]
        marker = "  ◄── +0x108 (food?)" if off == 0x108 else ""
        # Mostra apenas valores plausíveis como recursos (0 a 9999)
        if 0.0 <= v <= 9999.0:
            print(f"  +0x{off:03X}   0x{raw:08X}   {v:>10.1f}{marker}")
        else:
            print(f"  +0x{off:03X}   0x{raw:08X}   {'(?)':>10s}{marker}")

    print("\n" + "="*60)
    print("  Olhe os recursos na tela do jogo e identifique os offsets.")
    print("  Exemplo: se food=451 aparece em +0x108, wood=511 em +0x10C, etc.")
    print("="*60)


if __name__ == "__main__":
    main()
