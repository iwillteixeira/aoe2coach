"""
find_by_values.py — Encontra bloco de recursos pelo valor atual.

Instrução:
  1. Olhe seus recursos na tela do jogo.
  2. Execute: python find_by_values.py -f FOOD -w WOOD -g GOLD -s STONE
  Exemplo:  python find_by_values.py -f 200 -w 150 -g 0 -s 50
  Tolerância padrão: ±10 unidades. Use --tol para ajustar.
"""

import argparse
import struct
import ctypes
from ctypes import wintypes
import sys

try:
    import pymem
    import pymem.exception
except ImportError:
    print("pip install pymem")
    sys.exit(1)

PROCESS  = "AoE2DE_s.exe"
PTR_MAX  = 0x7FFFFFFFFFFF
MASK64   = 0xFFFFFFFFFFFFFFFF

# ---------------------------------------------------------------------------
# Regiões de memória
# ---------------------------------------------------------------------------

class _MBI(ctypes.Structure):
    _fields_ = [
        ("BaseAddress",       ctypes.c_void_p),
        ("AllocationBase",    ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize",        ctypes.c_size_t),
        ("State",             wintypes.DWORD),
        ("Protect",           wintypes.DWORD),
        ("Type",              wintypes.DWORD),
    ]

def get_regions(pm, heap_only=True):
    k32  = ctypes.WinDLL("kernel32")
    mbi  = _MBI()
    addr = 0
    while addr < PTR_MAX:
        if not k32.VirtualQueryEx(pm.process_handle, ctypes.c_void_p(addr),
                                   ctypes.byref(mbi), ctypes.sizeof(mbi)):
            break
        base = mbi.BaseAddress or 0
        size = mbi.RegionSize  or 0
        if mbi.State == 0x1000 and mbi.Protect & (0x02|0x04|0x20|0x40|0x80) and size > 0:
            # se heap_only: ignora regiões do módulo principal (código/static)
            in_module = pm.base_address <= base < pm.base_address + 0x5000000
            if not heap_only or not in_module:
                yield base, size
        nxt = base + size
        addr = nxt if nxt > addr else addr + 0x1000


# ---------------------------------------------------------------------------
# Busca de valores float32
# ---------------------------------------------------------------------------

def fclose(a, b, tol):
    return abs(a - b) <= tol


def scan_sequential(pm, food, wood, gold, stone, tol, window=256):
    """
    Busca food, wood, gold, stone como float32 sequencialmente a cada 4 bytes.
    Também testa offsets não-sequenciais dentro de 'window' bytes.
    """
    results = []
    for base, size in get_regions(pm, heap_only=True):
        try:
            chunk = pm.read_bytes(base, size)
        except Exception:
            continue

        n = len(chunk)
        for i in range(0, n - 15, 4):
            f0 = struct.unpack_from("<f", chunk, i)[0]
            if not fclose(f0, food, tol):
                continue

            # Verifica se wood/gold/stone aparecem dentro de 'window' bytes
            found_w = found_g = found_s = -1
            end = min(n, i + window)
            for j in range(i + 4, end, 4):
                v = struct.unpack_from("<f", chunk, j)[0]
                if found_w < 0 and fclose(v, wood,  tol): found_w = j
                if found_g < 0 and fclose(v, gold,  tol): found_g = j
                if found_s < 0 and fclose(v, stone, tol): found_s = j

            if found_w >= 0 and found_g >= 0 and found_s >= 0:
                addr = base + i
                results.append({
                    "base":    addr,
                    "food_off": 0,
                    "wood_off": (found_w - i),
                    "gold_off": (found_g - i),
                    "stone_off":(found_s - i),
                    "food_val":  f0,
                    "wood_val":  struct.unpack_from("<f", chunk, found_w)[0],
                    "gold_val":  struct.unpack_from("<f", chunk, found_g)[0],
                    "stone_val": struct.unpack_from("<f", chunk, found_s)[0],
                })

    return results


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description="Localiza bloco de recursos do AoE2DE na memória.")
    ap.add_argument("-f", "--food",  type=float, required=True, help="Comida atual")
    ap.add_argument("-w", "--wood",  type=float, required=True, help="Madeira atual")
    ap.add_argument("-g", "--gold",  type=float, required=True, help="Ouro atual")
    ap.add_argument("-s", "--stone", type=float, required=True, help="Pedra atual")
    ap.add_argument("--tol", type=float, default=10.0,
                    help="Tolerância em ±unidades (padrão 10)")
    args = ap.parse_args()

    try:
        pm = pymem.Pymem(PROCESS)
        print(f"Conectado — PID {pm.process_id}  base 0x{pm.base_address:X}\n")
    except pymem.exception.ProcessNotFound:
        print(f"'{PROCESS}' não encontrado.")
        sys.exit(1)

    print(f"Buscando:  food≈{args.food}  wood≈{args.wood}  "
          f"gold≈{args.gold}  stone≈{args.stone}  (±{args.tol})")
    print("Varrendo heap… pode levar 30–60s\n")

    results = scan_sequential(pm, args.food, args.wood, args.gold, args.stone,
                              args.tol, window=512)

    print(f"\n{'='*60}")
    print(f"  {len(results)} resultado(s) encontrado(s)")
    print(f"{'='*60}")

    for r in results[:10]:
        base = r["base"]
        print(f"\n  Endereço base (food): 0x{base:X}")
        print(f"    food  +0x{r['food_off']:03X}  →  {r['food_val']:.1f}")
        print(f"    wood  +0x{r['wood_off']:03X}  →  {r['wood_val']:.1f}")
        print(f"    gold  +0x{r['gold_off']:03X}  →  {r['gold_val']:.1f}")
        print(f"    stone +0x{r['stone_off']:03X}  →  {r['stone_val']:.1f}")

    if results:
        print(f"\n  Para encontrar o ponteiro estático, use o endereço da food:")
        for r in results[:3]:
            print(f"    python pointer_scan.py 0x{r['base']:X} --level 4 --offset 2048")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
