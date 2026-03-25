"""
find_resource_chain.py — BFS a partir de pPlayer seguindo ponteiros de heap
e verificando se algum aponta para a região dos recursos (food/wood/gold/stone).

Uso:
    python find_resource_chain.py --food 0x15030274BA0 --wood 0x15030274BF4 \\
                                  --gold 0x15030274C8C --stone 0x15030274D04
"""

import struct
import sys
import argparse
from collections import deque

try:
    import pymem
    import pymem.exception
except ImportError:
    print("pip install pymem pywin32")
    sys.exit(1)

PROCESS     = "AoE2DE_s.exe"
MASK64      = 0xFFFFFFFFFFFFFFFF
PTR_MIN     = 0x10000
PTR_MAX     = 0x7FFFFFFFFFFF
DEFAULT_RVA = 0x041CD3A0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def read_qword(pm, addr):
    try:
        return pm.read_longlong(addr) & MASK64
    except Exception:
        return None


def read_block(pm, addr, size):
    try:
        return pm.read_bytes(addr, size)
    except Exception:
        return None


def is_heap_ptr(v):
    """Ponteiro de heap 64-bit válido para este processo (addr >> 32 ≈ 0x100-0x1FF)."""
    if not (PTR_MIN < v < PTR_MAX):
        return False
    hi32 = (v >> 32) & 0xFFFF
    return 0x100 <= hi32 <= 0x1FF


def heap_ptrs_in_block(data):
    """Yield (offset, value) para cada ponteiro de heap alinhado em 8 bytes."""
    for i in range(0, len(data) - 7, 8):
        v = struct.unpack_from("<Q", data, i)[0]
        if is_heap_ptr(v):
            yield i, v


# ---------------------------------------------------------------------------
# Verificação: um ponteiro P "cobre" os recursos?
# ---------------------------------------------------------------------------

def check_ptr_covers_resources(pm, ptr_val, food, wood, gold, stone, max_look=0x2000):
    """
    Verifica se lendo mem[ptr_val + offset] dá os valores de food/wood/gold/stone
    para algum offset razoável (0 a max_look).  Retorna (True, offsets_dict) ou False.
    """
    if ptr_val > food:
        return False
    delta = food - ptr_val
    if delta >= max_look:
        return False

    # Lê um bloco suficiente para cobrir até stone
    stone_delta = stone - ptr_val if stone and stone >= ptr_val else delta + 0x600
    read_size   = min(stone_delta + 32, max_look)
    data = read_block(pm, ptr_val, read_size)
    if data is None:
        return False

    def fclose(a, b, tol=8.0):
        return abs(a - b) <= tol

    def read_f32(off):
        if off + 4 > len(data):
            return None
        return struct.unpack_from("<f", data, off)[0]

    food_off  = delta
    food_val  = read_f32(food_off)
    if food_val is None or not fclose(food_val, food_ref):
        return False

    # Procura wood dentro de ±1024 bytes após food
    found = {"food": (food_off, food_val)}
    for off in range(food_off, min(food_off + 1024, len(data) - 3), 4):
        v = read_f32(off)
        if v is None:
            continue
        if "wood" not in found and fclose(v, wood_ref):
            found["wood"] = (off, v)
        if "gold" not in found and fclose(v, gold_ref):
            found["gold"] = (off, v)
        if "stone" not in found and fclose(v, stone_ref):
            found["stone"] = (off, v)

    if len(found) >= 3:
        return found
    return False


# ---------------------------------------------------------------------------
# BFS
# ---------------------------------------------------------------------------

def bfs_find(pm, root, food, wood, gold, stone,
             max_levels=5, struct_scan=0x600, max_nodes=4000):
    """
    BFS de ponteiros de heap a partir de root.
    Para cada ponteiro encontrado, verifica se ele 'cobre' os recursos.
    """
    global food_ref, wood_ref, gold_ref, stone_ref
    food_ref  = float(food)   # serão lidos como float32 durante a verificação
    wood_ref  = float(wood)
    gold_ref  = float(gold)
    stone_ref = float(stone)

    # Lê os valores reais de food/wood/gold/stone como float32
    def read_f32_at(addr):
        try:
            raw = pm.read_bytes(addr, 4)
            return struct.unpack("<f", raw)[0]
        except Exception:
            return None

    food_val  = read_f32_at(food)
    wood_val  = read_f32_at(wood)
    gold_val  = read_f32_at(gold) if gold else None
    stone_val = read_f32_at(stone) if stone else None

    if food_val is not None:  food_ref  = food_val
    if wood_val is not None:  wood_ref  = wood_val
    if gold_val is not None:  gold_ref  = gold_val
    if stone_val is not None: stone_ref = stone_val

    print(f"  Valores atuais: food={food_ref:.1f}  wood={wood_ref:.1f}  "
          f"gold={gold_ref:.1f}  stone={stone_ref:.1f}\n")

    visited = {root}
    # queue: (current_addr, path)
    queue = deque([(root, [])])

    for level in range(1, max_levels + 1):
        if not queue:
            print("  Fila vazia — sem mais nós para seguir.")
            break

        next_queue = deque()
        nodes_this_level = 0

        print(f"  Nível {level}/{max_levels}  ({len(queue)} nó(s))...", flush=True)

        while queue:
            node_addr, path = queue.popleft()
            nodes_this_level += 1

            data = read_block(pm, node_addr, struct_scan)
            if data is None:
                continue

            for off, ptr_val in heap_ptrs_in_block(data):
                new_path = path + [(node_addr, off, ptr_val)]

                # Verifica se este ponteiro aponta para a região de recursos
                result = check_ptr_covers_resources(pm, ptr_val,
                                                     food, wood, gold, stone)
                if result:
                    print(f"\n  *** ENCONTRADO no nível {level} ***")
                    return new_path, ptr_val, result

                if ptr_val not in visited:
                    visited.add(ptr_val)
                    next_queue.append((ptr_val, new_path))
                    if len(next_queue) > max_nodes:
                        break

            if len(next_queue) > max_nodes:
                break

        queue = next_queue
        print(f"         → {len(visited)} endereços visitados, {len(queue)} na fila")

    return None, None, None


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rva",   type=lambda x: int(x, 16), default=DEFAULT_RVA)
    ap.add_argument("--food",  type=lambda x: int(x, 16), required=True)
    ap.add_argument("--wood",  type=lambda x: int(x, 16), required=True)
    ap.add_argument("--gold",  type=lambda x: int(x, 16), default=0)
    ap.add_argument("--stone", type=lambda x: int(x, 16), default=0)
    ap.add_argument("--levels", type=int, default=5)
    args = ap.parse_args()

    try:
        pm = pymem.Pymem(PROCESS)
        print(f"Conectado — PID {pm.process_id}  base 0x{pm.base_address:X}\n")
    except pymem.exception.ProcessNotFound:
        print(f"'{PROCESS}' não encontrado.")
        sys.exit(1)

    static_ptr = pm.base_address + args.rva
    p_player   = read_qword(pm, static_ptr)
    if p_player is None or not (PTR_MIN < p_player < PTR_MAX):
        print("Falha ao ler pPlayer.")
        sys.exit(1)
    print(f"pPlayer = 0x{p_player:X}")

    print(f"Alvos: food=0x{args.food:X}  wood=0x{args.wood:X}  "
          f"gold=0x{args.gold:X}  stone=0x{args.stone:X}")
    print(f"BFS até {args.levels} níveis a partir de pPlayer...\n{'='*60}")

    chain, ptr_val, offsets = bfs_find(
        pm, p_player,
        args.food, args.wood, args.gold, args.stone,
        max_levels=args.levels
    )

    print("\n" + "="*60)
    if chain is None:
        print("  Nenhuma cadeia encontrada.")
        print("  Alternativa: no Cheat Engine, abra o Memory View em")
        print(f"  0x{args.food:X}, clique direito → 'Find what accesses this address'")
    else:
        print(f"  CADEIA ENCONTRADA  (ponteiro base: 0x{ptr_val:X})")
        print("  Caminho de pPlayer:")
        labels = ["pPlayer"] + [f"[+0x{off:X}]→0x{to:X}" for _, off, to in chain]
        print("  " + " → ".join(labels))
        print(f"\n  Ponteiro base aponta para struct com offsets:")
        for label, (off, val) in offsets.items():
            print(f"    {label:<6}  +0x{off:03X}  =  {val:.1f}")
        base_rva = chain[0][2] - pm.base_address  # se o primeiro passo for estático
        print(f"\n  Para calibrar: adicione este ponteiro base ao offsets.json")
    print("="*60)


if __name__ == "__main__":
    main()
