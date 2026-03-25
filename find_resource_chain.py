"""
find_resource_chain.py — Percorre ponteiros a partir de pPlayer buscando
os endereços de food/wood/gold/stone encontrados pelo find_by_values.py.

Uso:
    python find_resource_chain.py --food 0x15030274BA0 --wood 0x15030274BF4

O script lê até 4 níveis de ponteiros de heap a partir de pPlayer,
e em cada nível verifica se algum offset [0, 0x800] aponta para os
endereços de recursos conhecidos.  Muito mais rápido que pointer_scan.py.
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

PROCESS     = "AoE2DE_s.exe"
MASK64      = 0xFFFFFFFFFFFFFFFF
PTR_MIN     = 0x10000
PTR_MAX     = 0x7FFFFFFFFFFF
DEFAULT_RVA = 0x041CD3A0   # pPlayer static ptr (scan_resources.py)

# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

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
    """Heurística: ponteiro de heap de 64 bits (0x000001xx...)."""
    if not (PTR_MIN < v < PTR_MAX):
        return False
    hi = v >> 40
    return 0x140 <= hi <= 0x1FF


def pointers_in_block(data, base_addr):
    """Retorna lista de (offset, valor) para cada ponteiro de heap no bloco."""
    out = []
    for i in range(0, len(data) - 7, 8):
        v = struct.unpack_from("<Q", data, i)[0]
        if is_heap_ptr(v):
            out.append((i, v))
    return out


# --------------------------------------------------------------------------
# BFS
# --------------------------------------------------------------------------

def bfs(pm, root, targets, max_levels=4, struct_scan=0x400, max_offset=0x800):
    """
    Percorre ponteiros a partir de root buscando qualquer endereço em targets.
    targets: dict { addr -> label }  (ex: {0x15030274BF4: "wood"})
    Retorna lista de cadeias (caminho) quando encontra.
    """
    # current_nodes: { current_addr -> path_list }
    # path_list: [(ptr_value, offset_usado), ...]
    current = {root: []}
    found   = []

    for level in range(1, max_levels + 1):
        print(f"  Nível {level}/{max_levels}  ({len(current)} nó(s))...", flush=True)
        next_nodes = {}

        for node_addr, path in current.items():
            block = read_block(pm, node_addr, struct_scan)
            if block is None:
                continue

            # 1) Verifica se algum byte do bloco aponta diretamente ao target
            for tgt, label in targets.items():
                for off in range(0, min(struct_scan, max_offset + 1), 8):
                    if off + 8 > len(block):
                        break
                    v = struct.unpack_from("<Q", block, off)[0] & MASK64
                    # Endereço absoluto armazenado aqui aponta para tgt?
                    if v == tgt:
                        chain = path + [(node_addr, off, tgt, 0, label)]
                        found.append(chain)

            # 2) Coleta ponteiros de heap para continuar a busca
            for off, ptr_val in pointers_in_block(block, node_addr):
                if ptr_val not in next_nodes:
                    next_nodes[ptr_val] = path + [(node_addr, off, ptr_val)]

        if found:
            break
        current = next_nodes
        if not current:
            print("  Sem mais ponteiros para seguir.")
            break

    return found


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description="Encontra cadeia de ponteiros de pPlayer até os recursos.")
    ap.add_argument("--rva",   type=lambda x: int(x, 16), default=DEFAULT_RVA)
    ap.add_argument("--food",  type=lambda x: int(x, 16), required=True,
                    help="Endereço de food encontrado pelo find_by_values.py")
    ap.add_argument("--wood",  type=lambda x: int(x, 16), required=True,
                    help="Endereço de wood encontrado pelo find_by_values.py")
    ap.add_argument("--gold",  type=lambda x: int(x, 16), default=0)
    ap.add_argument("--stone", type=lambda x: int(x, 16), default=0)
    ap.add_argument("--levels", type=int, default=4)
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
    print(f"pPlayer = 0x{p_player:X}\n")

    targets = {args.wood: "wood"}   # wood = endereço único, mais confiável
    if args.food:  targets[args.food]  = "food"
    if args.gold:  targets[args.gold]  = "gold"
    if args.stone: targets[args.stone] = "stone"

    print(f"Alvos:  {', '.join(f'{l}=0x{a:X}' for a, l in targets.items())}")
    print(f"BFS a partir de pPlayer com até {args.levels} níveis...\n")
    print("="*60)

    chains = bfs(pm, p_player, targets, max_levels=args.levels)

    print("\n" + "="*60)
    if not chains:
        print("  Nenhuma cadeia encontrada em 4 níveis.")
        print("  → Execute: python pointer_scan.py 0x{:X} --level 4 --offset 2048".format(args.wood))
    else:
        print(f"  {len(chains)} CADEIA(S) ENCONTRADA(S):")
        print("="*60)
        for i, chain in enumerate(chains, 1):
            # chain items: (from_addr, offset, to_addr[, delta, label])
            parts = [f"pPlayer"]
            for item in chain:
                if len(item) == 5:
                    from_a, off, to_a, delta, label = item
                    parts.append(f"[+0x{off:X}] = {label} addr (0x{to_a:X})")
                else:
                    from_a, off, to_a = item
                    parts.append(f"[+0x{off:X}]→0x{to_a:X}")
            print(f"  {i:2d}. " + " → ".join(parts))
    print("="*60)


if __name__ == "__main__":
    main()
