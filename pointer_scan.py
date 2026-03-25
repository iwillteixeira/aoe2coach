"""
pointer_scan.py — Busca cadeia de ponteiros estável para endereços dinâmicos.

Varre a memória nível a nível (sem carregar tudo na RAM) usando busca binária.
Cada nível faz uma passagem completa pela memória do processo.

Uso:
    python pointer_scan.py 0x1513E7C91CC
    python pointer_scan.py 0x1513E7C91CC --level 5 --offset 1024 --top 10
"""

import argparse
import bisect
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

PROCESS    = "AoE2DE_s.exe"
PTR_MIN    = 0x10000
PTR_MAX    = 0x7FFFFFFFFFFF
MEM_COMMIT = 0x1000
PAGE_READ  = 0x02 | 0x04 | 0x20 | 0x40 | 0x80
MAX_PER_LEVEL = 3000   # limite de endereços rastreados por nível


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


def _get_regions(pm, mod_base, mod_end):
    k32  = ctypes.WinDLL("kernel32")
    mbi  = _MBI()
    addr = 0
    while addr < PTR_MAX:
        if not k32.VirtualQueryEx(pm.process_handle, ctypes.c_void_p(addr),
                                  ctypes.byref(mbi), ctypes.sizeof(mbi)):
            break
        base = mbi.BaseAddress or 0
        size = mbi.RegionSize  or 0
        if mbi.State == MEM_COMMIT and mbi.Protect & PAGE_READ and size > 0:
            is_static = mod_base <= base < mod_end
            yield base, size, is_static
        nxt = base + size
        addr = nxt if nxt > addr else addr + 0x1000


# ---------------------------------------------------------------------------
# Scan de um nível
# ---------------------------------------------------------------------------

def _scan_level(pm, regions, targets_sorted, max_offset):
    """
    Uma passagem pela memória procurando ponteiros que apontem para
    qualquer endereço em [t - max_offset, t] para qualquer t em targets_sorted.

    Retorna: [(ptr_addr, target_apontado, offset, is_static)]
    """
    results = []

    for base, size, is_static in regions:
        try:
            chunk = pm.read_bytes(base, size)
        except Exception:
            continue

        for i in range(0, len(chunk) - 7, 8):
            val = struct.unpack_from("<Q", chunk, i)[0]
            if not (PTR_MIN <= val <= PTR_MAX):
                continue

            # Busca binária: existe algum target t tal que val <= t <= val+max_offset?
            lo = bisect.bisect_left(targets_sorted,  val)
            hi = bisect.bisect_right(targets_sorted, val + max_offset)
            if lo < hi:
                t      = targets_sorted[lo]
                offset = t - val
                results.append((base + i, t, offset, is_static))

    return results


# ---------------------------------------------------------------------------
# BFS por níveis
# ---------------------------------------------------------------------------

def pointer_scan(pm, target, max_level, max_offset, top_n, mod_base):
    mod_end = mod_base + 0x4000000   # ~64 MB de espaço do módulo

    # Pré-carrega lista de regiões (apenas metadados, não os dados)
    regions = list(_get_regions(pm, mod_base, mod_end))
    total_mb = sum(s for _, s, _ in regions) / 1024 / 1024
    print(f"  Regiões: {len(regions)}  |  Total: {total_mb:.0f} MB  |"
          f"  ~{total_mb / 800:.0f}-{total_mb / 400:.0f}s por nível\n")

    # current_targets: { addr → cadeia_até_aqui }
    current_targets = {target: []}
    static_chains   = []

    for level in range(1, max_level + 1):
        tlist = sorted(current_targets.keys())
        print(f"  Nível {level}/{max_level}: {len(tlist)} alvo(s)...", end="", flush=True)

        found = _scan_level(pm, regions, tlist, max_offset)
        print(f" {len(found)} ponteiros encontrados")

        next_targets: dict[int, list] = {}

        for (ptr_addr, pointed_at, offset, is_static) in found:
            parent_chain = current_targets.get(pointed_at, [])
            new_chain    = [(ptr_addr, offset)] + parent_chain

            if is_static:
                static_chains.append(new_chain)
                if len(static_chains) >= top_n * 2:
                    return static_chains
            else:
                if ptr_addr not in next_targets:
                    next_targets[ptr_addr] = new_chain

        # Evita explosão combinatória: mantém os mais promissores
        if len(next_targets) > MAX_PER_LEVEL:
            items = sorted(next_targets.items(), key=lambda x: len(x[1]))
            next_targets = dict(items[:MAX_PER_LEVEL])

        current_targets = next_targets
        if not current_targets:
            print("  Sem mais endereços intermediários para seguir.")
            break

    return static_chains


# ---------------------------------------------------------------------------
# Formatação
# ---------------------------------------------------------------------------

def _fmt(chain, mod_base):
    if not chain:
        return "(vazio)"
    base_addr, last_offset = chain[0], chain[0][1]
    # chain[0] = (static_ptr_addr, offset_para_nivel_seguinte)
    static_addr = chain[0][0]
    rva         = static_addr - mod_base
    steps       = [f"+0x{off:X}" for _, off in chain[1:]]
    steps.append(f"+0x{chain[0][1]:X}")
    return f"AoE2DE_s.exe+0x{rva:X}  ->  " + "  ->  ".join(steps)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("address",         help="Endereço alvo (hex), ex: 0x1513E7C91CC")
    ap.add_argument("--level",  type=int, default=5,    help="Profundidade máxima (padrão 5)")
    ap.add_argument("--offset", type=int, default=1024, help="Offset máximo por nível (padrão 1024)")
    ap.add_argument("--top",    type=int, default=10,   help="Cadeias a exibir (padrão 10)")
    args = ap.parse_args()

    target = int(args.address, 16)

    print(f"\n{'='*60}")
    print(f"  AoE2DE Pointer Scanner  —  nível a nível (baixo RAM)")
    print(f"{'='*60}")
    print(f"  Alvo    : 0x{target:X}")
    print(f"  Níveis  : {args.level}   Offset máx: {args.offset}")
    print()

    try:
        pm = pymem.Pymem(PROCESS)
        print(f"  Processo: PID {pm.process_id}  |  Base: 0x{pm.base_address:X}")
    except pymem.exception.ProcessNotFound:
        print(f"ERRO: '{PROCESS}' não encontrado.")
        sys.exit(1)

    print()
    chains = pointer_scan(pm, target, args.level, args.offset,
                          args.top, pm.base_address)

    print(f"\n{'='*60}")
    if not chains:
        print("  Nenhuma cadeia estática encontrada.")
        print("  Tente: --level 6  ou  --offset 2048")
    else:
        chains.sort(key=lambda c: len(c))
        print(f"  {min(args.top, len(chains))} CADEIA(S) ENCONTRADA(S):")
        print(f"{'='*60}")
        for i, ch in enumerate(chains[:args.top], 1):
            print(f"  {i:2d}. {_fmt(ch, pm.base_address)}")
        print(f"\n  Cole a melhor cadeia aqui para eu adicionar ao offsets.json.")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
