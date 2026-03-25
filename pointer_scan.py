"""
pointer_scan.py — Busca cadeia de ponteiros estável para endereços dinâmicos.

Uso:
    python pointer_scan.py 0x147B883257C
    python pointer_scan.py 0x147B883257C --level 5 --offset 2048 --top 10

O script lê toda a memória do processo, constrói um mapa reverso de ponteiros
e faz BFS de volta do endereço alvo até encontrar cadeias que começam em
endereços estáticos do módulo (AoE2DE_s.exe+OFFSET).

Essas cadeias funcionam em qualquer sessão do jogo.
"""

import argparse
import struct
import sys
import ctypes
from ctypes import wintypes
from collections import defaultdict

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


# ---------------------------------------------------------------------------
# Enumeração de regiões
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


def _get_regions(pm):
    """Yields (base, size, is_static) para regiões legíveis e commitadas."""
    k32  = ctypes.WinDLL("kernel32")
    mbi  = _MBI()
    addr = 0
    mod_base = pm.base_address
    mod_end  = mod_base + 0x4000000   # ~64 MB a partir da base do módulo

    while addr < PTR_MAX:
        if not k32.VirtualQueryEx(pm.process_handle, ctypes.c_void_p(addr),
                                  ctypes.byref(mbi), ctypes.sizeof(mbi)):
            break
        base = mbi.BaseAddress or 0
        size = mbi.RegionSize  or 0
        if mbi.State == MEM_COMMIT and mbi.Protect & PAGE_READ and size > 0:
            yield base, size, (mod_base <= base < mod_end)
        nxt = base + size
        addr = nxt if nxt > addr else addr + 0x1000


# ---------------------------------------------------------------------------
# Construção do mapa reverso de ponteiros
# ---------------------------------------------------------------------------

def _build_reverse_map(pm, verbose=True):
    """
    Lê toda a memória e constrói:
      reverse_map[ptr_value_alinhado] = [(addr_que_contem_o_ptr, is_static), ...]

    ptr_value_alinhado = valor & ~0xF  (alinha em 16 bytes para lookup rápido)
    """
    reverse_map: dict[int, list] = defaultdict(list)
    regions = list(_get_regions(pm))
    total   = sum(s for _, s, _ in regions)

    if verbose:
        print(f"  Regiões encontradas: {len(regions)}")
        print(f"  Total de memória a varrer: {total / 1024 / 1024:.1f} MB")
        print("  Varrendo... ", end="", flush=True)

    scanned = 0
    dots_at = total // 20

    for base, size, is_static in regions:
        try:
            chunk = pm.read_bytes(base, size)
        except Exception:
            continue

        for i in range(0, len(chunk) - 7, 8):
            val = struct.unpack_from("<Q", chunk, i)[0]
            if PTR_MIN <= val <= PTR_MAX:
                reverse_map[val & ~0xF].append((base + i, is_static))

        scanned += size
        if verbose and scanned % dots_at < size:
            print(".", end="", flush=True)

    if verbose:
        print(f" OK  ({len(reverse_map):,} ponteiros indexados)")

    return reverse_map


# ---------------------------------------------------------------------------
# BFS reverso: do alvo até endereço estático
# ---------------------------------------------------------------------------

def _pointer_scan(reverse_map, target, max_level, max_offset, top_n, mod_base):
    """
    BFS do endereço alvo para trás, procurando cadeias que terminam
    em um endereço estático do módulo.
    """
    # Cada item na fila: (endereço_atual, cadeia_acumulada)
    # cadeia = lista de offsets [(ptr_addr, offset_aplicado), ...]
    queue   = [(target, [])]
    chains  = []
    visited = set()

    for level in range(max_level):
        next_queue = []

        for current_addr, chain in queue:
            if current_addr in visited:
                continue
            visited.add(current_addr)

            # Procura ponteiros que apontem para [current_addr - max_offset, current_addr]
            for offset in range(0, max_offset + 1, 8):
                key = (current_addr - offset) & ~0xF
                for (ptr_addr, is_static) in reverse_map.get(key, []):
                    actual_val = current_addr - offset
                    # Confirma o offset real (o alinhamento pode ter arredondado)
                    actual_offset = current_addr - actual_val
                    if actual_offset < 0 or actual_offset > max_offset:
                        continue

                    new_chain = chain + [(ptr_addr, actual_offset)]

                    if is_static:
                        chains.append(new_chain)
                        if len(chains) >= top_n * 3:
                            return chains
                    else:
                        next_queue.append((ptr_addr, new_chain))

        queue = next_queue
        if not queue:
            break

    return chains


# ---------------------------------------------------------------------------
# Formatação
# ---------------------------------------------------------------------------

def _fmt_chain(chain, mod_base, mod_name="AoE2DE_s.exe"):
    if not chain:
        return "(vazio)"
    # Primeiro elemento: endereço estático → base offset
    base_addr, first_offset = chain[0]
    base_str = f"{mod_name}+0x{base_addr - mod_base:X}"
    # Demais: offsets intermediários
    steps = " -> ".join(f"+0x{off:X}" for _, off in chain[1:])
    if steps:
        return f"{base_str} -> {steps} -> +0x{first_offset:X}"
    return f"{base_str} -> +0x{first_offset:X}"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Pointer chain scanner para AoE2DE")
    parser.add_argument("address", help="Endereço alvo em hex, ex: 0x147B883257C")
    parser.add_argument("--level",  type=int, default=5,    help="Profundidade máxima (padrão: 5)")
    parser.add_argument("--offset", type=int, default=2048, help="Offset máximo por nível (padrão: 2048)")
    parser.add_argument("--top",    type=int, default=10,   help="Número de cadeias a exibir (padrão: 10)")
    args = parser.parse_args()

    target = int(args.address, 16)

    print(f"\n{'='*60}")
    print(f"  AoE2DE Pointer Scanner")
    print(f"{'='*60}")
    print(f"  Alvo    : 0x{target:X}")
    print(f"  Nível   : {args.level}")
    print(f"  Offset  : {args.offset}")
    print()

    # Conecta ao processo
    try:
        pm = pymem.Pymem(PROCESS)
        print(f"  Processo: {PROCESS}  (PID {pm.process_id})")
        print(f"  Base    : 0x{pm.base_address:X}")
    except pymem.exception.ProcessNotFound:
        print(f"ERRO: Processo '{PROCESS}' não encontrado. Abra o jogo.")
        sys.exit(1)

    print()
    reverse_map = _build_reverse_map(pm, verbose=True)

    print("\n  Buscando cadeias...", end="", flush=True)
    chains = _pointer_scan(reverse_map, target, args.level, args.offset,
                           args.top, pm.base_address)
    print(f" {len(chains)} encontradas")

    if not chains:
        print("\n  Nenhuma cadeia encontrada.")
        print("  Tente aumentar --level ou --offset.")
        sys.exit(0)

    # Ordena por menor número de níveis (cadeias mais curtas primeiro)
    chains.sort(key=lambda c: len(c))

    print(f"\n{'='*60}")
    print(f"  TOP {min(args.top, len(chains))} CADEIAS (mais curtas primeiro)")
    print(f"{'='*60}")
    for i, chain in enumerate(chains[:args.top], 1):
        print(f"  {i:2d}. {_fmt_chain(chain, pm.base_address)}")

    print(f"\n  Cole a melhor cadeia aqui para eu adicionar ao offsets.json.")


if __name__ == "__main__":
    main()
