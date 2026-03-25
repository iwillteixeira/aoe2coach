"""
scan_resources.py — Busca padrões de acesso ao bloco de recursos no executável atual.

Estratégia:
  1. Busca MOV Reg, [Reg+0x108] com qualquer combinação de registradores x64
  2. Para cada hit, verifica se há MOV Reg,[RIP+disp32] próximo (ponteiro estático)
  3. Tenta seguir a cadeia e ler os recursos
  4. Também varre por qualquer read de [Reg+0x20] logo após, típico do struct pRes

Uso:
    python scan_resources.py
"""

import struct
import sys
import ctypes
from ctypes import wintypes

try:
    import pymem
    import pymem.exception
except ImportError:
    print("pip install pymem pywin32")
    sys.exit(1)

PROCESS = "AoE2DE_s.exe"
MASK64   = 0xFFFFFFFFFFFFFFFF
PTR_MIN  = 0x10000
PTR_MAX  = 0x7FFFFFFFFFFF


# ---------------------------------------------------------------------------
# Leitura de módulo em chunks
# ---------------------------------------------------------------------------

def read_module_chunks(pm, chunk_size=0x400000):
    """Lê o módulo principal em pedaços de 4 MB."""
    base = pm.base_address
    module_size = 0x4000000   # 64 MB — cobre o executável
    chunks = []
    for off in range(0, module_size, chunk_size):
        try:
            data = pm.read_bytes(base + off, min(chunk_size, module_size - off))
            chunks.append((base + off, data))
        except Exception:
            pass
    return chunks


# ---------------------------------------------------------------------------
# Busca de padrões
# ---------------------------------------------------------------------------

REX_RANGE = set(range(0x48, 0x50))   # 0x48..0x4F


def find_reads_at_0x108(chunks):
    """
    Localiza instruções REX 8B ?? 08 01 00 00 onde ModRM.mod == 10b (disp32).
    Exemplos: MOV RAX,[R15+108h], MOV RCX,[RBX+108h], …
    """
    results = []
    for chunk_base, data in chunks:
        n = len(data)
        for i in range(n - 7):
            if (data[i] in REX_RANGE
                    and data[i + 1] == 0x8B
                    and data[i + 3] == 0x08 and data[i + 4] == 0x01
                    and data[i + 5] == 0x00 and data[i + 6] == 0x00):
                modrm = data[i + 2]
                mod = (modrm >> 6) & 3
                rm  = modrm & 7
                # mod=10 → disp32; rm=4 exige SIB (pula — instrução tem tamanho diferente)
                if mod == 2 and rm != 4:
                    results.append((chunk_base + i, bytes(data[i: i + 7])))
    return results


# Possíveis opcodes MOV Reg,[RIP+disp32] para registradores comuns
RIP_LOAD_PATTERNS = [
    (b"\x4C\x8B\x3D", "R15"),
    (b"\x4C\x8B\x35", "R14"),
    (b"\x4C\x8B\x2D", "R13"),
    (b"\x4D\x8B\x1D", "R11"),
    (b"\x4D\x8B\x05", "R8"),
    (b"\x48\x8B\x1D", "RBX"),
    (b"\x48\x8B\x0D", "RCX"),
    (b"\x48\x8B\x15", "RDX"),
    (b"\x48\x8B\x35", "RSI"),
    (b"\x48\x8B\x3D", "RDI"),
    (b"\x48\x8B\x05", "RAX"),
]


def find_nearest_rip_load(chunks, chunk_map, instr_va, window=0x800):
    """Busca MOV Reg,[RIP+d32] nos 'window' bytes anteriores a instr_va."""
    for chunk_base, data in chunks:
        if not (chunk_base <= instr_va < chunk_base + len(data)):
            continue
        local = instr_va - chunk_base
        start = max(0, local - window)
        for j in range(local - 7, start - 1, -1):
            for pfx, reg_name in RIP_LOAD_PATTERNS:
                if data[j: j + 3] == pfx:
                    va  = chunk_base + j
                    disp = struct.unpack_from("<i", data, j + 3)[0]
                    static_ptr = va + 7 + disp
                    return va, reg_name, static_ptr
    return None, None, None


# ---------------------------------------------------------------------------
# Verificação de leitura de recursos
# ---------------------------------------------------------------------------

RESOURCE_LABELS = ["food", "wood", "gold", "stone"]
RESOURCE_OFFSETS = [0x00, 0x08, 0x10, 0x18]


def try_chain(pm, static_ptr_va):
    """
    Segue: *static_ptr_va → pPlayer → [+0x108] → pRes → recursos.
    Retorna True se os valores parecem plausíveis.
    """
    try:
        p_player = pm.read_longlong(static_ptr_va) & MASK64
    except Exception as e:
        return False, f"Erro lendo *static: {e}"

    if not (PTR_MIN < p_player < PTR_MAX):
        return False, f"*static=0x{p_player:X} não parece ponteiro"

    try:
        p_res = pm.read_longlong(p_player + 0x108) & MASK64
    except Exception as e:
        return False, f"Erro lendo [pPlayer+0x108]: {e}"

    if not (PTR_MIN < p_res < PTR_MAX):
        return False, f"pRes=0x{p_res:X} não parece ponteiro"

    results = []
    for label, off in zip(RESOURCE_LABELS, RESOURCE_OFFSETS):
        try:
            raw = pm.read_longlong(p_res + off) & MASK64
            # Tenta interpretar como float na metade baixa
            f32 = struct.unpack("<f", struct.pack("<I", raw & 0xFFFFFFFF))[0]
            results.append(f"{label}=0x{raw:016X} ({f32:.1f})")
        except Exception as e:
            results.append(f"{label}=ERRO({e})")

    return True, f"pPlayer=0x{p_player:X}  pRes=0x{p_res:X}  " + "  ".join(results)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    try:
        pm = pymem.Pymem(PROCESS)
        print(f"Conectado — PID {pm.process_id}  base 0x{pm.base_address:X}\n")
    except pymem.exception.ProcessNotFound:
        print(f"'{PROCESS}' não encontrado.")
        sys.exit(1)

    base = pm.base_address
    print("Lendo módulo principal (~64 MB em chunks de 4 MB)…")
    chunks = read_module_chunks(pm)
    total_mb = sum(len(d) for _, d in chunks) // 1024 // 1024
    print(f"  {total_mb} MB lidos em {len(chunks)} chunks\n")

    print("=" * 60)
    print("  Varredura: MOV Reg,[Reg+0x108]")
    print("=" * 60)
    hits = find_reads_at_0x108(chunks)
    print(f"  {len(hits)} instrução(ões) encontrada(s)\n")

    chunk_map = {cb: d for cb, d in chunks}
    seen_statics = set()

    for va, instr in hits:
        hex_instr = " ".join(f"{b:02X}" for b in instr)
        print(f"  [0x{va:X}]  {hex_instr}  (RVA exe+0x{va - base:X})")

        rip_va, reg_name, static_ptr = find_nearest_rip_load(chunks, chunk_map, va)
        if rip_va is None:
            print("    → Nenhum MOV Reg,[RIP+d] próximo encontrado\n")
            continue

        print(f"    MOV {reg_name},[RIP+d]  @ 0x{rip_va:X}  →  static ptr = 0x{static_ptr:X}")

        if static_ptr in seen_statics:
            print("    (já verificado)\n")
            continue
        seen_statics.add(static_ptr)

        ok, msg = try_chain(pm, static_ptr)
        tag = "✓" if ok else "✗"
        print(f"    {tag} {msg}\n")

    print("=" * 60)
    print("  Cole a saída completa aqui para análise.")
    print("=" * 60)


if __name__ == "__main__":
    main()
