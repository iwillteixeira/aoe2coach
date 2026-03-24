"""
diagnose.py — Verifica o que está sendo lido em cada endereço do offsets.json.
Execute com o jogo aberto para ver os valores brutos.
"""
import json, struct
from pathlib import Path
import pymem, pymem.exception

PROCESS = "AoE2DE_s.exe"
OFFSETS = json.loads(Path("offsets.json").read_text())["offsets"]

try:
    pm = pymem.Pymem(PROCESS)
    print(f"Conectado — base: 0x{pm.base_address:X}\n")
except pymem.exception.ProcessNotFound:
    print("Processo não encontrado. Abra o jogo.")
    exit(1)

print(f"{'Campo':<20} {'Endereço':<20} {'Int':>10} {'Float':>12} {'Byte':>6}")
print("-" * 72)

for name, addr_str in OFFSETS.items():
    addr = int(addr_str, 16)
    if addr == 0:
        print(f"{name:<20} {'(não mapeado)':<20}")
        continue
    try:
        raw = pm.read_bytes(addr, 4)
        as_int   = struct.unpack("<i", raw)[0]
        as_uint  = struct.unpack("<I", raw)[0]
        as_float = struct.unpack("<f", raw)[0]
        as_byte  = raw[0]
        print(f"{name:<20} 0x{addr:<18X} {as_int:>10} {as_float:>12.2f} {as_byte:>6}")
    except Exception as e:
        print(f"{name:<20} 0x{addr:<18X}  ERRO: {e}")
