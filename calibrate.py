"""
calibrate.py — Re-mapeamento de offsets após patches do AoE2DE.

Uso:
    python calibrate.py

O script:
  1. Anexa ao AoE2DE.exe em execução.
  2. Para cada signature em offsets.json, varre toda a memória do processo.
  3. Resolve o endereço RIP-relative de cada correspondência encontrada.
  4. Salva os endereços resolvidos de volta em offsets.json.
  5. Reporta quais signatures não foram encontradas para reconfiguração manual.

Se uma signature quebrar após um patch (não encontrada), consulte o README.md
para instruções de remapeamento manual com Cheat Engine.
"""

from __future__ import annotations

import json
import logging
import struct
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    import pymem
    import pymem.exception
except ImportError:
    print("Erro: pymem não instalado. Execute: pip install pymem")
    sys.exit(1)

from memory_reader import (
    OFFSETS_FILE,
    PROCESS_NAME,
    _build_mask,
    _parse_signature,
    _scan_pattern,
    resolve_rip_relative,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("calibrate")


# ---------------------------------------------------------------------------
# Heurísticas de resolução por tipo de campo
# ---------------------------------------------------------------------------

# Alguns campos precisam de offset_field/instr_size diferentes dependendo
# do opcode exato que a signature captura.
RESOLUTION_HINTS: dict[str, dict] = {
    # MOV RAX, [RIP+disp32]  → 48 8B 05 <disp32>  (7 bytes)
    "tc_count":         {"offset_field": 3, "instr_size": 7},
    "villager_count":   {"offset_field": 3, "instr_size": 7},
    # MOVSS XMM0, [RIP+disp32]  → F3 0F 10 05 <disp32>  (8 bytes)
    "food":             {"offset_field": 4, "instr_size": 8},
    "wood":             {"offset_field": 4, "instr_size": 8},
    "gold":             {"offset_field": 4, "instr_size": 8},
    "stone":            {"offset_field": 4, "instr_size": 8},
    # MOV RCX, [RIP+disp32]  → 48 8B 0D <disp32>  (7 bytes)
    "game_time":        {"offset_field": 3, "instr_size": 7},
    # MOV EAX, [RIP+disp32]  → 8B 05 <disp32>  (6 bytes)
    "current_age":      {"offset_field": 2, "instr_size": 6},
    # CMP BYTE PTR [RIP+disp32], 0  → 80 3D <disp32>  (8 bytes)
    "age_research":     {"offset_field": 2, "instr_size": 7},
    # MOV EDX, [RIP+disp32]  → 8B 15 <disp32>  (6 bytes)
    "idle_tc":          {"offset_field": 2, "instr_size": 6},
    "tc_queue":         {"offset_field": 3, "instr_size": 7},
}


def calibrate() -> None:
    # ------------------------------------------------------------------
    # 1. Carregar offsets.json
    # ------------------------------------------------------------------
    try:
        data = json.loads(OFFSETS_FILE.read_text(encoding="utf-8"))
    except FileNotFoundError:
        logger.error("offsets.json não encontrado em %s", OFFSETS_FILE)
        sys.exit(1)

    signatures: dict[str, str] = data.get("signatures", {})
    if not signatures:
        logger.error("Nenhuma signature encontrada em offsets.json")
        sys.exit(1)

    # ------------------------------------------------------------------
    # 2. Anexar ao processo
    # ------------------------------------------------------------------
    logger.info("Anexando ao processo %s ...", PROCESS_NAME)
    try:
        pm = pymem.Pymem(PROCESS_NAME)
    except pymem.exception.ProcessNotFound:
        logger.error(
            "Processo '%s' não encontrado. Abra o AoE2DE antes de executar este script.\n"
            "  Dica: verifique o nome real com: Get-Process | Select-Object Name",
            PROCESS_NAME,
        )
        sys.exit(1)
    except Exception as exc:
        logger.error("Erro ao anexar: %s", exc)
        sys.exit(1)

    logger.info("Anexado. Base: 0x%X  PID: %d", pm.base_address, pm.process_id)
    logger.info("Iniciando varredura de memória — isso pode levar alguns segundos...\n")

    # ------------------------------------------------------------------
    # 3. Varrer cada signature
    # ------------------------------------------------------------------
    new_offsets: dict[str, str] = {}
    broken: list[str] = []
    found: list[str] = []

    total = len(signatures)
    for idx, (name, sig_str) in enumerate(signatures.items(), 1):
        logger.info("[%d/%d] Procurando: %-20s  sig: %s", idx, total, name, sig_str)

        pattern = _parse_signature(sig_str)
        mask    = _build_mask(sig_str)

        scan_result = _scan_pattern(pm, pattern, mask, pm.base_address)

        if scan_result is None:
            logger.warning("  ✗ Não encontrada: %s", name)
            broken.append(name)
            new_offsets[name] = "0x00000000"
            continue

        hints = RESOLUTION_HINTS.get(name, {"offset_field": 3, "instr_size": 7})
        try:
            resolved = resolve_rip_relative(
                pm,
                scan_result,
                offset_field=hints["offset_field"],
                instr_size=hints["instr_size"],
            )
            new_offsets[name] = hex(resolved)
            found.append(name)
            logger.info("  ✓ Resolvido: 0x%X  (instrução em 0x%X)", resolved, scan_result)
        except Exception as exc:
            logger.warning("  ✗ Falha ao resolver %s: %s", name, exc)
            broken.append(name)
            new_offsets[name] = "0x00000000"

    # ------------------------------------------------------------------
    # 4. Salvar offsets.json atualizado
    # ------------------------------------------------------------------
    data["offsets"]       = new_offsets
    data["calibrated_at"] = datetime.now(timezone.utc).isoformat()

    OFFSETS_FILE.write_text(
        json.dumps(data, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    logger.info("\noffsets.json atualizado.")

    # ------------------------------------------------------------------
    # 5. Relatório final
    # ------------------------------------------------------------------
    print("\n" + "=" * 60)
    print(f"  RESULTADO DA CALIBRAÇÃO")
    print("=" * 60)
    print(f"  Encontradas:     {len(found)}/{total}")
    print(f"  Quebradas:       {len(broken)}/{total}")

    if found:
        print("\n  OK:")
        for n in found:
            print(f"    ✓  {n}  →  {new_offsets[n]}")

    if broken:
        print("\n  QUEBRADAS (requerem remapeamento manual):")
        for n in broken:
            print(f"    ✗  {n}")
        print("\n  → Consulte o README.md para instruções de remapeamento com Cheat Engine.")

    print("=" * 60)


if __name__ == "__main__":
    calibrate()
