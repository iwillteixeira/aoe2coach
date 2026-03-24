"""
coach.py — Integração com a API da Anthropic para coaching de AoE2DE.

Recebe um GameState, monta um contexto e chama Claude para obter
uma dica curta e acionável (máx 2 linhas).
"""

from __future__ import annotations

import logging
import os
from typing import Optional

try:
    import anthropic
except ImportError:
    raise ImportError("anthropic não instalado. Execute: pip install anthropic")

from memory_reader import GameState

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuração
# ---------------------------------------------------------------------------

MODEL = "claude-opus-4-6"

SYSTEM_PROMPT = """Você é um coach especialista em Age of Empires 2 Definitive Edition.
Seu objetivo é dar dicas curtas, precisas e imediatamente acionáveis ao jogador.

Benchmarks de referência (Pro / Fast):
- Feudal Age up: ~10:00–10:30 min (22 aldeões)
- Castle Age up: ~20:00–21:00 min (30–32 aldeões)
- Imperial Age up: ~35:00–38:00 min
- 30 aldeões antes de entrar no Castle Age
- Nenhum TC deve ficar idle por mais de 5 segundos durante booming
- Fila de aldeões em todos os TCs sempre que possível

Regras de resposta:
- Máximo 2 linhas de texto (sem bullet points, sem markdown).
- Foco em UMA ação imediata e concreta.
- Se tudo está bem, diga isso brevemente e aponte o próximo milestone.
- Nunca repita o estado do jogo de volta ao jogador — vá direto à dica.
- Responda sempre em português do Brasil."""


# ---------------------------------------------------------------------------
# Coach
# ---------------------------------------------------------------------------

class AoE2Coach:
    """
    Chama a API da Anthropic com o estado atual do jogo e retorna uma dica.
    Usa streaming para minimizar latência percebida.
    """

    def __init__(self, api_key: Optional[str] = None):
        key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not key:
            raise ValueError(
                "ANTHROPIC_API_KEY não definida. "
                "Exporte a variável de ambiente antes de iniciar."
            )
        self._client = anthropic.Anthropic(api_key=key)

    # ------------------------------------------------------------------
    # Geração de dica
    # ------------------------------------------------------------------

    def get_tip(self, state: GameState) -> str:
        """
        Retorna uma dica de coaching baseada no estado atual do jogo.
        Usa streaming e retorna o texto completo ao término.
        """
        user_message = self._build_user_message(state)
        logger.debug("Solicitando dica para estado: %s", state.as_dict())

        try:
            with self._client.messages.stream(
                model=MODEL,
                max_tokens=256,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": user_message}],
                thinking={"type": "adaptive"},
            ) as stream:
                tip = stream.get_final_message()

            # Extrai apenas o bloco de texto (ignora blocos de thinking)
            text_blocks = [b.text for b in tip.content if b.type == "text"]
            result = " ".join(text_blocks).strip()
            logger.info("Dica gerada: %s", result[:120])
            return result

        except anthropic.AuthenticationError:
            return "Erro: ANTHROPIC_API_KEY inválida."
        except anthropic.RateLimitError:
            return "Coaching temporariamente indisponível (rate limit). Aguarde."
        except anthropic.APIConnectionError:
            return "Sem conexão com a API. Verifique sua internet."
        except Exception as exc:
            logger.error("Erro inesperado no coach: %s", exc)
            return "Erro ao obter dica de coaching."

    # ------------------------------------------------------------------
    # Montagem do payload
    # ------------------------------------------------------------------

    @staticmethod
    def _build_user_message(state: GameState) -> str:
        s = state.as_dict()

        lines = [
            f"Tempo: {s['game_time']}  |  Idade: {s['age']}"
            + (" (pesquisando próxima idade)" if s["researching_age"] else ""),
            f"Aldeões: {s['villagers']} (+{s['villagers_producing']} produzindo)  |  "
            f"TCs: {s['tc_count']} ({s['idle_tcs']} ociosos, fila: {s['tc_queue']})",
            f"Recursos — Comida: {s['food']}  Madeira: {s['wood']}  "
            f"Ouro: {s['gold']}  Pedra: {s['stone']}",
        ]

        # Contexto extra para situações críticas
        alerts: list[str] = []
        if s["idle_tcs"] > 0:
            alerts.append(f"ALERTA: {s['idle_tcs']} TC(s) ociosos!")
        if s["tc_queue"] == 0 and s["villagers"] < 30:
            alerts.append("Nenhum aldeão em produção (fila vazia).")
        if alerts:
            lines.append("⚠ " + " | ".join(alerts))

        return "\n".join(lines)
