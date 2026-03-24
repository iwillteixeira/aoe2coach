"""
main.py — Entry point do AoE2Coach.

Inicializa o MemoryReader, o AoE2Coach e o Overlay, conectando-os
de forma que:
  - O MemoryReader faz polling a cada 3 s e notifica quando o estado muda.
  - O AoE2Coach é chamado na mesma thread de background para gerar a dica.
  - O Overlay é atualizado via fila thread-safe.
  - O loop tkinter roda na thread principal.

Uso:
    python main.py [--hotkey KEY] [--no-coach]

Variáveis de ambiente:
    ANTHROPIC_API_KEY   Obrigatória para o coach (pode ser omitida com --no-coach).
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
import threading
import time

from memory_reader import MemoryReader, GameState
from coach import AoE2Coach
from overlay import Overlay

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  [%(name)s]  %(message)s",
    datefmt="%H:%M:%S",
    handlers=[
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger("main")

# ---------------------------------------------------------------------------
# Argumentos
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="AoE2Coach — leitura de memória + coaching por IA",
    )
    parser.add_argument(
        "--hotkey",
        default="F8",
        help="Tecla de atalho para mostrar/ocultar o overlay (padrão: F8)",
    )
    parser.add_argument(
        "--no-coach",
        action="store_true",
        help="Desabilita a integração com a API da Anthropic (modo monitor)",
    )
    parser.add_argument(
        "--poll",
        type=float,
        default=3.0,
        help="Intervalo de polling em segundos (padrão: 3.0)",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Habilita logs de depuração",
    )
    return parser.parse_args()


# ---------------------------------------------------------------------------
# Aplicação principal
# ---------------------------------------------------------------------------

class AoE2CoachApp:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.overlay = Overlay(hotkey=args.hotkey)
        self.coach: AoE2Coach | None = None
        self.reader: MemoryReader | None = None
        self._coach_lock = threading.Lock()  # evita chamadas simultâneas à API

        # Inicializa o coach (se habilitado)
        if not args.no_coach:
            try:
                self.coach = AoE2Coach()
                logger.info("AoE2Coach inicializado.")
            except ValueError as exc:
                logger.warning("Coach desabilitado: %s", exc)
                self.overlay.enqueue_tip(
                    "Coach desabilitado — defina ANTHROPIC_API_KEY para ativar."
                )

    # ------------------------------------------------------------------
    # Callback do MemoryReader
    # ------------------------------------------------------------------

    def _on_state_change(self, state: GameState) -> None:
        """Chamado pela thread do MemoryReader quando o estado muda."""
        # Atualiza o overlay com os novos dados
        self.overlay.enqueue_update(
            game_time  = state.game_time_str(),
            age        = state.age_name(),
            villagers  = state.villagers,
            prod       = state.villagers_producing,
            tc_count   = state.tc_count,
            idle_tcs   = state.idle_tc,
            tc_queue   = state.tc_queue,
            food       = int(state.food),
            wood       = int(state.wood),
            gold       = int(state.gold),
            stone      = int(state.stone),
            connected  = True,
        )

        # Solicita dica ao coach (não bloqueante; ignora se já estiver rodando)
        if self.coach is None:
            return

        if not self._coach_lock.acquire(blocking=False):
            logger.debug("Coach ocupado — pulando esta mudança.")
            return

        def _run_coach():
            try:
                self.overlay.enqueue_tip("⏳ Analisando...")
                tip = self.coach.get_tip(state)
                self.overlay.enqueue_tip(tip)
            except Exception as exc:
                logger.error("Erro no coach thread: %s", exc)
                self.overlay.enqueue_tip("Erro ao consultar o coach.")
            finally:
                self._coach_lock.release()

        threading.Thread(target=_run_coach, name="CoachThread", daemon=True).start()

    # ------------------------------------------------------------------
    # Thread de atualização periódica do overlay (mesmo sem mudanças)
    # ------------------------------------------------------------------

    def _overlay_refresh_loop(self) -> None:
        """
        Atualiza o overlay periodicamente mesmo quando não há mudança de estado,
        para manter o contador de tempo visível.
        """
        while True:
            if self.reader and self.reader.connected:
                state = self.reader.state
                self.overlay.enqueue_update(
                    game_time  = state.game_time_str(),
                    age        = state.age_name(),
                    villagers  = state.villagers,
                    prod       = state.villagers_producing,
                    tc_count   = state.tc_count,
                    idle_tcs   = state.idle_tc,
                    tc_queue   = state.tc_queue,
                    food       = int(state.food),
                    wood       = int(state.wood),
                    gold       = int(state.gold),
                    stone      = int(state.stone),
                    connected  = True,
                )
            else:
                self.overlay.enqueue_status("○ Aguardando AoE2DE.exe...")

            time.sleep(1)

    # ------------------------------------------------------------------
    # Inicialização
    # ------------------------------------------------------------------

    def run(self) -> None:
        logger.info("Iniciando AoE2Coach...")
        logger.info("Hotkey para toggle: %s", self.args.hotkey)
        if self.args.no_coach:
            logger.info("Modo monitor (sem coach).")

        # Aviso sobre necessidade de direitos de administrador
        logger.info(
            "AVISO: A leitura de memória requer que este processo tenha "
            "privilégios suficientes. Execute como Administrador se necessário."
        )

        # Inicia o MemoryReader
        self.reader = MemoryReader(
            on_state_change=self._on_state_change,
            poll_interval=self.args.poll,
        )
        self.reader.start()

        # Inicia a thread de refresh periódico do overlay
        refresh_thread = threading.Thread(
            target=self._overlay_refresh_loop,
            name="OverlayRefresh",
            daemon=True,
        )
        refresh_thread.start()

        # Mensagem inicial no overlay
        self.overlay.enqueue_status("○ Aguardando AoE2DE.exe...")
        self.overlay.enqueue_tip(
            "Inicie o AoE2DE e entre em uma partida para começar."
        )

        # Loop principal do tkinter (bloqueante)
        try:
            self.overlay.run()
        except KeyboardInterrupt:
            logger.info("Encerrado pelo usuário.")
        finally:
            if self.reader:
                self.reader.stop()
            logger.info("AoE2Coach encerrado.")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    args = parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    app = AoE2CoachApp(args)
    app.run()


if __name__ == "__main__":
    main()
