"""
automator.py — Produção automática de aldeões em TCs ociosos.

Envia inputs DIRETAMENTE para o handle da janela do AoE2DE via PostMessage,
sem precisar de foco na janela e sem interferir com o que o jogador
está digitando em outro lugar.

Fluxo por TC ocioso:
  1. PostMessage → hotkey "Ir ao próximo TC ocioso"
  2. Aguarda o jogo processar (delay configurável)
  3. PostMessage → hotkey "Produzir aldeão"
  4. Repete para cada TC ocioso detectado

Configuração necessária no jogo:
  - Atribua uma tecla para "Ir ao próximo TC ocioso" (Town Center → Go to next idle)
  - Anote qual tecla é usada para produzir aldeão no seu layout (padrão: A)
  - Informe essas teclas em main.py (--idle-tc-key e --vill-key)
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Optional

try:
    import win32api
    import win32con
    import win32gui
except ImportError:
    raise ImportError(
        "pywin32 não instalado. Execute: pip install pywin32"
    )

logger = logging.getLogger(__name__)

WINDOW_TITLE_SUBSTR = "Age of Empires II"

# Teclas especiais: nome → virtual key code
SPECIAL_KEYS: dict[str, int] = {
    "home":   win32con.VK_HOME,
    "end":    win32con.VK_END,
    "insert": win32con.VK_INSERT,
    "delete": win32con.VK_DELETE,
    "pgup":   win32con.VK_PRIOR,
    "pgdn":   win32con.VK_NEXT,
    "f1":     win32con.VK_F1,
    "f2":     win32con.VK_F2,
    "f3":     win32con.VK_F3,
    "f4":     win32con.VK_F4,
    "f5":     win32con.VK_F5,
    "f6":     win32con.VK_F6,
    "f7":     win32con.VK_F7,
    "f8":     win32con.VK_F8,
    "f9":     win32con.VK_F9,
    "f10":    win32con.VK_F10,
    "f11":    win32con.VK_F11,
    "f12":    win32con.VK_F12,
    "space":  win32con.VK_SPACE,
    "tab":    win32con.VK_TAB,
    "numpad0": win32con.VK_NUMPAD0,
    "numpad1": win32con.VK_NUMPAD1,
    "numpad2": win32con.VK_NUMPAD2,
    "numpad3": win32con.VK_NUMPAD3,
    "numpad4": win32con.VK_NUMPAD4,
    "numpad5": win32con.VK_NUMPAD5,
}


def _resolve_vk(key: str) -> int:
    """Converte nome ou caractere de tecla em virtual key code."""
    lower = key.lower().strip()
    if lower in SPECIAL_KEYS:
        return SPECIAL_KEYS[lower]
    # Caractere único (letra, número, símbolo)
    vk = win32api.VkKeyScanEx(key[0], win32api.GetKeyboardLayout(0)) & 0xFF
    if vk == 0xFF:
        raise ValueError(f"Tecla não reconhecida: '{key}'")
    return vk


def _find_game_window() -> Optional[int]:
    """Retorna o handle da janela do AoE2DE ou None se não encontrada."""
    result: list[int] = []

    def _enum(hwnd: int, _) -> bool:
        if win32gui.IsWindowVisible(hwnd):
            title = win32gui.GetWindowText(hwnd)
            if WINDOW_TITLE_SUBSTR in title:
                result.append(hwnd)
        return True

    win32gui.EnumWindows(_enum, None)
    return result[0] if result else None


def _post_key(hwnd: int, vk: int, delay_after: float = 0.05) -> None:
    """Envia WM_KEYDOWN + WM_KEYUP para o handle informado."""
    scan = win32api.MapVirtualKey(vk, 0)

    lp_down = 1 | (scan << 16)
    lp_up   = 1 | (scan << 16) | (1 << 30) | (1 << 31)

    win32api.PostMessage(hwnd, win32con.WM_KEYDOWN, vk, lp_down)
    time.sleep(delay_after)
    win32api.PostMessage(hwnd, win32con.WM_KEYUP, vk, lp_up)


# ---------------------------------------------------------------------------
# AutoVillager
# ---------------------------------------------------------------------------

class AutoVillager:
    """
    Monitora TCs ociosos e enfileira aldeões automaticamente via PostMessage.

    Parâmetros:
        idle_tc_key   Tecla configurada no jogo para "Ir ao próximo TC ocioso"
        vill_key      Tecla de produção de aldeão no seu layout de hotkeys
        key_delay     Segundos entre cada PostMessage (padrão: 0.15)
        tc_delay      Segundos entre processar cada TC (padrão: 0.20)
        cooldown      Segundos de espera após uma rodada completa (padrão: 4.0)
    """

    def __init__(
        self,
        idle_tc_key: str = "Home",
        vill_key: str    = "A",
        key_delay: float = 0.15,
        tc_delay: float  = 0.20,
        cooldown: float  = 4.0,
    ):
        self.idle_tc_key = idle_tc_key
        self.vill_key    = vill_key
        self.key_delay   = key_delay
        self.tc_delay    = tc_delay
        self.cooldown    = cooldown

        self._vk_idle_tc: Optional[int] = None
        self._vk_vill: Optional[int]    = None
        self._last_trigger: float       = 0.0
        self._lock = threading.Lock()
        self._enabled = True

        self._resolve_keys()

    def _resolve_keys(self) -> None:
        try:
            self._vk_idle_tc = _resolve_vk(self.idle_tc_key)
            self._vk_vill    = _resolve_vk(self.vill_key)
            logger.info(
                "AutoVillager configurado — TC ocioso: '%s' (VK 0x%02X) | "
                "Aldeão: '%s' (VK 0x%02X)",
                self.idle_tc_key, self._vk_idle_tc,
                self.vill_key,    self._vk_vill,
            )
        except ValueError as exc:
            logger.error("AutoVillager: %s", exc)
            self._enabled = False

    # ------------------------------------------------------------------
    # API pública
    # ------------------------------------------------------------------

    @property
    def enabled(self) -> bool:
        return self._enabled

    def toggle(self) -> bool:
        """Liga/desliga. Retorna o novo estado."""
        self._enabled = not self._enabled
        logger.info("AutoVillager %s.", "ATIVADO" if self._enabled else "DESATIVADO")
        return self._enabled

    def try_queue(self, idle_tc: int) -> bool:
        """
        Tenta enfileirar 1 aldeão por TC ocioso.
        Retorna True se executou, False se no cooldown ou desabilitado.

        Deve ser chamado de uma thread de background — nunca da thread tkinter.
        """
        if not self._enabled:
            return False
        if idle_tc <= 0:
            return False

        now = time.monotonic()
        if now - self._last_trigger < self.cooldown:
            return False

        # Adquire lock para evitar disparos simultâneos
        if not self._lock.acquire(blocking=False):
            return False

        try:
            hwnd = _find_game_window()
            if hwnd is None:
                logger.warning("AutoVillager: janela do AoE2DE não encontrada.")
                return False

            logger.info(
                "AutoVillager: %d TC(s) ocioso(s) → enfileirando aldeões...",
                idle_tc,
            )

            for i in range(idle_tc):
                # Navega para o próximo TC ocioso
                _post_key(hwnd, self._vk_idle_tc, delay_after=self.key_delay)
                # Produz aldeão
                _post_key(hwnd, self._vk_vill,    delay_after=self.key_delay)

                if i < idle_tc - 1:
                    time.sleep(self.tc_delay)

            self._last_trigger = time.monotonic()
            logger.info("AutoVillager: %d aldeão(ões) enfileirado(s).", idle_tc)
            return True

        except Exception as exc:
            logger.error("AutoVillager erro: %s", exc)
            return False
        finally:
            self._lock.release()
