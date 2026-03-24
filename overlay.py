"""
overlay.py — Janela overlay transparente sempre-no-topo para o AoE2Coach.

Características:
- Fundo semi-transparente escuro, texto branco
- Dica da IA destacada em amarelo
- Hotkey configurável (padrão: F8) para mostrar/ocultar
- Arrastar com clique para reposicionar
- Atualização thread-safe via fila de eventos
"""

from __future__ import annotations

import logging
import queue
import threading
import tkinter as tk
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuração visual
# ---------------------------------------------------------------------------

BG_COLOR        = "#1A1A1A"
TEXT_COLOR      = "#FFFFFF"
TIP_COLOR       = "#FFD700"   # amarelo ouro
LABEL_COLOR     = "#AAAAAA"   # cinza claro para rótulos
BORDER_COLOR    = "#444444"

FONT_NORMAL     = ("Consolas", 11)
FONT_SMALL      = ("Consolas", 10)
FONT_TIP        = ("Consolas", 11, "bold")
FONT_TITLE      = ("Consolas", 12, "bold")

ALPHA           = 0.85        # transparência da janela (0.0 = invisível, 1.0 = opaco)
DEFAULT_HOTKEY  = "F8"

PAD             = 10


# ---------------------------------------------------------------------------
# Eventos internos
# ---------------------------------------------------------------------------

@dataclass
class _UpdateEvent:
    """Atualização de estado do jogo."""
    game_time:    str
    age:          str
    villagers:    int
    prod:         int
    tc_count:     int
    idle_tcs:     int
    tc_queue:     int
    food:         int
    wood:         int
    gold:         int
    stone:        int
    connected:    bool

@dataclass
class _TipEvent:
    """Nova dica da IA."""
    tip: str

@dataclass
class _StatusEvent:
    """Mensagem de status (aguardando jogo, erro, etc.)."""
    message: str


# ---------------------------------------------------------------------------
# Overlay
# ---------------------------------------------------------------------------

class Overlay:
    """
    Janela tkinter sempre-no-topo, arrastável, com hotkey de toggle.

    Deve ser criada e gerenciada na thread principal (tkinter não é thread-safe).
    Use enqueue_update(), enqueue_tip() e enqueue_status() de outras threads.
    """

    def __init__(self, hotkey: str = DEFAULT_HOTKEY):
        self.hotkey = hotkey
        self._queue: queue.Queue = queue.Queue()
        self._visible = True
        self._drag_x = 0
        self._drag_y = 0

        self._root: Optional[tk.Tk] = None
        self._tip_text: Optional[tk.StringVar] = None
        self._status_text: Optional[tk.StringVar] = None

        # Variáveis de exibição
        self._vars: dict[str, tk.StringVar] = {}

    # ------------------------------------------------------------------
    # API pública (thread-safe)
    # ------------------------------------------------------------------

    def enqueue_update(self, **kwargs) -> None:
        """Agenda atualização de estado do jogo. Chamável de qualquer thread."""
        self._queue.put(_UpdateEvent(**kwargs))

    def enqueue_tip(self, tip: str) -> None:
        """Agenda nova dica da IA. Chamável de qualquer thread."""
        self._queue.put(_TipEvent(tip=tip))

    def enqueue_status(self, message: str) -> None:
        """Agenda mensagem de status. Chamável de qualquer thread."""
        self._queue.put(_StatusEvent(message=message))

    def run(self) -> None:
        """Inicia o loop principal do tkinter (bloqueante — chame da thread principal)."""
        self._build_window()
        self._bind_hotkey()
        self._schedule_queue_poll()
        self._root.mainloop()

    def destroy(self) -> None:
        if self._root:
            self._root.destroy()

    # ------------------------------------------------------------------
    # Construção da janela
    # ------------------------------------------------------------------

    def _build_window(self) -> None:
        root = tk.Tk()
        root.title("AoE2Coach")
        root.overrideredirect(True)          # sem barra de título
        root.attributes("-topmost", True)
        root.attributes("-alpha", ALPHA)
        root.configure(bg=BG_COLOR)

        # Posição inicial: canto superior direito (será ajustada pelo usuário)
        root.geometry(f"+{root.winfo_screenwidth() - 420}+20")

        self._root = root
        self._build_ui(root)
        self._bind_drag(root)

    def _mkvar(self, name: str, initial: str = "") -> tk.StringVar:
        v = tk.StringVar(value=initial)
        self._vars[name] = v
        return v

    def _build_ui(self, parent: tk.Tk) -> None:
        # Frame principal com borda
        outer = tk.Frame(parent, bg=BORDER_COLOR, padx=1, pady=1)
        outer.pack(fill=tk.BOTH, expand=True)

        inner = tk.Frame(outer, bg=BG_COLOR, padx=PAD, pady=PAD)
        inner.pack(fill=tk.BOTH, expand=True)

        # ── Título ──────────────────────────────────────────────────
        title_row = tk.Frame(inner, bg=BG_COLOR)
        title_row.pack(fill=tk.X, pady=(0, 6))

        tk.Label(title_row, text="⚔ AoE2 Coach", font=FONT_TITLE,
                 fg=TIP_COLOR, bg=BG_COLOR).pack(side=tk.LEFT)

        self._status_text = self._mkvar("status", "Aguardando jogo...")
        tk.Label(title_row, textvariable=self._status_text,
                 font=FONT_SMALL, fg=LABEL_COLOR, bg=BG_COLOR).pack(side=tk.RIGHT)

        tk.Frame(inner, bg=BORDER_COLOR, height=1).pack(fill=tk.X, pady=(0, 6))

        # ── Tempo e idade ───────────────────────────────────────────
        row1 = tk.Frame(inner, bg=BG_COLOR)
        row1.pack(fill=tk.X, pady=1)

        self._lbl("row1", row1, "Tempo:", "game_time", "00:00")
        self._lbl("row1b", row1, "Idade:", "age", "Dark Age", side=tk.RIGHT)

        # ── Aldeões e TCs ───────────────────────────────────────────
        row2 = tk.Frame(inner, bg=BG_COLOR)
        row2.pack(fill=tk.X, pady=1)

        self._lbl("r2a", row2, "Aldeões:", "villagers", "0")
        self._lbl("r2b", row2, "TCs:", "tc_status", "0  (idle: 0)", side=tk.RIGHT)

        # ── Recursos ────────────────────────────────────────────────
        row3 = tk.Frame(inner, bg=BG_COLOR)
        row3.pack(fill=tk.X, pady=1)

        for emoji, key, col in (
            ("🌾", "food",  tk.LEFT),
            ("🪵", "wood",  tk.LEFT),
            ("💰", "gold",  tk.LEFT),
            ("🪨", "stone", tk.LEFT),
        ):
            tk.Label(row3, text=emoji, font=FONT_SMALL,
                     fg=TEXT_COLOR, bg=BG_COLOR).pack(side=col, padx=(0, 2))
            v = self._mkvar(key, "0")
            tk.Label(row3, textvariable=v, font=FONT_NORMAL,
                     fg=TEXT_COLOR, bg=BG_COLOR, width=6, anchor="w").pack(side=col, padx=(0, 6))

        tk.Frame(inner, bg=BORDER_COLOR, height=1).pack(fill=tk.X, pady=(6, 4))

        # ── Dica da IA ───────────────────────────────────────────────
        tk.Label(inner, text="💡 Dica do Coach:", font=FONT_SMALL,
                 fg=LABEL_COLOR, bg=BG_COLOR, anchor="w").pack(fill=tk.X)

        self._tip_text = self._mkvar("tip", "Aguardando primeira leitura...")
        tk.Label(inner, textvariable=self._tip_text,
                 font=FONT_TIP, fg=TIP_COLOR, bg=BG_COLOR,
                 wraplength=380, justify=tk.LEFT, anchor="w").pack(
            fill=tk.X, pady=(2, 0))

    def _lbl(self, _id: str, parent: tk.Frame, label: str,
             var_name: str, initial: str, side=tk.LEFT) -> None:
        tk.Label(parent, text=label, font=FONT_SMALL,
                 fg=LABEL_COLOR, bg=BG_COLOR).pack(side=side, padx=(0, 3))
        v = self._mkvar(var_name, initial)
        tk.Label(parent, textvariable=v, font=FONT_NORMAL,
                 fg=TEXT_COLOR, bg=BG_COLOR).pack(side=side, padx=(0, 12))

    # ------------------------------------------------------------------
    # Arrastar janela
    # ------------------------------------------------------------------

    def _bind_drag(self, widget: tk.Widget) -> None:
        widget.bind("<ButtonPress-1>",   self._on_drag_start)
        widget.bind("<B1-Motion>",       self._on_drag_motion)

        for child in widget.winfo_children():
            self._bind_drag(child)

    def _on_drag_start(self, event) -> None:
        self._drag_x = event.x_root - self._root.winfo_x()
        self._drag_y = event.y_root - self._root.winfo_y()

    def _on_drag_motion(self, event) -> None:
        x = event.x_root - self._drag_x
        y = event.y_root - self._drag_y
        self._root.geometry(f"+{x}+{y}")

    # ------------------------------------------------------------------
    # Hotkey (toggle visibilidade)
    # ------------------------------------------------------------------

    def _bind_hotkey(self) -> None:
        try:
            import keyboard
            keyboard.add_hotkey(self.hotkey, self._toggle_visibility,
                                suppress=False)
            logger.info("Hotkey '%s' registrada para toggle do overlay.", self.hotkey)
        except ImportError:
            logger.warning("keyboard não instalado — hotkey desabilitada.")
        except Exception as exc:
            logger.warning("Não foi possível registrar hotkey '%s': %s",
                           self.hotkey, exc)

    def _toggle_visibility(self) -> None:
        if self._root is None:
            return
        self._visible = not self._visible
        if self._visible:
            self._root.deiconify()
        else:
            self._root.withdraw()

    # ------------------------------------------------------------------
    # Fila de atualização
    # ------------------------------------------------------------------

    def _schedule_queue_poll(self) -> None:
        self._root.after(100, self._poll_queue)

    def _poll_queue(self) -> None:
        try:
            while True:
                event = self._queue.get_nowait()
                self._process_event(event)
        except queue.Empty:
            pass
        finally:
            if self._root:
                self._root.after(100, self._poll_queue)

    def _process_event(self, event) -> None:
        if isinstance(event, _UpdateEvent):
            self._apply_update(event)
        elif isinstance(event, _TipEvent):
            if self._tip_text:
                self._tip_text.set(event.tip)
        elif isinstance(event, _StatusEvent):
            if self._status_text:
                self._status_text.set(event.message)

    def _apply_update(self, e: _UpdateEvent) -> None:
        def sv(name: str, value) -> None:
            v = self._vars.get(name)
            if v:
                v.set(str(value))

        sv("game_time", e.game_time)
        sv("age", e.age + (" Age" if not e.age.endswith("Age") else ""))
        sv("villagers",
           f"{e.villagers} (+{e.prod} prod.)" if e.prod else str(e.villagers))
        sv("tc_status",
           f"{e.tc_count}  (idle: {e.idle_tcs}, fila: {e.tc_queue})")
        sv("food",  str(e.food))
        sv("wood",  str(e.wood))
        sv("gold",  str(e.gold))
        sv("stone", str(e.stone))

        if self._status_text:
            self._status_text.set(
                "● Conectado" if e.connected else "○ Desconectado"
            )
