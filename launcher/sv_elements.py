from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Dict, List, Sequence, Tuple

from sv_sprite_stretch import MIN_SIZE, widened

SPRITE_BORDER = 4

_ACCENT_STATES: Sequence[Tuple[Tuple[str, ...], str]] = (
    (("selected", "disabled"), "button-accent-dis"),
    (("disabled",), "button-accent-dis"),
    (("active", "focus"), "button-accent-focus-hover"),
    (("focus",), "button-accent-focus"),
    (("selected",), "button-accent-rest"),
    (("pressed",), "button-accent-pressed"),
    (("active",), "button-accent-hover"),
)

SPLIT_MAIN_STYLE = "SplitMain.Accent.TButton"
SPLIT_DROP_STYLE = "SplitDrop.Accent.TButton"


def _theme_namespace(root: tk.Misc) -> str:
    return str(root.tk.call("ttk::style", "theme", "use")).replace(
        "sun-valley-", "sv_")


def _sprite(root: tk.Misc, name: str) -> str:
    return str(root.tk.eval("set ttk::theme::{}::I({})".format(
        _theme_namespace(root), name)))


def _theme_background(root: tk.Misc) -> str:
    return str(root.tk.eval("set ttk::theme::{}::theme_colors(-bg)".format(
        _theme_namespace(root))))


def _button_layout(element: str) -> list:
    return [(element, {"sticky": "nswe", "children": [
        ("Button.padding", {"sticky": "nswe", "children": [
            ("Button.label", {"sticky": "nswe"})]})]})]


def _create_toolbar(root: tk.Misc, style: ttk.Style,
                    keep: List[tk.PhotoImage]) -> None:
    rest = tk.PhotoImage(master=root, width=MIN_SIZE, height=MIN_SIZE)
    rest.put(_theme_background(root), to=(0, 0, MIN_SIZE, MIN_SIZE))
    keep.append(rest)
    pressed, width, height = widened(root, _sprite(root, "button-pressed"),
                                     (SPRITE_BORDER,))
    hover, _, _ = widened(root, _sprite(root, "button-hover"),
                          (SPRITE_BORDER,))
    style.element_create("Toolbar.button", "image", rest,
                         ("pressed", pressed), ("active", "!disabled", hover),
                         border=SPRITE_BORDER, width=width, height=height,
                         sticky="nsew")
    style.layout("Toolbar.TButton", _button_layout("Toolbar.button"))


def _cut(root: tk.Misc, keep: List[tk.PhotoImage], sprite: str,
         left: bool) -> tk.PhotoImage:
    width = int(root.tk.call("image", "width", sprite))
    height = int(root.tk.call("image", "height", sprite))
    x0, x1 = (0, width - SPRITE_BORDER) if left else (SPRITE_BORDER, width)
    piece = tk.PhotoImage(master=root, width=x1 - x0, height=height)
    root.tk.call(piece, "copy", sprite, "-from", x0, 0, x1, height)
    keep.append(piece)
    return piece


def _create_split_half(root: tk.Misc, style: ttk.Style,
                       keep: List[tk.PhotoImage], element: str,
                       left: bool) -> None:
    def cut(name: str) -> tk.PhotoImage:
        return _cut(root, keep, widened(root, _sprite(root, name),
                                        (SPRITE_BORDER,))[0], left)
    _, width, height = widened(root, _sprite(root, "button-accent-rest"),
                               (SPRITE_BORDER,))
    states = [state + (cut(name),) for state, name in _ACCENT_STATES]
    b = SPRITE_BORDER
    style.element_create(element, "image", cut("button-accent-rest"), *states,
                         border=(b, b, 0, b) if left else (0, b, b, b),
                         width=width - SPRITE_BORDER, height=height,
                         sticky="nsew")


def create(root: tk.Misc, style: ttk.Style) -> None:
    if "Toolbar.button" in style.element_names():
        return
    images: Dict[str, List[tk.PhotoImage]] = root.__dict__.setdefault(
        "_sv_element_images", {})
    keep = images.setdefault(_theme_namespace(root), [])
    _create_toolbar(root, style, keep)
    _create_split_half(root, style, keep, "SplitMain.button", left=True)
    _create_split_half(root, style, keep, "SplitDrop.button", left=False)
    style.layout(SPLIT_MAIN_STYLE, _button_layout("SplitMain.button"))
    style.layout(SPLIT_DROP_STYLE, _button_layout("SplitDrop.button"))
