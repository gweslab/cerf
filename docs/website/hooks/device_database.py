import html
import json

from board_database import (BOARD_CONFIG_PARAMS, BOARD_FAMILIES_BY_ID, BOARDS, GENERIC_PARTS, board_sort_key,
                            soc_family_of, soc_of, sort_text)
from build_site import ICONS_DIR

ICONS_URL = '/' + ICONS_DIR
UNSUPPORTED_BADGE = 'unsupported_badge'
CPU_ICON = 'board'

CHIP_SATURATION = 55
CHIP_LIGHTNESS = 30
CHIP_ALPHA = 0.9

SUPPORT_CLAUSES = {
    'bootable_full': (('ROM is bootable', 'good'), ('Full hardware coverage', 'good')),
    'bootable_partial': (('ROM is bootable', 'good'), ('Only shared hardware support', 'caution')),
    'unknown_partial': (('No ROM ever tested', 'caution'), ('Only shared hardware support', 'caution')),
    'no_support': (('Unbootable', 'bad'), ('No hardware support', 'bad')),
}
SEARCH_HINT = 'Search'
LEVEL_TOGGLES = (('no_support', 'Unsupported'), ('unknown_partial', 'Unknown'))


def _chip_color(text):
    value = 0
    units = text.encode('utf-16-le')
    for i in range(0, len(units), 2):
        value = (value * 31 + int.from_bytes(units[i:i + 2], 'little')) & 0xFFFFFFFF
    return f'hsla({value % 360}, {CHIP_SATURATION}%, {CHIP_LIGHTNESS}%, {CHIP_ALPHA})'


def _arch_chip(arch):
    return f'<span class="cerf-db-arch" style="background: {_chip_color(arch)}">{html.escape(arch)}</span>'


def _icon(icon, supported, title):
    badge = '' if supported else (f'<img class="cerf-db-badge" src="{ICONS_URL}/{UNSUPPORTED_BADGE}.svg" '
                                  'alt=""/>')
    state = '' if supported else ' cerf-db-off'
    return (f'<span class="cerf-db-icon{state}" title="{html.escape(title)}">'
            f'<img src="{ICONS_URL}/{html.escape(icon)}.svg" alt="{html.escape(title)}"/>{badge}</span>')


def _row(icon, supported, title, content):
    return f'<li>{_icon(icon, supported, title)}<span class="cerf-db-row-text">{content}</span></li>'


def _value_name(param_id, value_id):
    return next(v['name'] for v in BOARD_CONFIG_PARAMS[param_id]['enum_values'] if v['id'] == value_id)


def _linked_settings(board, part_id):
    return [(param_id, setting) for param_id, setting in board.get('board_config', {}).items()
            if BOARD_CONFIG_PARAMS[param_id].get('generic_part_id') == part_id]


def _setting_text(param_id, setting):
    return _value_name(param_id, setting['default'])


def _setting_supported(setting):
    return setting['default'] in setting.get('values', [])


def _size_text(spec):
    if 'display_width' not in spec:
        return ''
    return f'{spec["display_width"]}x{spec["display_height"]}'


def _entry(segments, size, supported):
    text = ' - '.join(s for s in segments if s)
    if size:
        text = f'{text} ({size})' if text else size
    return supported, text


def _part_entries(board, part_id):
    specs = [s for s in board['device_specs'] if s['generic_part_id'] == part_id]
    settings = _linked_settings(board, part_id)
    if not specs:
        if not settings:
            return []
        return [_entry([_setting_text(p, s) for p, s in settings], '',
                       all(_setting_supported(s) for _p, s in settings))]
    entries = []
    for index, spec in enumerate(specs):
        attached = settings if index == 0 else []
        segments = [spec.get('displayed_name', '')] + [_setting_text(p, s) for p, s in attached]
        supported = spec['supported'] and all(_setting_supported(s) for _p, s in attached)
        entries.append(_entry(segments, _size_text(spec), supported))
    return entries


def _cpu_row(board):
    soc = soc_of(board['id'])
    arch = soc_family_of(board['id'])['arch']
    return _row(CPU_ICON, True, soc['name'], f'{html.escape(soc["name"])} {_arch_chip(arch)}')


def _part_rows(board):
    working, missing = [], []
    for part in GENERIC_PARTS:
        for supported, text in _part_entries(board, part['id']):
            row = _row(part['icon'], supported, part['name'], html.escape(text or part['name']))
            (working if supported else missing).append(row)
    return working + missing


def _support(board):
    items = ''.join(f'<span class="cerf-db-clause"><span class="cerf-db-dot cerf-db-{tone}"></span>'
                    f'{html.escape(text)}</span>' for text, tone in SUPPORT_CLAUSES[board['support_level']])
    return f'<div class="cerf-db-support">{items}</div>'


def _search_fields(board, family):
    soc = soc_of(board['id'])
    fields = [board['name'], board['id'], family, f'{soc["name"]} ({soc_family_of(board["id"])["name"]})']
    fields += [text for text, _tone in SUPPORT_CLAUSES[board['support_level']]]
    return json.dumps(fields, ensure_ascii=False)


def _filters():
    toggles = ''.join(f'<label class="cerf-db-toggle"><input type="checkbox" data-support="{level}"/>'
                      f'{html.escape(label)}</label>' for level, label in LEVEL_TOGGLES)
    return (f'<div class="cerf-db-filters" hidden><input type="search" class="cerf-db-search" '
            f'placeholder="{SEARCH_HINT}" aria-label="{SEARCH_HINT}"/>{toggles}</div>')


def _card(board):
    year = board.get('device_year')
    year_html = f'<span class="cerf-db-year">{year}</span>' if year else ''
    rows = ''.join([_cpu_row(board)] + _part_rows(board))
    family = BOARD_FAMILIES_BY_ID[board['board_family_id']]['name']
    return (f'<article class="cerf-db-card" data-support="{board["support_level"]}" '
            f'data-search="{html.escape(_search_fields(board, family))}" '
            f'style="--cerf-db-tint: {_chip_color(family)}">'
            f'<div class="cerf-db-head"><div class="cerf-db-title">'
            f'<span class="cerf-db-name">{html.escape(board["name"])}</span>'
            f'<span class="cerf-db-family">{html.escape(family)}</span></div>'
            f'{year_html}</div>'
            f'{_support(board)}'
            f'<ul class="cerf-db-rows">{rows}</ul>'
            '</article>')


def build_device_database():
    families = {}
    for board in BOARDS:
        families.setdefault(board['board_family_id'], []).append(board)
    cards = []
    for family_id in sorted(families, key=lambda f: sort_text(BOARD_FAMILIES_BY_ID[f]['name'])):
        for board in sorted(families[family_id], key=lambda b: board_sort_key(b['name'])):
            cards.append(_card(board))
    return f'{_filters()}\n\n<div class="cerf-db-grid">{"".join(cards)}</div>'
