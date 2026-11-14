import html
import os
import re

import yaml

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CHANGELOG_YML = os.path.join(REPO, 'docs', 'changelog.yml')

_BOLD = re.compile(r'\*\*(.+?)\*\*')

PLAIN = 'plain'
CATEGORIZED = 'categorized'

GROUPS = [
    ('important',       'Important',       '❗', PLAIN),
    ('devices',         'Devices',         '📱', CATEGORIZED),
    ('emulator',        'Emulator',        '💿', CATEGORIZED),
    ('launcher',        'Launcher',        '🚀', CATEGORIZED),
    ('cerfman',         'Devices Manager', '🗂️', CATEGORIZED),
    ('ce_apps',         'CE Apps',         '💾', CATEGORIZED),
    ('guest_additions', 'Guest Additions', '✨', CATEGORIZED),
    ('website',         'Website',         '🌐', CATEGORIZED),
    ('patches',         'Patches',         '🚑', CATEGORIZED),
    ('changes',         'Changes',         '📝', PLAIN),
]

SUBCATS = [
    ('new',     '🆕'),
    ('fixed',   '✅'),
    ('deleted', '❌'),
]


def _lines(block):
    return [line.strip() for line in (block or '').splitlines() if line.strip()]


def _subcats(block, kind):
    if kind == PLAIN:
        lines = _lines(block)
        return [{'key': None, 'emoji': None, 'lines': lines}] if lines else []
    subcats = []
    for sub_key, sub_emoji in SUBCATS:
        lines = _lines((block or {}).get(sub_key))
        if lines:
            subcats.append({'key': sub_key, 'emoji': sub_emoji, 'lines': lines})
    return subcats


def load():
    with open(CHANGELOG_YML, 'r', encoding='utf-8') as f:
        data = yaml.safe_load(f) or []
    entries = []
    for item in data:
        groups = []
        for key, heading, emoji, kind in GROUPS:
            subcats = _subcats(item.get(key), kind)
            if subcats:
                groups.append({'heading': heading, 'emoji': emoji,
                               'subcats': subcats})
        entries.append({'version': str(item['version']),
                        'date': str(item.get('date', '')),
                        'groups': groups})
    return entries


def _bullet_html(text):
    return _BOLD.sub(r'<b>\1</b>', html.escape(text))


def _changes_cell(groups):
    blocks = []
    for group in groups:
        parts = [f'<b>{group["emoji"]} {html.escape(group["heading"])}</b>']
        for subcat in group['subcats']:
            prefix = f'{subcat["emoji"]} ' if subcat['emoji'] else ''
            parts += [prefix + _bullet_html(line) for line in subcat['lines']]
        blocks.append('<br/>\n          '.join(parts))
    return '\n'.join(f'        <p>{block}</p>' for block in blocks)


def render_rows(entries):
    lines = []
    for entry in entries:
        lines.append('    <tr>')
        lines.append(f'      <td>{html.escape(entry["version"])}</td>')
        lines.append(f'      <td>{html.escape(entry["date"])}</td>')
        lines.append('      <td>')
        lines.append(_changes_cell(entry['groups']))
        lines.append('      </td>')
        lines.append('    </tr>')
    return '\n'.join(lines)


MARKDOWN_HARD_BREAK = '  '


def render_markdown(groups):
    lines = []
    for group in groups:
        lines.append(f'## {group["emoji"]} {group["heading"]}')
        for subcat in group['subcats']:
            prefix = f'{subcat["emoji"]} ' if subcat['emoji'] else ''
            lines += [prefix + line + MARKDOWN_HARD_BREAK for line in subcat['lines']]
    return '\n'.join(lines)


def entry_for(tag):
    wanted = f'v{tag}'
    for entry in load():
        version = entry['version']
        if version == wanted or version.startswith(wanted + ' '):
            return entry
    return None
