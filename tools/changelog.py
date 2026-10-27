import html
import os
import re

import yaml

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CHANGELOG_YML = os.path.join(REPO, 'docs', 'changelog.yml')

_BOLD = re.compile(r'\*\*(.+?)\*\*')

GROUPS = [
    ('devices',         'Devices',         '📱'),
    ('emulator',        'Emulator',        '💿'),
    ('launcher',        'Launcher',        '🚀'),
    ('cerfman',         'Devices Manager', '🗂️'),
    ('ce_apps',         'CE Apps',         '💾'),
    ('guest_additions', 'Guest Additions', '✨'),
    ('website',         'Website',         '🌐'),
]

SUBCATS = [
    ('new',     '🆕'),
    ('fixed',   '✅'),
    ('deleted', '❌'),
]

LEGACY = ('changes', 'Changes', '📝')


def _lines(block):
    return [line.strip() for line in (block or '').splitlines() if line.strip()]


def load():
    with open(CHANGELOG_YML, 'r', encoding='utf-8') as f:
        data = yaml.safe_load(f) or []
    entries = []
    for item in data:
        groups = []
        for key, heading, emoji in GROUPS:
            sub = item.get(key)
            if not sub:
                continue
            subcats = []
            for sub_key, sub_emoji in SUBCATS:
                lines = _lines(sub.get(sub_key))
                if lines:
                    subcats.append({'key': sub_key, 'emoji': sub_emoji,
                                    'lines': lines})
            if subcats:
                groups.append({'heading': heading, 'emoji': emoji,
                               'subcats': subcats})
        legacy = _lines(item.get(LEGACY[0]))
        if legacy:
            groups.append({'heading': LEGACY[1], 'emoji': LEGACY[2],
                           'subcats': [{'key': None, 'emoji': None,
                                        'lines': legacy}]})
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
