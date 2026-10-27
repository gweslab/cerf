import os
import sys
import datetime

ROOT = os.path.dirname(os.path.abspath(__file__))
VERSION_H = os.path.join(ROOT, 'cerf-qt', 'version.h')
SOURCE    = os.path.join(ROOT, 'README_SOURCE.md')
OUTPUT    = os.path.join(ROOT, 'README.md')
CHANGELOG_LINK = 'https://cerf.cx/changelog/'
CHANGELOG_RECENT = 2
FUNDING = os.path.join(ROOT, '.github', 'FUNDING.yml')

# FUNDING.yml platform key -> shields.io badge (label, hex, logo, logo color)
# + the profile URL its username slots into. The label is shields' static-badge
# path, where a lone '-' separates label from message: a literal dash in a label
# is escaped as '--', and a space as '%20'.
FUNDING_BADGES = [
    ('patreon',         'Patreon',
     'FF424D', 'patreon',      'white', 'https://www.patreon.com/{user}'),
]
FUNDING_MESSAGE = 'support'

sys.path.insert(0, os.path.join(ROOT, 'tools'))
from header_defines import int_define
from board_database import (FEATURE_SPECS, SUPPORT_BOOTABLE_PARTIAL, board_sort_key,
                            family_of, running_boards, soc_family_of, soc_of, sort_text)
from product_facts import ASSET_ICONS_DIR, BADGE_PREFIX
import android_sdk
import apt_packages
import homebrew_packages

SVG_DIR = f'assets/{ASSET_ICONS_DIR}'

UNMODELED_MARK = '*'
UNMODELED_LEGEND = (f'``{UNMODELED_MARK}`` Supported, but CERF does not model this '
                    'board\'s differences.')

import changelog


def parse_version():
    major = int_define(VERSION_H, 'CERF_VERSION_MAJOR')
    minor = int_define(VERSION_H, 'CERF_VERSION_MINOR')
    patch = int_define(VERSION_H, 'CERF_VERSION_PATCH')
    return f'{major}.{minor}' if patch == 0 else f'{major}.{minor}.{patch}'


def icon_img(stem, title, size=32):
    return (f'<img src="{SVG_DIR}/{stem}.svg" width="{size}" height="{size}" '
            f'title="{title}" alt="{title}"/>')


def badge_img(cpu):
    return (f'<img src="{SVG_DIR}/{BADGE_PREFIX}{cpu.lower()}.svg" '
            f'align="middle" title="{cpu}" alt="{cpu}"/>')


def features_cell(board):
    working = {f['feature_id'] for f in board.get('device_features', [])
               if f.get('supported')}
    icons = [icon_img(stem, label)
             for key, stem, label in FEATURE_SPECS if key in working]
    return ' '.join(icons) if icons else '&mdash;'


def _rowspan(count):
    return f' rowspan="{count}"' if count > 1 else ''


def _by_name(groups):
    return sorted(groups.values(), key=lambda group: sort_text(group[0]['name']))


def _grouped_boards():
    arches = {}
    for board in running_boards():
        soc = soc_of(board['id'])
        family = family_of(board['id'])
        socs = arches.setdefault(soc_family_of(board['id'])['arch'], {})
        families = socs.setdefault(soc['id'], (soc, {}))[1]
        families.setdefault(family['id'], (family, []))[1].append(board)
    return [(arch, [(soc, [(family, sorted(boards,
                                          key=lambda b: board_sort_key(b['name'])))
                           for family, boards in _by_name(families)])
                    for soc, families in _by_name(arches[arch])])
            for arch in sorted(arches)]


def _board_cell(board):
    mark = (f' <code>{UNMODELED_MARK}</code>'
            if board.get('support_level') == SUPPORT_BOOTABLE_PARTIAL else '')
    return (f'{icon_img("board", "PDA", 16)} <b>{board["name"]}</b>{mark} '
            f'<code>{board["id"]}</code>')


def build_supported_devices():
    lines = [
        '<table>',
        '  <thead>',
        '    <tr>',
        '      <th>SoC</th>',
        '      <th>Family</th>',
        '      <th>Board</th>',
        '      <th>Features</th>',
        '    </tr>',
        '  </thead>',
        '  <tbody>',
    ]
    unmodeled = False
    for arch, socs in _grouped_boards():
        for soc, families in socs:
            soc_rows = sum(len(boards) for _family, boards in families)
            first_in_soc = True
            for family, boards in families:
                for index, board in enumerate(boards):
                    lines.append('    <tr>')
                    if first_in_soc:
                        soc_family = soc_family_of(board['id'])
                        lines.append(f'      <td{_rowspan(soc_rows)} align="center">'
                                     f'{badge_img(arch)}'
                                     f'<br/><b>{soc["name"]}</b>'
                                     f'<br/><sub>{soc_family["name"]}</sub></td>')
                        first_in_soc = False
                    if index == 0:
                        lines.append(f'      <td{_rowspan(len(boards))}>'
                                     f'<b>{family["name"]}</b></td>')
                    lines.append(f'      <td>{_board_cell(board)}</td>')
                    lines.append(f'      <td>{features_cell(board)}</td>')
                    lines.append('    </tr>')
                    unmodeled |= board.get('support_level') == SUPPORT_BOOTABLE_PARTIAL
    lines.append('  </tbody>')
    lines.append('</table>')
    if unmodeled:
        lines.append('')
        lines.append(UNMODELED_LEGEND)
    return '\n'.join(lines)


def build_support_badges():
    usernames = {}
    with open(FUNDING, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.split('#', 1)[0].strip()
            if ':' not in line:
                continue
            key, value = line.split(':', 1)
            usernames[key.strip()] = value.strip().strip('\'"')

    badges = []
    for key, label, color, logo, logo_color, url in FUNDING_BADGES:
        user = usernames.get(key)
        if not user:
            continue
        alt = label.replace('--', '-').replace('%20', ' ')
        badges.append(
            f'<a href="{url.format(user=user)}">'
            f'<img src="https://img.shields.io/badge/{label}-{FUNDING_MESSAGE}-{color}'
            f'?logo={logo}&amp;logoColor={logo_color}" alt="{alt}"/></a>')
    return ' '.join(badges)


def build_changelog():
    entries = changelog.load()
    recent = entries[:CHANGELOG_RECENT]

    lines = [
        '<table>',
        '  <thead>',
        '    <tr>',
        '      <th>Version</th>',
        '      <th>Release Date</th>',
        '      <th>Changes</th>',
        '    </tr>',
        '  </thead>',
        '  <tbody>',
        changelog.render_rows(recent),
    ]
    if len(entries) > CHANGELOG_RECENT:
        lines.append('    <tr>')
        lines.append('      <td colspan="3"><b>Previous versions</b> - '
                     f'see the <a href="{CHANGELOG_LINK}">full changelog</a>.</td>')
        lines.append('    </tr>')
    lines.append('  </tbody>')
    lines.append('</table>')
    return '\n'.join(lines)


def code_list(items):
    quoted = [f'`{item}`' for item in items]
    return ', '.join(quoted[:-1]) + ' and ' + quoted[-1]


def main():
    with open(SOURCE, 'r', encoding='utf-8') as f:
        content = f.read()

    version = parse_version()
    content = content.replace('{version}', version)
    content = content.replace('{changelog}', build_changelog())
    content = content.replace('{supported_devices}', build_supported_devices())
    content = content.replace('{support_badges}', build_support_badges())
    content = content.replace('{cur_year}', str(datetime.date.today().year))
    content = content.replace('{apt_install}', apt_packages.install_command())
    content = content.replace('{brew_install}', homebrew_packages.install_command())
    content = content.replace('{android_sdk_packages}', code_list(android_sdk.packages()))

    with open(OUTPUT, 'w', encoding='utf-8', newline='\n') as f:
        f.write(content)

    print(f'README.md compiled (v{version})')


if __name__ == '__main__':
    main()
