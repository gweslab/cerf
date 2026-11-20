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

FUNDING_BADGES = [
    ('patreon',         'Patreon',
     'FF424D', 'patreon',      'white', 'https://www.patreon.com/{user}'),
]
FUNDING_MESSAGE = 'support'

sys.path.insert(0, os.path.join(ROOT, 'tools'))
from header_defines import int_define
import android_sdk
import apt_packages
import homebrew_packages

import changelog


def parse_version():
    major = int_define(VERSION_H, 'CERF_VERSION_MAJOR')
    minor = int_define(VERSION_H, 'CERF_VERSION_MINOR')
    patch = int_define(VERSION_H, 'CERF_VERSION_PATCH')
    return f'{major}.{minor}' if patch == 0 else f'{major}.{minor}.{patch}'


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
