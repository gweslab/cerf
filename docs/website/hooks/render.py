import datetime
import html
import os
import re
import sys

import yaml

HERE      = os.path.dirname(os.path.abspath(__file__))
SITE      = os.path.dirname(HERE)
ROOT      = os.path.dirname(os.path.dirname(SITE))
DEV_YML   = os.path.join(SITE, 'devices.yml')
DEV_DIR   = os.path.join(SITE, 'content', 'assets', 'devices')
FEAT_YML  = os.path.join(SITE, 'features.yml')
FEAT_DIR  = os.path.join(SITE, 'content', 'assets', 'features')
ART_YML   = os.path.join(SITE, 'articles.yml')
ART_DIR   = os.path.join(SITE, 'content', 'assets', 'articles')
FUNDING   = os.path.join(ROOT, '.github', 'FUNDING.yml')

FUNDING_LINKS = [
    ('patreon',         'Patreon',         ':fontawesome-brands-patreon:',
     'https://www.patreon.com/{user}'),
]

SITE_LINKS = [
    # ('GitHub',  ':fontawesome-brands-github:',  'https://github.com/gweslab/cerf'),
    ('Discord', ':fontawesome-brands-discord:', 'https://discord.gg/QREE9Y2v2d'),
]

sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, 'tools'))
import changelog
import compile_readme
from board_database import running_boards, soc_family_of


def _boards_table():
    table = compile_readme.build_supported_devices()
    return table.replace(compile_readme.SVG_DIR, '/assets/icons')


def _changelog_table():
    lines = ['<table>', '  <thead>', '    <tr>', '      <th>Version</th>',
             '      <th>Release date</th>', '      <th>Changes</th>',
             '    </tr>', '  </thead>', '  <tbody>',
             changelog.render_rows(changelog.load()),
             '  </tbody>', '</table>']
    return '\n'.join(lines)


def _stats():
    boards    = running_boards()
    platforms = {b['board_family_id'] for b in boards}
    socs      = {b['soc_id'] for b in boards}
    cpus      = sorted({soc_family_of(b['id'])['arch'] for b in boards})

    cells = [
        (str(len(platforms)), 'devices'),
        (str(len(boards)), 'board variants'),
        (str(len(socs)),      'SoCs'),
        (' + '.join(cpus), 'guest CPUs'),
    ]
    out = ['<div class="cerf-stats">']
    for value, label in cells:
        out.append('  <div class="cerf-stat">'
                   f'<span class="cerf-stat-value">{html.escape(value)}</span>'
                   f'<span class="cerf-stat-label">{html.escape(label)}</span>'
                   '</div>')
    out.append('</div>')
    return '\n'.join(out)


def _slides(entry, assets_dir, assets_url, single_key):
    folder = entry.get('dir')
    if folder:
        path = os.path.join(assets_dir, folder)
        if not os.path.isdir(path):
            return []
        names = sorted(n for n in os.listdir(path)
                       if n.lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.webp')))
        return [f'{assets_url}/{folder}/{n}' for n in names]

    names = entry.get(single_key)
    if isinstance(names, str):
        names = [names]
    return [f'{assets_url}/{n}' for n in names or []
            if os.path.isfile(os.path.join(assets_dir, n))]


def _slide_attrs(slides, index):
    rest = ' '.join(slides[1:])
    if not rest:
        return ''
    return f' data-cerf-slides="{rest}" data-cerf-offset="{index * 1300}"'


def _devices():
    with open(DEV_YML, 'r', encoding='utf-8') as f:
        devices = yaml.safe_load(f).get('devices') or []

    out = ['<div class="cerf-rail">',
           '<div class="cerf-rail-track" tabindex="0" role="region" aria-label="Devices">']
    for index, device in enumerate(devices):
        slides = _slides(device, DEV_DIR, '/assets/devices', 'file')
        if not slides:
            continue

        alt   = html.escape(device['device'])
        klass = 'cerf-device cerf-device--wide' if device.get('wide') else 'cerf-device'
        attrs = _slide_attrs(slides, index)

        out.append(f'  <figure class="{klass}">')
        out.append(f'    <img src="{slides[0]}" loading="lazy" draggable="false" '
                   f'alt="{alt}"{attrs} />')
        out.append('    <figcaption>'
                   f'<b>{alt}</b>'
                   f'<span>{html.escape(device["os"])}</span>'
                   '</figcaption>')
        out.append('  </figure>')

    boards = len(running_boards())
    out.append(f'  <a class="cerf-rail-all" href="{_card_url("devices.md")}">'
               '<span class="cerf-rail-all-mark">&rarr;</span>'
               '<b>All</b>'
               f'<span>{boards} boards</span>'
               '</a>')
    out.append('</div>')
    out.append('</div>')
    return '\n'.join(out)


def _card_url(link):
    """Manifest links are page paths; the cards are raw HTML, which MkDocs does
    not rewrite the way it rewrites markdown links."""
    if not link or '://' in link:
        return link

    path, _, anchor = link.partition('#')
    if path.endswith('.md'):
        path = path[:-len('.md')]
        if path.endswith('/index'):
            path = path[:-len('index')]
        elif path == 'index':
            path = ''
    if path and not path.endswith('/'):
        path += '/'
    url = '/' + path.lstrip('/')
    return url + '#' + anchor if anchor else url


def _cards(manifest, key, assets_dir, assets_url):
    with open(manifest, 'r', encoding='utf-8') as f:
        cards = yaml.safe_load(f).get(key) or []

    out = ['<div class="cerf-wall" markdown>\n']
    for index, card in enumerate(cards):
        slides = _slides(card, assets_dir, assets_url, 'image')

        out.append(f'<a class="cerf-card" href="{_card_url(card.get("link", ""))}">')
        if slides:
            out.append(f'  <img src="{slides[0]}" loading="lazy" '
                       f'alt="{html.escape(card["title"])}"'
                       f'{_slide_attrs(slides, index)} />')
        out.append('  <span class="cerf-card-body">'
                   f'<b>{html.escape(card["title"])}</b>'
                   f'<span>{html.escape(card["text"])}</span>'
                   '</span>')
        out.append('</a>\n')
    out.append('</div>')
    return '\n'.join(out)


def _links():
    with open(FUNDING, 'r', encoding='utf-8') as f:
        users = yaml.safe_load(f) or {}

    pills = [f'[{icon} {label}]({url.format(user=users[key])})'
              '{ .cerf-pill }'
              for key, label, icon, url in FUNDING_LINKS if users.get(key)]
    pills += [f'[{icon} {label}]({url}){{ .cerf-pill }}'
             for label, icon, url in SITE_LINKS]

    return ('<div class="cerf-links" markdown>\n\n'
            + '\n'.join(pills)
            + '\n\n</div>')


HERO_PERMALINK = re.compile(
    r'(<h1[^>]*>.*?)<a class="headerlink"[^>]*>.*?</a>(</h1>)', re.S)


def on_config(config):
    if config.copyright and '{cur_year}' in config.copyright:
        config.copyright = config.copyright.replace(
            '{cur_year}', str(datetime.date.today().year))
    return config


def on_page_content(content, page, config, files):
    if page.is_homepage:
        content = HERO_PERMALINK.sub(r'\1\2', content, count=1)
    return content


def on_page_markdown(markdown, page, config, files):
    if '{version}' in markdown:
        markdown = markdown.replace('{version}', compile_readme.parse_version())
    if '{boards_table}' in markdown:
        markdown = markdown.replace('{boards_table}', _boards_table())
    if '{changelog_table}' in markdown:
        markdown = markdown.replace('{changelog_table}', _changelog_table())
    if '{stats}' in markdown:
        markdown = markdown.replace('{stats}', _stats())
    if '{devices}' in markdown:
        markdown = markdown.replace('{devices}', _devices())
    if '{features}' in markdown:
        markdown = markdown.replace(
            '{features}', _cards(FEAT_YML, 'features', FEAT_DIR, '/assets/features'))
    if '{articles}' in markdown:
        markdown = markdown.replace(
            '{articles}', _cards(ART_YML, 'articles', ART_DIR, '/assets/articles'))
    if '{links}' in markdown:
        markdown = markdown.replace('{links}', _links())
    return markdown
