import argparse
import glob
import os
import shutil
import subprocess
import sys

from changelog import CHANGELOG_YML
from product_facts import ASSET_ICONS_DIR, LOGO_ASSET
from svg_raster import intrinsic_size, render_svg

ROOT      = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SITE      = os.path.join(ROOT, 'docs', 'website')
CONTENT   = os.path.join(SITE, 'content')
ICONS_SVG = os.path.join(ROOT, 'assets', ASSET_ICONS_DIR)
ICONS_DIR = 'assets/icons'
IMG_DIR   = 'assets/img'
LOGO_ICO  = os.path.join(ROOT, 'assets', LOGO_ASSET + '.ico')
LOGO_SVG  = os.path.join(ICONS_SVG, LOGO_ASSET + '.svg')
LIGHT_SVG = os.path.join(ICONS_SVG, 'cerf-light.svg')
BAND_SVG  = os.path.join(ROOT, 'docs', 'github_band.svg')
BAND_ZOOM = 2
COPIES    = {
    'main':      ('mkdocs.yml', os.path.join(ROOT, 'build', 'site')),
    'playstore': ('mkdocs.googleplay.yml', os.path.join(ROOT, 'build', 'site-googleplay')),
}

IMAGES = [LOGO_ICO, LOGO_SVG, LIGHT_SVG]


def served_path(source):
    return IMG_DIR + '/' + os.path.basename(source)


BAND_PNG = served_path(os.path.splitext(BAND_SVG)[0] + '.png')


def sync_assets():
    icons = os.path.join(CONTENT, ICONS_DIR)
    if os.path.isdir(icons):
        shutil.rmtree(icons)
    os.makedirs(icons)
    for svg in glob.glob(os.path.join(ICONS_SVG, '*.svg')):
        shutil.copy2(svg, os.path.join(icons, os.path.basename(svg)))

    os.makedirs(os.path.join(CONTENT, IMG_DIR), exist_ok=True)
    for src in IMAGES:
        with open(src, 'rb') as f:
            data = f.read()
        with open(os.path.join(CONTENT, served_path(src)), 'wb') as f:
            f.write(data)

    with open(BAND_SVG, 'r', encoding='utf-8') as f:
        width, height = intrinsic_size(f.read())
    band = render_svg(BAND_SVG, width * BAND_ZOOM, height * BAND_ZOOM, 'RGBA')
    band.save(os.path.join(CONTENT, BAND_PNG), optimize=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--serve', nargs='?', const='main', choices=sorted(COPIES),
                        help='serve one copy locally with live reload instead of building (default: main)')
    parser.add_argument('--port', type=int, default=None,
                        help='port for --serve (default: mkdocs\' own 8000)')
    args = parser.parse_args()
    if args.port is not None and not args.serve:
        parser.error('--port applies to --serve')

    sync_assets()

    if args.serve:
        config = os.path.join(SITE, COPIES[args.serve][0])
        cmd = [sys.executable, '-m', 'mkdocs', 'serve',
               '--livereload',
               '-f', config,
               '-w', SITE,
               '-w', os.path.join(ROOT, 'libCerfCore', 'db'),
               '-w', CHANGELOG_YML,
               '-w', os.path.join(ROOT, 'cerf-qt', 'play_store_links_text.h')]
        if args.port is not None:
            cmd += ['-a', f'127.0.0.1:{args.port}']
        subprocess.check_call(cmd)
        return

    for config_name, out in COPIES.values():
        subprocess.check_call([sys.executable, '-m', 'mkdocs', 'build', '--strict',
                               '-f', os.path.join(SITE, config_name), '-d', out])
        print(f'site built into {out}')


if __name__ == '__main__':
    main()
