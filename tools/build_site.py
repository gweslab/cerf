import argparse
import glob
import os
import shutil
import subprocess
import sys

from product_facts import ASSET_ICONS_DIR, LOGO_ASSET

ROOT      = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SITE      = os.path.join(ROOT, 'docs', 'website')
CONTENT   = os.path.join(SITE, 'content')
ICONS_SVG = os.path.join(ROOT, 'assets', ASSET_ICONS_DIR)
COPIES    = {
    'main':      ('mkdocs.yml', os.path.join(ROOT, 'build', 'site')),
    'playstore': ('mkdocs.googleplay.yml', os.path.join(ROOT, 'build', 'site-googleplay')),
}

IMAGES = [
    (os.path.join('assets', LOGO_ASSET + '.ico'), LOGO_ASSET + '.ico'),
    (os.path.join('assets', ASSET_ICONS_DIR, LOGO_ASSET + '.svg'), LOGO_ASSET + '.svg'),
    (os.path.join('assets', ASSET_ICONS_DIR, 'cerf-light.svg'), 'cerf-light.svg'),
]


def sync_assets():
    icons = os.path.join(CONTENT, 'assets', 'icons')
    if os.path.isdir(icons):
        shutil.rmtree(icons)
    os.makedirs(icons)
    for svg in glob.glob(os.path.join(ICONS_SVG, '*.svg')):
        shutil.copy2(svg, os.path.join(icons, os.path.basename(svg)))

    img = os.path.join(CONTENT, 'assets', 'img')
    os.makedirs(img, exist_ok=True)
    for src, name in IMAGES:
        # Byte copy, not shutil.copyfile: a shared-folder filesystem can report
        # identical inodes for distinct files, which trips its same-file check.
        with open(os.path.join(ROOT, src), 'rb') as f:
            data = f.read()
        with open(os.path.join(img, name), 'wb') as f:
            f.write(data)


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
               '-w', os.path.join(ROOT, 'libCerfCore', 'db.json'),
               '-w', os.path.join(ROOT, 'docs', 'changelog.yml'),
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
