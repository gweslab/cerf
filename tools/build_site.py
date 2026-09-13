"""Builds the CERF website into build/site, or serves it locally with live reload.

    python tools/build_site.py                      build into build/site
    python tools/build_site.py --serve              http://127.0.0.1:8000, reloads on edit
    python tools/build_site.py --serve --port 8123  the same, on another port

The board table, changelog and version are pulled in by docs/website/hooks/render.py
from the same sources the launcher and README.md use, so the site cannot drift from
them. This script only syncs the shared image assets - which live outside the site
tree - into the docs dir, where MkDocs can see them.
"""

import argparse
import glob
import os
import shutil
import subprocess
import sys

ROOT      = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SITE      = os.path.join(ROOT, 'docs', 'website')
CONTENT   = os.path.join(SITE, 'content')
OUT       = os.path.join(ROOT, 'build', 'site')
ICONS_SRC = os.path.join(ROOT, 'launcher', 'assets', 'icons')

ICONS_SVG = os.path.join(ROOT, 'cerf', 'assets', 'icons_sources')

IMAGES = [
    (os.path.join('docs', 'cerf_youtube.png'),           'cerf_youtube.png'),
    (os.path.join('docs', 'launcher.png'),               'launcher.png'),
    (os.path.join('cerf', 'assets', 'cerf.ico'),         'cerf.ico'),
    (os.path.join('cerf', 'assets', 'icons_sources', 'cerf.svg'), 'cerf.svg'),
    (os.path.join('cerf', 'assets', 'icons_sources', 'cerf-light.svg'), 'cerf-light.svg'),
]


def sync_assets():
    # The boards table references CPU-arch badge PNGs (launcher/assets/icons)
    # and feature/board icon SVGs (cerf/assets/icons_sources); the render hook
    # rewrites both to /assets/icons, so stage both source trees into one dir.
    icons = os.path.join(CONTENT, 'assets', 'icons')
    if os.path.isdir(icons):
        shutil.rmtree(icons)
    shutil.copytree(ICONS_SRC, icons, ignore=shutil.ignore_patterns('*.md'))
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
    parser.add_argument('--serve', action='store_true',
                        help='serve locally with live reload instead of building')
    parser.add_argument('--port', type=int, default=None,
                        help='port for --serve (default: mkdocs\' own 8000)')
    args = parser.parse_args()
    if args.port is not None and not args.serve:
        parser.error('--port applies to --serve')

    sync_assets()
    config = os.path.join(SITE, 'mkdocs.yml')

    if args.serve:
        # --livereload is passed explicitly: mkdocs 1.6.1 declares it as a hidden
        # flag paired with --no-livereload, and click 8.3 resolves that pair to
        # False by default, which silently starts the server with no file watching.
        #
        # -w: the manifests, the hook and the data the hook reads all live outside
        # content/, which is the only tree mkdocs watches on its own.
        cmd = [sys.executable, '-m', 'mkdocs', 'serve',
               '--livereload',
               '-f', config,
               '-w', SITE,
               '-w', os.path.join(ROOT, 'launcher', 'supported_devices.py'),
               '-w', os.path.join(ROOT, 'docs', 'changelog.yml')]
        if args.port is not None:
            cmd += ['-a', f'127.0.0.1:{args.port}']
        subprocess.check_call(cmd)
        return

    subprocess.check_call([sys.executable, '-m', 'mkdocs', 'build', '--strict',
                           '-f', config, '-d', OUT])
    print(f'site built into {OUT}')


if __name__ == '__main__':
    main()
