import re
import os

ROOT = os.path.dirname(os.path.abspath(__file__))
VERSION_H = os.path.join(ROOT, 'cerf', 'version.h')
SOURCE    = os.path.join(ROOT, 'README_SOURCE.md')
OUTPUT    = os.path.join(ROOT, 'README.md')

ICONS = {
    'i_display':   '<img src="docs/icons/display.png" width="16" height="16" title="Graphics" alt="Graphics"/>',
    'i_speaker':   '<img src="docs/icons/speaker.png" width="16" height="16" title="Sound" alt="Sound"/>',
    'i_stylus':    '<img src="docs/icons/stylus.png" width="16" height="16" title="Touch" alt="Touch"/>',
    'i_keyboard':  '<img src="docs/icons/keyboard.png" width="16" height="16" title="Keyboard" alt="Keyboard"/>',
    'i_internet':  '<img src="docs/icons/internet.png" width="16" height="16" title="Network Emulation" alt="Network Emulation"/>',
    'i_pda':       '<img src="docs/icons/pda.png" width="16" height="16" title="PDA" alt="PDA"/>',
    'i_chip':      '<img src="docs/icons/chip.png" width="16" height="16" title="Chip" alt="Chip"/>',
    'i_os_ce':     '<img src="docs/icons/os_ce.png" width="16" height="16" title="Windows CE" alt="Windows CE"/>',
    'i_os_old_ce': '<img src="docs/icons/os_old_ce.png" width="16" height="16" title="Windows CE (Classic)" alt="Windows CE (Classic)"/>',
    'i_os_ppc2000':'<img src="docs/icons/os_ppc2000.png" width="16" height="16" title="Pocket PC 2000" alt="Pocket PC 2000"/>',
    'i_os_ppc2002':'<img src="docs/icons/os_ppc2002.png" width="16" height="16" title="PPC2002+ Icon" alt="PPC2002+ Icon"/>',
    'i_os_wm6':    '<img src="docs/icons/os_wm6.png" width="16" height="16" title="Windows Mobile 6+" alt="Windows Mobile 6+"/>',
    'i_os_zune':   '<img src="docs/icons/os_zune.png" width="16" height="16" title="Zune OS" alt="Zune OS"/>',
    'i_os_zune_hd':'<img src="docs/icons/os_zune_hd.png" width="16" height="16" title="Zune HD OS" alt="Zune HD OS"/>',
}


def parse_version():
    with open(VERSION_H, 'r') as f:
        text = f.read()
    major = int(re.search(r'#define CERF_VERSION_MAJOR\s+(\d+)', text).group(1))
    minor = int(re.search(r'#define CERF_VERSION_MINOR\s+(\d+)', text).group(1))
    patch = int(re.search(r'#define CERF_VERSION_PATCH\s+(\d+)', text).group(1))
    return f'{major}.{minor}' if patch == 0 else f'{major}.{minor}.{patch}'


def main():
    with open(SOURCE, 'r', encoding='utf-8') as f:
        content = f.read()

    version = parse_version()
    content = content.replace('{version}', version)
    for key, value in ICONS.items():
        content = content.replace('{' + key + '}', value)

    with open(OUTPUT, 'w', encoding='utf-8') as f:
        f.write(content)

    print(f'README.md compiled (v{version})')


if __name__ == '__main__':
    main()
