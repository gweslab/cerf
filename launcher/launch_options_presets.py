"""Static data tables for the launch-options resolution / DPI overrides: the
preset resolution stops the slider snaps through and the override slider bounds.
Kept out of launch_options.py so that panel file holds only behaviour."""
from __future__ import annotations


# Common display resolutions the override slider snaps through, ordered by
# pixel area (ascending) so the thumb moves monotonically small -> large,
# spanning PDA sizes up to 4K UHD. Both orientations of the everyday small
# sizes are included; the boxes stay free-form so any value off this list
# is still typable.
RES_PRESETS = [
    (240, 320),  (320, 240),    #  QVGA
    (320, 480),  (480, 320),    #  HVGA
    (640, 480),  (480, 640),    #  VGA
    (800, 480),  (480, 800),    #  WVGA
    (854, 480),                 #  FWVGA
    (800, 600),  (600, 800),    #  SVGA
    (1024, 600),                #  WSVGA
    (1024, 768), (768, 1024),   #  XGA
    (1280, 720),                #  HD 720p
    (1280, 800),                #  WXGA
    (1366, 768),                #  HD
    (1280, 1024),               #  SXGA
    (1440, 900),                #  WXGA+
    (1600, 900),                #  HD+
    (1680, 1050),               #  WSXGA+
    (1600, 1200),               #  UXGA
    (1920, 1080),               #  FHD 1080p
    (1920, 1200),               #  WUXGA
    (2560, 1440),               #  QHD 1440p
    (2560, 1600),               #  WQXGA
    (3440, 1440),               #  UW-QHD
    (3840, 2160),               #  4K UHD
]

# DPI override slider bounds. The entry stays free-form so any value (including
# extreme ones) is typable past the slider's range.
DPI_SLIDER_MIN = 48
DPI_SLIDER_MAX = 480

FONT_SIZE_SLIDER_MIN = 6
FONT_SIZE_SLIDER_MAX = 48

DEFAULT_SCREEN_WIDTH = 800
DEFAULT_SCREEN_HEIGHT = 600
