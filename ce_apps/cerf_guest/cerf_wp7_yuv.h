#pragma once

#include <windows.h>
#include "include/ddraw_wp7.h"

typedef struct {
    DWORD code;
    DWORD size;
    DWORD stride;
    DWORD xpitch;
    DWORD cb_offset;
    DWORD cr_offset;
    DWORD cb_stride;
    DWORD cr_stride;
    DWORD chroma_xpitch;
} CerfWp7Layout;

const Wp7_FOURCC_FORMAT* CerfWp7FourCcFormats(DWORD* count);
BOOL  CerfWp7YuvLayout(DWORD fourcc, DWORD width, DWORD height, CerfWp7Layout* out);
void  CerfWp7DescribeLayout(Wp7_DDSURFACEDESC* d, const CerfWp7Layout* l);
ULONG CerfWp7OverlayFormat(DWORD code);
ULONG CerfWp7DescClass(DWORD code);
void  CerfWp7PadTiled(BYTE* luma, DWORD chroma_offset, DWORD width, DWORD height);
