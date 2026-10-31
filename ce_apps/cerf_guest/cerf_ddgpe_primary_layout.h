#pragma once

#include <windows.h>

#include "cerfcore/peripherals/cerf_virt/cerf_virt_rotation.h"

typedef cerfcore::CerfVirt::CerfRotatedLayout CerfPrimaryLayout;

void CerfPrimaryLayoutInit(void);
void CerfPrimaryLayoutFor(int angle, int screen_w, int screen_h, int stride, int bytes_px,
                          CerfPrimaryLayout* out);
BOOL CerfPrimaryLayoutBind(void* lcl, const CerfPrimaryLayout* lay);
void CerfPrimaryLayoutOf(void* lcl, CerfPrimaryLayout* out);
void CerfPrimaryLayoutForget(void* lcl);
BOOL CerfPrimaryLayoutAnyBound(void);
