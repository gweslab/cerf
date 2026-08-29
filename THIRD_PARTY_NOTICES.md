# Third-Party Notices

CE Runtime Foundation is released under the MIT License (`LICENSE`). It links the
components below, each under its own license and copyright. Full license texts that
are too long to inline are in `licenses/`.

## Bundled / linked

| Component | Version | License | Copyright |
| --- | --- | --- | --- |
| [nlohmann-json](https://github.com/nlohmann/json) | 3.12.0 | MIT | (c) 2013-2025 Niels Lohmann |
| [YY-Thunks](https://github.com/Chuyu-Team/YY-Thunks) | 1.2.1 | MIT | (c) 2018 Chuyu-Team |
| [libslirp](https://gitlab.freedesktop.org/slirp/libslirp) | 4.9.1 | BSD-3-Clause | (c) 1995-1996 Danny Gasparovski and the libslirp contributors |
| [GLib](https://gitlab.gnome.org/GNOME/glib) | 2.88.0 | LGPL-2.1-or-later | (c) The GLib authors |
| [PCRE2](https://github.com/PCRE2Project/pcre2) | 10.47 | BSD-3-Clause | (c) 1997-2007 University of Cambridge; (c) 2007-2024 Philip Hazel; JIT written by Zoltan Herczeg |
| [GNU libiconv](https://www.gnu.org/software/libiconv/) | 1.18 | LGPL-2.1-or-later | (c) Free Software Foundation |
| [GNU gettext (libintl)](https://www.gnu.org/software/gettext/) | 0.22.5 | LGPL-2.1-or-later | (c) Free Software Foundation |

GLib, PCRE2, libiconv and libintl are pulled in transitively by libslirp and form its
static link closure.

---

### MIT (nlohmann-json, YY-Thunks)

> Permission is hereby granted, free of charge, to any person obtaining a copy of this
> software and associated documentation files (the "Software"), to deal in the Software
> without restriction, including without limitation the rights to use, copy, modify, merge,
> publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons
> to whom the Software is furnished to do so, subject to the following conditions:
>
> The above copyright notice and this permission notice shall be included in all copies or
> substantial portions of the Software.
>
> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
> INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
> PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE
> FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
> OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
> DEALINGS IN THE SOFTWARE.

### BSD-3-Clause

**libslirp** - Copyright (c) 1995, 1996 Danny Gasparovski. All rights reserved.

> Redistribution and use in source and binary forms, with or without modification, are
> permitted provided that the following conditions are met:
> 1. Redistributions of source code must retain the above copyright notice, this list of
>    conditions and the following disclaimer.
> 2. Redistributions in binary form must reproduce the above copyright notice, this list of
>    conditions and the following disclaimer in the documentation and/or other materials
>    provided with the distribution.
> 3. Neither the name of the copyright holder nor the names of its contributors may be used
>    to endorse or promote products derived from this software without specific prior written
>    permission.
>
> THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT
> NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
> PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL DANNY GASPAROVSKI OR CONTRIBUTORS BE LIABLE FOR
> ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
> BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
> PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
> IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY
> WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

**PCRE2** is distributed under the 3-clause BSD licence (the "PCRE2 LICENCE"), with the
same three conditions and disclaimer form as above, held by University of Cambridge and
Philip Hazel (and Zoltan Herczeg for the JIT component).

### LGPL-2.1-or-later (GLib, libiconv, libintl)

The full license text is supplied in [`licenses/LGPL-2.1.txt`](licenses/LGPL-2.1.txt).

These libraries are statically linked. Per LGPL-2.1 §6, a recipient of a CE Runtime
Foundation binary is entitled to relink the work against a modified version of each
library. This is satisfied as follows:

- **Corresponding library source.** The exact upstream releases used are pinned in the
  table above (GLib 2.88.0, libiconv 1.18, gettext 0.25) and are built unmodified from
  their upstream sources, linked in the table above. The unmodified source for each is
  available from its upstream project; a written request to the project maintainer will
  also be honored for the duration that a given release is distributed.
- **Relinkable form of the work.** CE Runtime Foundation's complete source is public,
  so a recipient can rebuild the work against a modified library from source.

## Embedded fonts

**[IBM Plex](https://github.com/IBM/plex)** - SIL Open Font License 1.1, (c) 2017 IBM Corp.
`cerf.exe` embeds the unmodified faces in the table below as `RCDATA` resources. CERF loads
them at run time as process-private fonts. CERF does not install them on the host system.

| Face | File |
| --- | --- |
| IBM Plex Sans Regular | `cerf/assets/fonts/IBMPlexSans-Regular.ttf` |
| IBM Plex Sans Bold | `cerf/assets/fonts/IBMPlexSans-Bold.ttf` |
| IBM Plex Mono Bold | `cerf/assets/fonts/IBMPlexMono-Bold.ttf` |

The file [`licenses/OFL-1.1.txt`](licenses/OFL-1.1.txt) contains the full license text.

## Development environment

- **[SimpleEnglish](https://github.com/AminBlg/SimpleEnglish)** - MIT, (c) 2026 AminBlg

## Studied references

- **[QEMU](https://www.qemu.org/)** - the MIPS CP0 exception model, translation-block
  chaining and cache invalidation, the condition-flag cache, MMIO dispatch
  memoization, the virtual clock and the timer peripherals, and the DP8390 NIC.
- **[the Linux kernel](https://www.kernel.org/)** - StrongARM coprocessor behavior,
  the NE2000 PC card, the 8390 NIC, raw NAND, the S3C24xx IIS, and the S3C24xx
  touch screen.
- **[NetBSD](https://www.netbsd.org/)** - hpcmips, the UCB1200, the IT8181 and IT8368,
  the VRC4172, the PR31x00, and the VR41xx.
- **[Dolphin](https://dolphin-emu.org/)** - the precision timer wait and the
  Windows process power-throttling opt-out.

## Trademarks

Windows and Windows CE are trademarks of Microsoft Corporation. CE Runtime Foundation is an
independent project, not affiliated with, endorsed by, or sponsored by Microsoft.

ASD-STE100 is a registered trademark of ASD. The SimpleEnglish skill is unofficial, and ASD
and STEMG do not endorse it.
