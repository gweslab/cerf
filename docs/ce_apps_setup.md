# Building `ce_apps/` - CE toolchain & SDK setup

**This is optional.** CERF itself (`cerf.exe`) builds with Visual Studio alone and needs
nothing on this page. You only need the Windows CE toolchain if you want to build
`ce_apps/` - the CE-side binaries CERF ships, including the Guest Additions display
driver (`cerf_guest`). If you are working on the emulator core, boards, SoCs, the JIT, or
the host UI, skip this file entirely; the prebuilt CE binaries are staged for you.

Everything below lives under `third_party/`, which is gitignored.

---

## 1. What the build looks for

The build reads one directory. Whatever produces it, this is the contract:

```
third_party/wince/
  bin/                              CE toolchain (flat, exactly as eVC4 ships it)
    clarm.exe  clthumb.exe  clmips.exe  clsh.exe
    link.exe   lib.exe      rc.exe   rcdll.dll
    armasm.exe mipsasm.exe  mspdb60.dll
    c1_arm.dll c1xx_arm.dll c2_arm.dll
    c1_mp.dll  c1xx_mp.dll  c2_mp.dll
    c1_sh.dll  c1xx_sh.dll  c2_sh.dll
  STANDARDSDK/
    Include/{Armv4, Armv4i, Mipsii, Mipsiv, Sh3}/
    Lib/{Armv4, Armv4i, Mipsii, Mipsiv, Sh3}/       (each with coredll.lib, corelibc.lib)
```

**ARMv4, ARMv4i (Thumb), MIPS-II, MIPS-IV, SH-3** are the complete set CERF targets. Each app
selects its CE version at link time via the PE subsystem stamp and its coredll import
binding, so one SDK serves every CE version CERF boots.

Copies or symlinks both work; the build only reads the paths above.

Verify the tree at any time:

```
powershell -ExecutionPolicy Bypass -File setup.ps1 -Check
```

---

## 2. Producing it from eMbedded Visual C++ 4.0

One download supplies **both** halves - the toolchain and an SDK covering every target
architecture.

### 2.1 Get eVC4

Obtain **eMbedded Visual C++ 4.0 (English)**. It was a free Microsoft download and is
archived, with the rest of the CE developer tooling, at:

> https://www.hpcfactor.com/developer/

You do **not** need the Service Packs or Updates listed on that page. The base release is
sufficient for every target architecture.

### 2.2 Unpack it - do not install it

The eVC4 IDE does not install on modern Windows, and you do not need it to. Unpack the
CD/ISO (7-Zip opens it directly) into:

```
third_party/evc4/
```

Unpack the CD *itself*, not a subfolder of it. You have it right when these exist:

```
third_party/evc4/SDK/STANDARD_SDK.msi
third_party/evc4/WCE/wce400/BIN/clarm.exe
third_party/evc4/COMMON/EVC/BIN/rc.exe
```

### 2.3 Run the unpacker

```
powershell -ExecutionPolicy Bypass -File tools/unpack_evc4.ps1
```

It expands `STANDARD_SDK.msi` via an **administrative install** (`msiexec /a`) - the MSI's
file tree is extracted without installing the product, touching the registry, or running
the IDE's setup - then lays the toolchain and SDK out as § 1 requires and verifies the
result. Pass `-Force` to rebuild an existing `third_party/wince/`.

Then build the CE binaries:

```
powershell -ExecutionPolicy Bypass -File build.ps1
```

which walks every `ce_apps/*/build.ps1` after `cerf.exe` links.

---

## 3. Do not substitute a newer SDK

The CE 5.0 Standard SDK ships `ARMV4I`, `MIPSII` and `MIPSIV` only - it dropped ARMv4
non-Thumb, which CERF needs for no-Thumb cores such as the SA-1110. The CE 4.0 Standard SDK
on the eVC4 CD is the newest one carrying every target.
