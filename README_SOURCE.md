<img src="docs/github_band.svg" width="100%"/>

<div align="center">
  <b>CE Runtime Foundation</b> (aka <i>CERF</I>) - <b>Universal Windows CE emulator</b><br/>
  <b><a href="https://cerf.cx">cerf.cx</a></b> - read more information about the project  
</div><br/>

<div align="center">
  <a href="https://discord.gg/QREE9Y2v2d"><img src="https://img.shields.io/badge/Discord-join%20the%20server-5865F2?logo=discord&amp;logoColor=white" alt="Discord"/></a> {support_badges}
</div>

<br/>

> [!WARNING]
> **Beta stage.** CERF is a hobby project, developed in spare time
> and can't be a called production-grade/exceptionally stable project.
> **Expect bugs, crashes, and breaking changes.** 🙃
>
> For the same reason - be careful if you are going to use CERF is a reference for
> hardware level behaviour. The code works but CERF is not an official chip datasheet.

## Downloads

To use the newest features, download the WIP build ({version}) from the artifacts [![build](https://github.com/gweslab/cerf/actions/workflows/build.yml/badge.svg)](https://github.com/gweslab/cerf/actions/workflows/build.yml). For a stable version, go to the [latest release](https://github.com/gweslab/cerf/releases/latest).

If you need any additional help, e.g. what to run and how to use the emulator - visit [cerf.cx](https://cerf.cx/articles).

See ``cerf.exe`` command line usage at [cerf.cx/articles/command-line](https://cerf.cx/articles/command-line/).

## Supported boards

{supported_devices}

## Running your own ROM

A ROM boots only if **CERF implements that exact board**. A matching SoC is not sufficient.

**The board is on the supported list.** The [articles](https://cerf.cx/articles/own-rom/) show how to boot your own dump.

**The board is not on the supported list.** A new board is a code contribution. It needs C++ for the memory map of the board, for each peripheral that the drivers use, and for the quirks of the SoC. The code must agree with datasheets, BSP sources and reverse engineering, at the quality level of the current tree. A new board is not a change to a configuration file - that's not that simple.

> [!IMPORTANT]
> **CERF does not accept ROM submissions or requests for new boards.** If you want a new board - your only choice is to build a support yourself and send a contribution.

## Building

CERF requires Visual Studio 2026 with the C++ desktop development workload.

> [!NOTE]
> **The first build on a new machine takes more than one hour.** vcpkg compiles the dependencies from source before CERF links. This occurs one time on each machine. Later builds use the cached `vcpkg_installed/` tree and are complete in a few minutes. Do not stop the first build.

Configure the clone (one time on each machine):

```
setup.cmd
```

or dry run:

```
setup.cmd -Check
```

It will
- point git at tracked hooks
- report missing prerequisite

**Build the entire proejct with a helper script**:

```
powershell -ExecutionPolicy Bypass -File build.ps1
```

The script will:
- wait for a parallel build (Claude Code-special feature for parallel agents work)
- build the launcher (and will install CPython into a repo directory, if needed)
- build the emulator itself (and will pick appropriate SDK/toolchain from your installations)
- build all the bundled Windows CE apps (at ``ce_apps/``)

### Building the CE-side binaries (optional)

`ce_apps/` holds the Windows CE binaries that CERF ships, and the Guest Additions driver.
To build them, you need a CE toolchain and a CE SDK. 

`cerf.exe` does **not** need them. If you work on the emulator core, the boards, the SoCs, the JIT or the host UI,
use the prebuilt binaries from another CERF release or just dont use them at all.

To build `ce_apps/`, install eMbedded Visual C++ 4.0 (a free Microsoft download from the
Microsoft archive). CERF includes a script that will unpack the installation (you dont want and probably can't install ancient tools)
and will place the build tools / SDK into appropriate directories.
See **[docs/ce_apps_setup.md](docs/ce_apps_setup.md)**.

`setup.cmd -Check` reports whether the CE toolchain is present.

### Website

This repositroy includes [cerf.cx](https://cerf.cx) source code at ``docs/website``.

`python tools/build_site.py --serve` runs the website on your machine with live reload.

## Changelog

{changelog}

## Known Issues

For the issues of each board, see the [board database of the launcher](launcher/supported_devices.py) or read Notes block when you use a launcher.

## Claude Development Environment

> [!TIP]
> Contributions made with AI are welcome - only if they correspond the quality level we maintain. The development involves a huge **human resouce** contribution. Do not turn this project into AI slop - we build a respectable emulator here.

The environment includes several contraversional things you need to know before using it.

- Full project **documentation is injected** into a system prompt - this eats tokens
- The environment **kills** global ``clangd.exe`` and own ``claude.exe`` instances if they leak memory
- Thinking is set to *high*; **bypass permissions mode** is set
- Several own/3rd-party **skills** included
- Powerful hooks triggering when agent might do something bad to the codebase
- IDA MCP is ready to be installed at ``tools\ida_server.py`` and ``tools\ida_claude.py``
- FS Read MCP is a workaround for ``Read()`` tool, useful for ``/tracking restore`` and massive text files (``tools\fs_read_mcp.py``)

The environment gives you the **`/start-board-implementation`** skill. Run the skill and agent will start the new board bring-up on its own. You need experience - the skill won't do all the work instead of you. (Tho honestly speaking, there have been cases where Claude alone brought a board to a bootable state)

Run the environment:

```
run_claude.cmd
```

## License

[MIT](LICENSE). Third-party components and studied references are listed in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

---

CERF was started as [WCECL](https://github.com/dz333n/wcecl) in 2019.

**Copyright (c) 2019-{cur_year} [Yaroslav Kibysh](https://yaroslavkibysh.com)**
