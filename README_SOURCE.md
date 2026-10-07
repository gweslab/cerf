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
>
> **This document covers development and contribution aspects**. Visit [cerf.cx](https://cerf.cx)
> for user-oriented documentation.

## [Contribution Guidelines](.github/CONTRIBUTING.md)

## Downloads

To use the newest features, download the WIP build ({version}) from the artifacts [![build](https://github.com/gweslab/cerf/actions/workflows/build.yml/badge.svg)](https://github.com/gweslab/cerf/actions/workflows/build.yml). For a stable version, go to the [latest release](https://github.com/gweslab/cerf/releases/latest).

If you need any additional help, e.g. what to run and how to use the emulator - visit [cerf.cx](https://cerf.cx/articles).

See `cerf.exe` command line usage at [cerf.cx/articles/command-line](https://cerf.cx/articles/command-line/). Might be stale - prefer running `cerf.exe --help` manually instead.

## Running your own ROM

**The board is on the supported list.** The [articles](https://cerf.cx/articles/own-rom/) show how to boot your own dump.

**The board is not on the supported list.** A new board needs a code contribution. You need to write your own code. Visit [Contribution Guidelines](.github/CONTRIBUTING.md) before doing that.

> [!IMPORTANT]
> **CERF does not accept ROM submissions or requests for new boards.** If you want a new board - your only choice is to build a support yourself and send a contribution.

## Building

CERF requires Visual Studio 2026 with the C++ desktop development workload.

> [!NOTE]
> **The first build on a new machine takes more than one hour.** vcpkg compiles the dependencies from source before CERF links. This occurs one time on each machine. Later builds use the cached `vcpkg_installed/` tree and are complete in a few minutes. Do not stop the first build.

> [!CAUTION]
> Development environment might need additional configuration on your machine that this guide doesn't explain. If you find a bug there, or find a more universal approach - feel free to submit a pull request.

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
- build all the bundled Windows CE apps (at `ce_apps/`)

> [!NOTE]
> The script is primarily designed for Claude. It should still work if you invoke it manually.

### Building the CE-side binaries (optional)

`ce_apps/` holds various Windows CE applications CERF is bundled with including the Guest Additions driver.

You don't need those if you are not working with Guest Additions. You may copy Guest Additions binaries from an artifact or skip them entirely.

To build `ce_apps/`, install eMbedded Visual C++ 4.0 (a free Microsoft download from the
Microsoft archive). CERF includes a script that will unpack the installation (you dont want and probably can't install ancient tools)
and will place the build tools / SDK into appropriate directories.
See **[docs/ce_apps_setup.md](docs/ce_apps_setup.md)**.

`setup.cmd -Check` reports whether the CE toolchain is present.

### Website

This repository includes [cerf.cx](https://cerf.cx) source code at `docs/website`.

`python tools/build_site.py --serve` runs the website on your machine with live reload.

## AI Usage / Vibecode Notice

AI-assisted contributions are welcome. That's a nice thing to have in 2026 - you have access to tons of resources right in your pocket. Let me show generic use cases on this project:
- study emulators, study JIT, study assembly on various archs, study every piece that affects your code that you don't understand how it works yet
- learn and use AI to reverse engineer; use AI to reach for more correct architecture calls when you stall
- use AI to find projects/resources with compatible license to learn/borrow something complex
- use it to find manuals and papers for devices you target, SoCs/peripherals you target and to extract quotes from them
- use it to work with and explain complex data structures and non trivial algorithms
- use it to review your code and to criticize it 
- the AI is an instrument to convert plain thoughts into a code - that's a replacement for typing code in order to get the same code you wanted but faster

The vibe code is banned. Please read [Contribution Guidelines](.github/CONTRIBUTING.md). Do not turn this into an AI slop. We put an effort here and we maintain a quality level.

## Claude Development Environment

The environment includes several controversial things you need to know before using it.

- Full project **documentation is injected** into a system prompt - this eats tokens
- The environment **kills** global `clangd.exe` and own `claude.exe` instances if they leak memory
- Thinking is set to _high_; **bypass permissions mode** is set
- Several own/3rd-party **skills** included
- Powerful hooks triggering when agent might do something bad to the codebase
- IDA MCP is ready to be installed at `tools\ida_server.py` and `tools\ida_claude.py`
- FS Read MCP is a workaround for `Read()` tool, useful for `/tracking restore` and massive text files (`tools\fs_read_mcp.py`)

The environment gives you the **`/start-board-implementation`** skill. Run the skill and agent will start the new board bring-up on its own. You need experience - the skill won't do all the work instead of you. (it actually will do, and [that's the problem](#ai-usage--vibecode-notice))

Run the environment:

```
run_claude.cmd
```

## Supported boards

{supported_devices}

## Changelog

{changelog}

---

CERF was known earlier as [WCECL](https://github.com/dz333n/wcecl) (2019)

[**MIT License**](LICENSE) | [**Third-Party Notices**](THIRD_PARTY_NOTICES.md)<br/>
**Copyright &copy; 2019-{cur_year} [Yaroslav Kibysh](https://yaroslavkibysh.com)**
