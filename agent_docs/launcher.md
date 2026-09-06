# Launcher - the configuration and bundle front end

`launcher/` is a standalone Python/tkinter program. PyInstaller packages it as
`launcher.exe`. It is **not** a `CerfEmulator` service and it shares no code with
`cerf.exe`. The two programs sit in the same directory and exchange data through
files only.

The launcher owns three jobs:

- it installs and updates ROM bundles into `devices/<name>/`
- it **owns every persisted user setting** - it is the only writer of
  `cerf-user.json`
- it starts `cerf.exe`

`cerf.exe` reads those files. It writes one of them in one case only. See
§ The exception: the window resize.

## Run modes

`launcher.py` is the only entry point. It reads `sys.argv` and picks a mode.

| Argument form | What happens |
|---|---|
| (none) | The full window opens. This is the normal mode. |
| `sync <command> …` | Console mode. `launcher_cli.py` downloads, updates or deletes bundles. |
| `transactional <device> <file>` | One configuration dialog opens. See § Transactional mode. |
| `--upgrade`, `--post-upgrade` | The two stages of the self-update. |

`devices_dir` is always `<exe dir>/devices`, the same tree `cerf.exe` reads.

## The three configuration files

| File | Written by | Content |
|---|---|---|
| `devices/<name>/cerf.json` | The launcher, from the remote manifest | The truth about the device: `meta`, `board.id`, `rom.primary`. Never edited by hand. A bundle update replaces it. |
| `devices/<name>/cerf-user.json` | The launcher (and the user) | Every user setting. It survives a bundle update. It wins over `cerf.json`. |
| `<exe dir>/cerf.json` | Shipped, then the launcher | The keys that belong to the installation, not to one device. |

`docs/website/content/articles/cerf-json.md` is the schema. It owns what each of
these files can contain.

`cerf-user.json` holds the launcher link (`launcher.repository_url` +
`name_on_repository`), the display-name override (`meta.name`), and the
persisted launch options:

    network.enabled
    guest_additions.enabled
    guest_additions.override_color_scheme
    full_screen
    share_folder
    board.configurable_screen_width / _height / _dpi / _bpp

**A setting is written only when it differs from the `cerf.json` value.**
`persisted_options.py` computes that difference. `resolve_baseline` builds the
`cerf.json` values, and `persist_subset` writes the difference set. The launcher
deletes the file when it becomes empty.

**`persist_subset` takes the keys its caller owns.** It reads the file, replaces
only those keys, and writes the file back. A caller that owns four keys must not
write the full set, because that removes the keys of every other caller.

## Option blocks

Two option blocks are shared. The side panel and the transactional dialogs build
the same widgets from the same class, so the two places always agree.

- `customizations_block.py` - resolution, color depth, DPI, color scheme. Color
  scheme is last.
- `share_folder_block.py` - the guest-additions shared folder: one check box and
  one path field.

`launch_options.py` puts both blocks in the side panel. It adds the
guest-additions check box, the full-screen check box, and the log and network
check boxes. It writes each change to disk immediately.

## Transactional mode

### Why it exists

Every control that edits a persisted setting lives in the launcher, and only
there. `cerf.exe` draws no such control. When the running emulator needs one, it
asks the launcher to show it.

The rule follows from file ownership. The launcher is the only writer of
`cerf-user.json`. A dialog inside `cerf.exe` therefore has two possible
outcomes, and both are bad. It loses what the user picked, or it becomes a
second writer of the same file. A second copy of the same controls also needs
manual work to stay in step with the side panel.

### The protocol

1. `cerf.exe` writes `devices/<device>/transactional-XXXXXXXX-XXXX.json`. Each
   top-level key names one dialog to run:

        { "customizations": { "query": { "force_reboot": true,
                                         "default_reset": "soft" } } }

   `query` carries what the dialog cannot know by itself. It can be empty.
   More than one key runs more than one dialog, one after the other.

2. `cerf.exe` starts `launcher.exe transactional <device> <file>` and waits for
   it to exit. It pumps its own messages while it waits, so the window stays
   alive.

3. The launcher runs each dialog. The controls already show the saved values,
   because they read the same two files. **OK** saves. **Cancel** saves nothing.

4. A dialog that must answer `cerf.exe` writes a `response` object into its own
   key of the same file:

        { "customizations": { "query": { … },
                              "response": { "reboot": "soft" } } }

   `reboot` is `null`, `"soft"` or `"hard"`.

5. `cerf.exe` reads the response and deletes the file.

### What the refresh does

Each caller decides whether to run the refresh. `LauncherTransaction` never runs
it.

`DeviceConfigRefresh` re-reads `cerf.json` and then `cerf-user.json`. It writes
the mutable fields into the live `DeviceConfig`. It then calls its listeners.

**The refresh must never replay the command line.** `ConfigLoader` applies CLI
arguments last at boot. A replay puts the old `--screen-width` back over the
value the launcher just wrote.

Two services keep their own copy of a refreshed field, so each one registers a
listener:

- `FolderShareConfig` re-applies the path at once, because the shared folder is
  live.
- `CerfVirtColorScheme` re-reads its table at the next CPU reset, because the
  guest reads that table only when its display driver starts.

Nothing else needs a listener. The guest reads the DPI and the screen size from
`DeviceConfig` at the moment it asks for them. The color depth already re-applies
on the reset line.

### The exception: the window resize

The user can also change the guest resolution when they resize the window. That
path has no dialog and no launcher. `cerf.exe` therefore writes
`board.configurable_screen_width` and `_height` into `cerf-user.json` itself
(`UserConfigWriter`). This is the only write `cerf.exe` makes into that file. All
three ways to set the resolution then agree.

### When `launcher.exe` is missing

`launcher.exe` must be present and must work. If it is absent, or if it fails to
start, `cerf.exe` shows an error box that names the file. This is a damaged
installation, not a supported state.

## Bundles

A bundle is one ROM package on a remote repository. `bundle_repositories.py`
reads the repository list from the global `cerf.json`. The default repository is
`https://cerf-bundles.dz3n.net/cerf-bundles`. Each repository serves
`manifest.json` (version 2 only) and `analytics.json`.

`operations.py` (`BundleManager`) installs into a temporary directory, then
replaces the device directory with it. An update **keeps** `cerf-user.json` and
every installed add-on package. It then writes `cerf.json` from the manifest.
`devices/manifest.json` records what is installed, keyed by directory name. A
bundle is out of date when its recorded archive SHA-256 differs from the remote
one.

The launcher verifies the size and the SHA-256 of every archive. Extraction
rejects any member that escapes the target directory.

## Starting cerf.exe

`launcher_spawn.py` builds the argument list with
`LaunchOptionsPanel.collect_args()` and starts `cerf.exe` detached.

The launcher does not start a device that already runs. `cerf.exe` writes
`devices/<name>/cerf-status.json` with its pid, window handle and a heartbeat.
`device_state.running_status()` treats a heartbeat older than 7 seconds as dead.
A running device locks its launch options in the side panel.

## Board data

`supported_devices.py` is a hand-edited table, keyed by `board_id`. It holds the
supported flag, the SoC, the feature map and the per-board notes. `board_info.py`
reads it, the side panel shows it, and `compile_readme.py` builds the README
board table from it.

## Self-update

`update_source.py` picks the channel from the global `cerf.json`: the latest
GitHub release, the latest CI build, or nothing. The launcher downloads the
update into `<exe dir>/upgrade/`. A staged `launcher.exe --upgrade` then copies
it over the installation, after the old process exits. It never overwrites the
global `cerf.json`. `cerf_json_merge.py` merges that file, so user keys survive.
The launcher refuses an update while any `cerf.exe` runs.

## CPython 3.7 - a hard limit

**The launcher ships on CPython 3.7.9 (x86).** It is the newest interpreter that
loads on Windows Vista, the supported floor. Every `launcher/*.py` file must run
on 3.7.

Use nothing newer: no walrus `:=`, no `Path.unlink(missing_ok=)`, no
`str.removeprefix` or `removesuffix`, no `math.isqrt`, no `dict | dict`. A 3.8+
call runs on a modern interpreter and then fails inside the shipped exe, where
nobody sees the traceback.

Run the cached interpreter on every launcher file:

    references/python/cpython-3.7.9-x86/python.exe -m py_compile launcher/*.py

`launcher/build.ps1` runs PyInstaller 5.13.2 against that interpreter, embeds the
UCRT redistributable, and copies the result to `bundled/launcher.exe`. The
top-level `build.ps1` runs it when any launcher file changes, and
`CopyBundledFiles` puts it next to `cerf.exe`.

## Rules

- **Never run the launcher yourself.** It downloads ROM bundles and rewrites the
  device tree of the user.
- A new setting goes in the launcher, never in a new `cerf.exe` dialog.
- `cerf.exe` reads `cerf-user.json`. Only the window-resize path writes it.
