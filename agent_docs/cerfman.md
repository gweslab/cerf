# cerfman - the device manager, configuration and installation

cerfman is the internal name of the CE Runtime Foundation Device Manager. It is C++ and Qt Quick code in `cerf-qt/cerfman/`. It is part of the frontend
executable: `cerf.exe` on Windows, `cerf` on Linux, and the `CE Runtime Foundation.app`
bundle on macOS. `tools/host_branch.py` holds the path of that executable on each host.

cerfman links libCerfCore and reads `db.json` only through the libCerfCore readers. No
second copy of that data exists in any other language.

## Process modes

The command line of the frontend selects one mode:

| Command line | Mode |
|---|---|
| (none) | The manager window opens. |
| `--wait-for-pid=`, `--install`, `--upgrade`, `--post-upgrade` | The install stage runs. See § Self-update and installation. |
| anything else, for example `--device=<name>` | The emulator runs. |

On Windows, Linux and macOS, the manager starts each device as a separate emulator
process: the same executable with `--device=<name>` and the options of that start. The
emulator opens manager windows directly, in its own process.

The Android app has no command-line modes. Its manager runs each device inside the
manager process, as one more `CerfEmulator` instance with the options of that start.

When a fatal halts a device on Android, the manager opens the crash window and continues
to run. A desktop emulator process opens the crash window itself in a production build,
then exits with the halt code. A dev build exits at once.

A device can fail to stop after the user closes it or after a fatal halts it. A desktop emulator
process then exits.
On Android the manager closes the window of that device and opens the crash window. The
threads of the device stay allocated until the app ends, because CERF cannot join a thread
that does not stop.

A fatal that halts the manager instance ends the manager and every device that runs in it.
The app then opens the crash window. The app ends when the user closes that window. When the
instance that shows the crash window halts too, the app ends at once.

The manager writes its log to `manager.log` in the install root. The install root is the
folder that holds the global `cerf.json`.

## The three configuration files

| File | Content |
|---|---|
| `devices/<name>/cerf.json` | The truth about the device: `meta`, `board.id`, `rom.primary`. A bundle update replaces it. Nobody edits it by hand. |
| `devices/<name>/cerf-user.json` | Every user setting of the device and the repository link. It survives a bundle update. It wins over `cerf.json`. |
| `<install root>/cerf.json` | The keys that belong to the installation, not to one device. |

`docs/website/content/articles/cerf-json.md` is the schema. It owns what each of these
files can contain.

When `bundled/cerf.local.json` exists, a dev build puts its top-level keys into the
global `cerf.json` that it builds. A key in that file replaces the key of the same name.

The manager writes a device setting only when it differs from the `cerf.json` value. It
deletes the file when the file becomes empty. The screen size and the color depth have
no such baseline: "Auto" is their absence, and the manager writes any other value.

A write takes the keys its caller owns. It reads the file, replaces those keys and
writes the file back. A caller that owns four keys must not write the full set,
because that removes the keys of every other caller.

CERF does not read a broken `cerf-user.json`. It does not report the broken file. A
write overwrites a configuration file that it cannot read or parse.

The emulator writes `board.configurable_screen_width` and `_height` into
`cerf-user.json` when the user resizes the window. No other emulator path writes the
file outside the property sheet.

## The property sheet

The property sheet is the only place that edits a device setting. It holds one model
of the device. A page loads its values from that model when the sheet shows it and
stores them back when the user leaves it. OK writes the model. Cancel writes nothing.
No control writes on change.

In the emulator process, the sheet opens on its Guest Additions page, with every
control that needs a restart of the emulator disabled. Some fields take effect only
after a guest reset. When the user changes one, OK asks which reset to run.

After OK in the emulator process, the emulator reads `cerf.json` and then
`cerf-user.json` again. It never applies its command line again, because a
command-line value replaces the value that the sheet just wrote. A service that keeps
its own copy of a setting registers a listener for that read.

The manager puts on the command line of an emulator only the settings that no
configuration file holds.

## Bundles

A bundle is one ROM package on a remote repository. Each repository serves version 2
of `manifest.json` and `analytics.json`. The repositories are the
`bundle_repositories` key of the global `cerf.json`.

A bundle update replaces the device directory with the new bundle. It keeps
`cerf-user.json`, every installed add-on package and every storage file inside the
device directory.

`devices/manifest.json` records each installed bundle. A bundle is out of date when
the SHA-256 of its archive in that file differs from the SHA-256 in the remote
manifest. A broken `devices/manifest.json` counts as empty. The next write
overwrites it.

The manager makes sure that the size and the SHA-256 of each archive match the
manifest. During extraction it rejects each file in the archive whose path is outside
the target directory.

## Running devices

A running emulator writes `devices/<name>/cerf-status.json` with its pid, window handle
and a heartbeat. A heartbeat older than 7 seconds counts as dead. The property sheet of
a running device opens with every control disabled.

The manager brings a running device to the front and does not start a second one. On
Windows it uses the window handle. On Linux it sends a datagram to the abstract Unix
socket `cerf-show/<pid>`. On macOS the socket is the file `cerf-show-<pid>` in
`$TMPDIR`. On Android the manager shows the window of the running device directly.

Before the Android manager starts a second device, it asks the user, because a host crash
or a lack of memory stops every device that runs.

## Self-update and installation

Each channel picks the build for the `host_branch` of the installation. `build.py`
stamps that key into the global `cerf.json`. `tools/host_branch.py` is the only table
of host branches. A file with no key is a `win32-x86` build.

- The stable channel takes the release asset whose name ends with
  `-Release-<platform>.zip`.
- The unstable channel reads the `host_branches` object of `latest.json`. Its root
  keys stay the `win32-x86` build, because older installations read only them.

The manager downloads the update into `<install root>/upgrade/` and starts the staged
frontend with `--wait-for-pid=<pid> --upgrade`. The install stage then does these steps:

1. It waits for that process to exit. It does not continue while a frontend of the
   installation runs.
2. It copies the staged build over the installation. On macOS it replaces each
   application bundle whole, symbolic links included.
3. It removes the retired entries of earlier builds that the new build does not ship.
4. It merges the global `cerf.json`, so user keys survive.
5. On Windows, it creates the shortcuts that the options name. On an upgrade, it also
   rewrites the shortcuts and the Programs and Features entry that point into this
   installation, so integration from an earlier build follows the new executable.
6. It starts the installed frontend with `--wait-for-pid=<pid> --post-upgrade`. That
   process deletes `upgrade/`.

On Android, the app places its bundled files into the install root at the first start
of each installed package. It merges `cerf.json` as the install stage does. It also
deletes each file that the previous package placed and the new package does not ship.

## Installing and uninstalling

`installers/windows_installer.ps1` installs CERF on Windows. It asks the user for the
install root, `%APPDATA%\CE Runtime Foundation` by default, and for the install choices.
It downloads the build into `<install root>\upgrade\`. Then it starts
`upgrade\cerf.exe --install` with the flags that the answers name. The script needs
PowerShell 3.0 and .NET Framework 4.5.

`installers/linux_macos_installer.sh` installs CERF on Linux and macOS in the same way.
Its install root is `~/CE Runtime Foundation` by default. It reads its answers from
`/dev/tty`, so it also works when `curl` pipes it into `sh`.

On Linux, the script installs the packages that CERF needs with `apt-get`, `pacman`,
`dnf` or `zypper`. It holds one package list for each of these package managers. Each
list names the packages that own the libraries that `cerf` links, the Qt plugins that
it loads and the QML modules that it imports. A new library, plugin or QML import in
the frontend needs its package in every list. Before the script starts the staged
frontend, `ldd` must find every library and symbol version that `cerf` needs.

`uninstaller-win32/` builds `uninstall.exe`, a Win32 program with the static C runtime.
It sits in the install root, copies itself to `%TEMP%`, runs from the copy, and removes
the installation. It removes the Start menu folder, the desktop shortcut and the
Programs and Features entry only when they point into this installation. The user data
in the install root stays unless the user asks for it to go too.

`launcher-stub-win32/` builds the root `launcher.exe`. It forwards its whole command
line to `cerf.exe`, or to `uninstall.exe` when the command line holds `--uninstall`.
Installers and self-updates of 7.0 start `upgrade\launcher.exe`, so the stub stays
in the Windows release. The 7.0 installer starts it with `--install` and the user's
choices. The install stage then creates the shortcuts that those choices name.

An installer is as old as the day the user downloaded it. As a result, it stages a
release and hands control to the frontend in that release. Everything that shapes an
installation belongs to the install stage, so the newest build always decides it.

The installer scripts, and the copy of the uninstaller in `%TEMP%`, run outside an
installation. No installation data is beside them, so their code must not load
`db.json` or another file that an installation ships.

## Rules

- Never run the installer, the uninstaller or the install stage against the
  integration of a real installation. They write to the installation directory, the
  Start menu and the registry.
- A new setting goes in the property sheet or in Settings of the manager.
