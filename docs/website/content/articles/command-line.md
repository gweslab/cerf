# Running CERF from the command line

The launcher is the normal way to start CERF: it downloads the ROM bundle and boots it. Everything
below is for running `cerf.exe` directly.

## Commands

| Command | Action |
| --- | --- |
| `cerf.exe --device=devemu_ce6` | Boot a specific device |
| `cerf.exe --guest-additions` | Boot with [Guest Additions](guest-additions.md) |
| `cerf.exe --log=ALL` | Enable every log channel |
| `cerf.exe --flush-outputs` | Force-flush logs - avoids truncation on a crash, but is very slow |

`cerf.exe --help` prints the full command line, including the list of board ids.

## Logs

CERF writes `cerf.log` next to the executable. By default it carries a **limited set of channels** -
enough to see a boot fail or a device misbehave, without spam. For full detail use `--log=ALL`, or
name the ones you want:

```
cerf.exe --log=BOOT,JIT,MMU
```

If CERF dies, it also writes `cerf.crash.log` next to the executable - every other thread's
register state and a snapshot of its stack at the moment of the crash. Both files are what a bug
report needs.
