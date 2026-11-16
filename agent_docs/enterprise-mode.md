# Enterprise mode

Enterprise mode serves the owners of a commercial license.

`bundled/cerf.default.json` holds its keys and their standard values.

Each `enterprise` key acts alone. `allowed` only shows the Settings page.

## The password gate

The password gate asks for the enterprise password. A correct password signs in the
process, not one `CerfEmulator`.

A device asks in a dialog of its emulator window, never in a new window. On Android, a
new window that opens during a key press hangs the app.

The password gate covers every route into cerfman. Emulator code opens a cerfman
window only through `PasswordGatedActions`. The manager window locks again when it
becomes active in a signed-out process, because on Android a device that exits returns
to that window.

## Kiosk mode

A device reads the `kiosk` key when it starts. After that, only its own menu and the
host key change its kiosk mode.

On the desktop, a close request does nothing, and the host key ends kiosk mode. An
Android device can have no host key. There the close request and Return to my devices
go through the gate.

A shutdown dialog that the guest causes is never behind the gate, because only that
dialog can resume a guest that sleeps.

## The shutdown policy

The action that runs with no dialog waits longer after a guest suspend than the dialog
does. Some guests sleep and wake at once, and the user cannot cancel that action.

A host action that the host does not implement stays in the shutdown policy. It halts
the instance when it runs.

- `cerf-qt/enterprise_config.h`, `cerf-qt/process_sign_in.h`,
  `cerf-qt/cerfman/password_gate.h`, `cerf-qt/password_gated_actions.h`,
  `cerf-qt/kiosk_mode.h`, `cerf-qt/shutdown_policy.h`, `cerf-qt/host_power.h`,
  `cerf-qt/cerfman/enterprise_model.h`
