# Trouble with the touch screen or mouse

Most CERF boards are touch devices, and the guest's pointer behaviour is not always what a modern
mouse leads you to expect. If taps do not land, this page is the checklist.

## Taps do not register, or feel unreliable

Emulation is not free, and the guest's touch driver samples the pen on its own schedule. A fast
modern click can be shorter than the guest ever looks - it presses and releases between two of the
guest's samples, and the tap is simply missed.

If taps are dropping:

- **Hold the click a moment longer.** A deliberate press-and-hold gives the guest's driver time to
  see the pen down and the pen up.
- **Wiggle slightly while holding.** A tiny movement produces extra samples and reliably wakes a
  driver that a perfectly still tap did not.
- **Slow down.** If the machine is under load - mid-boot, or a heavy app - the guest is getting
  fewer moments of CPU, so give each tap more time.

None of this means the tap was wrong; it means the pen was down for less guest-time than the driver
needed.

## Guest Additions pointer does nothing in some apps

With [Guest Additions](features.md#guest-additions) on, CERF drives an absolute pointer straight
into the guest - and that is the right thing almost everywhere. But some apps do not read the
system pointer at all: they open the **touch screen directly** and read its raw stream.

The clearest case is the **first-boot welcome wizard's screen calibration** - the "tap the crosses"
step. It reads the raw touch panel on purpose, so the Guest Additions pointer flows right past it
and nothing happens.

The fix is to hand those apps the panel they expect:

1. Open the **pointer source** switch in the status bar.
2. Switch from the Guest Additions pointer to the board's **stock touch** source.
3. Do the calibration (or use the app), then switch back if you like.

This is why the pointer source is switchable at all - a calibrator wants the real panel, everything
else is happier with the host pointer.

## The pointer is captured and will not leave the window

On a board whose stock input is a **relative mouse** rather than a touch panel, CERF locks the host
pointer to the window while that source is active - a relative device has no absolute position to
map a free cursor onto.

**Tap the host key to release the pointer.** Tap it again to give the input back to the guest. The
host key is Right Ctrl, and **Settings** in the launcher gives it to another key.
