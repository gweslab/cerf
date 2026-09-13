# PC Cards and serial ports

Windows CE handhelds got most of their hardware through the PC Card slot, and thousands of cards
were made for it. CERF emulates the slot itself, the way the board wires it.

What goes into it is a card modeled as one specific piece of hardware. The guest binds its own
driver to that card and drives it. The cards below are the ones that exist today. Anything else
cannot be inserted.

Cards go in and come out while the guest is running. A slot is an icon in the status bar.

## NE2000 Ethernet

An Ethernet card, and the one most CE ROMs carry a driver for. The guest gets an address and its own
TCP/IP stack goes online.

Configuration differs on every CE version. [Getting the guest online](networking.md) covers each one.

## Compact Flash

Storage. Insert an image you already have, or let CERF build one. To build one: pick the files you
want on the card, then choose FAT16 or FAT32. CERF asks for a card size and writes the files in.

The result is `CF.IMG` next to `cerf.exe`, and it stays there for next time. A device bundle can ship
cards of its own, and those appear at the top of the insert menu.

## Serial Modem PC Card

A modem that answers the guest's `AT` commands, takes the call and speaks PPP. Dial-up networking
then reaches the internet over an emulated phone line.

The dial-up procedure is in [Getting the guest online](networking.md).

## Serial Port Forwarder

Bridges the guest's serial port to a real serial port on the host. Bytes, baud rate and control lines
pass through. The insert menu lists the ports it finds on your machine.

With a virtual COM port pair, the guest can reach a desktop that runs ActiveSync. That path has its
own guide: [Connecting to ActiveSync](activesync.md).

## HP Palmtop VGA (F1252A)

An external display card. Its monitor output arrives as a window on the host.

It works on the HP Jornada series, and is verified on the Jornada 720. There, the stock ROM detects
the card and loads its own driver for it. The guest gets HP's own control panel with it.

<div class="cerf-wall cerf-wall--pair" markdown>

![The HP VGA control panel on a Jornada 720](/assets/articles/pc-cards/hp-vga-control-panel.png)

![The external VGA output in its own host window](/assets/articles/pc-cards/hp-vga-output.png)

</div>

## Built-in serial ports

A board with a serial port of its own gets the modem and the forwarder without spending a card slot.
The port has its own status-bar icon, and the same menu behind it.
