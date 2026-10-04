# Getting the guest online

There are several ways to put a Windows CE guest on the internet
- **guest additions** built-in driver (available out of box in any Guest Additions run)
- an **NE2000 Ethernet PC Card** bridged (recommended)
- a **dial-up modem** over an emulated phone

## Guest Additions Ethernet

!!! note

    Windows CE 2.0 needs a [network stack installed](#windows-ce-20-network-stack) for this to work

Boot a device with Guest Additions enabled. A virtual Ethernet adapter will appear and will always work
even on if a device has no hardware capabalities for internet interface, or CERF doesnt emulate one there.

## NE2000 PC Card

**1.** Insert the **NE2000 Ethernet** card into a free PC Card slot.

!!! note

    If a *PC Card driver not found* window appears, the guest has no NE2000 driver (or it is a CERF
    emulation bug) - this path will not work on that ROM.

    If you are using Windows CE 2.0, it needs a [network stack installed](#windows-ce-20-network-stack) -
    otherwise you will receive the same error.

**2.** Configure it, which depends on the guest:

=== "Desktop CE ≥ 4"

    Usually auto-configured with no prompt - a connection tray icon may appear, and you are online.

=== "Desktop CE ≤ 3 and Pocket PC"

    An **NE2000 Compatible Ethernet Driver Settings** window appears. Leave everything at its
    default (obtain an IP address via DHCP), click **OK**, and a tray icon may appear. The
    connection should work from there.

=== "Windows Mobile"

    The card is detected automatically but needs the network assigned. Go to **Settings &rarr;
    Connections** tab **&rarr; Connections**, and set **My network card connects to** to **The
    Internet**. On newer versions, after opening **Connections**, go to **Advanced &rarr; Select
    Networks** and change everything to **My Work Network**.

## Windows CE 2.0 network stack

Windows CE 2.0 **lacks a network stack** and there is no official way to receive one.

However, you can install a **[Network Service Pack for Windows CE 2.0 made by HPC:Factor](https://www.hpcfactor.com/qlink/?linkID=31)**.

A *soft reboot* might be needed.

## Dial-up

### 1. Attach a modem in CERF

Pick whichever suits your board, and attach the modem in CERF:

- **Built-in modem** - click the **COM** icon in the status bar and choose **Insert &rarr; Serial
  Modem**.
- **PC Card modem** - click any PC Card slot in the status bar and choose **Insert &rarr; Serial
  Modem**.

### 2. Open the modem connection app in the guest

The path is nearly the same on every Windows CE version; the differences are only where the applet
lives.

=== "Desktop CE ≤ 3"

    **Start &rarr; Communications &rarr; Remote Networking**.

    ![Remote Networking in the Start menu](/assets/articles/networking/remote-networking-menu-ce2.png)

=== "Desktop CE ≥ 4"

    **Start &rarr; Settings &rarr; Network and Dial-up Connections** - it opens the same window as
    on older CE.

    ![Network and Dial-up Connections](/assets/articles/networking/network-ce6.png)

=== "Pocket PC"

    **Start &rarr; Settings &rarr; Connections** tab **&rarr; Modem**.

    ![The Modem settings on Pocket PC](/assets/articles/networking/modems-ppc2000.png)

=== "Windows Mobile"

    **Start &rarr; Settings &rarr; Connections** tab **&rarr; Connections**. On Windows Mobile 6.5+
    the Start menu is full-screen, but the path is identical.

    ![Connections on Windows Mobile](/assets/articles/networking/connections-wm6.png)

### 3. Make a new connection

Open **Make New Connection** (the modem one) and fill it with stock values - for the phone number,
just enter `1` and save.

For the device, pick the modem: usually **Hayes Compatible on COM1**, or **CERF Virtual Modem** if
it is a PC Card. The exact name varies by guest; if in doubt, guess - there is rarely more than one.

=== "Desktop CE"

    ![Making a dial-up connection on desktop CE](/assets/articles/networking/setup-dialup-ce2.png)

=== "Pocket PC"

    ![Making a dial-up connection on Pocket PC](/assets/articles/networking/setup-dialup-ppc2000.png)

=== "Windows Mobile"

    ![Making a dial-up connection on Windows Mobile](/assets/articles/networking/setup-dialup-wm6.png)

### 4. Dial and go online

=== "Desktop CE"

    Double-click your connection, dial, and you are ready to browse.

    ![Dialling on desktop CE](/assets/articles/networking/dial-ce2.png)

=== "Pocket PC"

    Open the **Connections** link in the Modem applet, then tap your connection and dial.

    ![Dialling on Pocket PC](/assets/articles/networking/dial-ppc2000.png)

=== "Windows Mobile"

    Just start browsing - the first request prompts you to dial.
