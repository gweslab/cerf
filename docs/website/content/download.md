---
hide:
  - navigation
---

# Download

<div class="cerf-download" markdown>

=== ":fontawesome-brands-windows: Windows"
    !!! question "**Windows 7 x86 and newer** is required."

    1. Open **PowerShell**
    2. Paste this command:

        ```powershell
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072
        iex ((New-Object Net.WebClient).DownloadString('https://cerf.cx/win_installer.ps1'))
        ```
    3. Press **Enter**
    4. Follow on-screen instructions

=== ":fontawesome-brands-linux: Linux"
    !!! question "Supported CPUs: **x86-64, ARM64**"

    1. Open **a terminal**
    2. Paste the following command:

        ```sh
        curl -fsSL https://cerf.cx/unix_installer.sh | sh
        ```
    3. Press **Enter**
    4. Follow on-screen instructions

=== ":fontawesome-brands-apple: macOS"
    !!! question "Supported CPUs: **ARM64**"

    1. Open **Terminal**
    2. Paste this command:

        ```sh
        curl -fsSL https://cerf.cx/unix_installer.sh | sh
        ```
    3. Press **Enter**
    4. Follow on-screen instructions

=== ":fontawesome-brands-android: Android"
    !!! question "**Android 10 (ARM64) and newer** is required."

    [:fontawesome-brands-google-play: Google Play](https://play.google.com/store/apps/details?id=cx.cerf){ .md-button .md-button--primary }

</div>

!!! abstract "[Non commercial use only](/license-details)"

[:fontawesome-solid-code: Installers Source Code](https://github.com/gweslab/cerf/tree/main/installers)


## Manual download

If you can't or don't want to use an installer, download the archive for your platform from the [latest release on GitHub](https://github.com/gweslab/cerf/releases/latest).

You might need to read the source of your platform's installer if it needs additional packages. macOS will need a sandbox wokaround to launch anything you download from browser.

## Unstable builds

You can obtain an unstable build in a few ways:

=== "Android"
    Join open testing and install the emulator from Play Store

    [:fontawesome-brands-google-play: Google Play open testing](https://play.google.com/apps/testing/cx.cerf)

=== "Deskop / Installer"
    The installers above work for unstable builds too. Just pick the one. It's the recommended path for desktops for a clean unstable build installation.

=== "Desktop / Over the air"
    If you have CE Runtime Foundation installed you can update over the air - switch to unstable builds at:

    **Emulator Settings** → **Update Channel** → **Unstable Releases**

=== "Manual download"
    Find raw archives at [:fontawesome-solid-list: GitHub Artifacts](https://github.com/gweslab/cerf/actions/workflows/build.yml?query=branch%3Amain+is%3Asuccess). Registration is required.
