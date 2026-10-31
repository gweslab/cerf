---
hide:
  - navigation
---

# Download

<div class="cerf-download" markdown>

=== ":fontawesome-brands-windows: Windows"

    Open PowerShell and paste this command:

    ```powershell
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072
    iex ((New-Object Net.WebClient).DownloadString('https://cerf.cx/win_installer.ps1'))
    ```
    !!! warning "Supported platforms"

        **Windows 7 x86 and newer** is required.

    [:fontawesome-solid-code: Installer Source Code](https://github.com/gweslab/cerf/blob/main/installers/windows_installer.ps1)

=== ":fontawesome-brands-linux: Linux"

    Open a terminal and paste this command:

    ```sh
    curl -fsSL https://cerf.cx/unix_installer.sh | sh
    ```

    !!! warning "Supported platforms"

        Known supported platforms: Ubuntu 26.04, Debian testing, Arch, Fedora 44, openSUSE Tumbleweed

        Linux builds are only x86-64. [Send feedback](https://cerf.cx/feedback) if you want ARM64 too.

    [:fontawesome-solid-code: Installer Source Code](https://github.com/gweslab/cerf/blob/main/installers/linux_macos_installer.sh)

=== ":fontawesome-brands-apple: macOS"

    Open Terminal and paste this command:

    ```sh
    curl -fsSL https://cerf.cx/unix_installer.sh | sh
    ```
    !!! warning "Supported platforms"

        Only modern ARM64 CPUs are supported.

    [:fontawesome-solid-code: Installer Source Code](https://github.com/gweslab/cerf/blob/main/installers/linux_macos_installer.sh)

=== ":fontawesome-brands-android: Android"

    [:fontawesome-solid-download: Download APK](/cerf_latest_arm64.apk){ .md-button .md-button--primary }

    !!! warning "Supported platforms"

        Only for ARM64.

</div>

## Manual download

If you can't or don't want to use an installer, download the archive for your platform from the [latest release on GitHub](https://github.com/gweslab/cerf/releases/latest).

You might need to read the source of your platform's installer if it needs additional packages. macOS will need a sandbox wokaround to launch anything you download from browser.

## Unstable builds

If you have CE Runtime Foundation installed you can update over the air - switch to unstable builds at:

**Emulator Settings** → **Update Channel** → **Unstable Releases**

Find raw archives at [:fontawesome-solid-list: GitHub Artifacts](https://github.com/gweslab/cerf/actions/workflows/build.yml?query=branch%3Amain+is%3Asuccess) Registration is required.
