---
hide:
  - navigation
---

!!! warning
    This draft is intended to replace the primary download page for CERF 8.0 release. These installers do work, but always pick an unstable build option.

# Download

<div class="cerf-download" markdown>

=== ":fontawesome-brands-windows: Windows"

    Open PowerShell and paste this command:

    ```powershell
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072
    iex ((New-Object Net.WebClient).DownloadString('https://cerf.cx/win_installer.ps1'))
    ```

    [:fontawesome-solid-code: View Source](https://github.com/gweslab/cerf/blob/main/installers/windows_installer.ps1){ .md-button }

    !!! warning "Supported platforms"

        **Windows 7 x86 and newer** is required.

=== ":fontawesome-brands-linux: Linux"

    Open a terminal and paste this command:

    ```sh
    curl -fsSL https://cerf.cx/unix_installer.sh | sh
    ```

    [:fontawesome-solid-code: View Source](https://github.com/gweslab/cerf/blob/main/installers/linux_macos_installer.sh){ .md-button }

    !!! warning "Supported platforms"

        Known supported platforms: Ubuntu 26.04, Debian testing, Arch, Fedora 44, openSUSE Tumbleweed

        Linux builds are only x86-64. [Send feedback](https://cerf.cx/feedback) if you want ARM64 too.

=== ":fontawesome-brands-apple: macOS"

    Open Terminal and paste this command:

    ```sh
    curl -fsSL https://cerf.cx/unix_installer.sh | sh
    ```

    [:fontawesome-solid-code: View Source](https://github.com/gweslab/cerf/blob/main/installers/linux_macos_installer.sh){ .md-button }

    !!! warning "Supported platforms"

        Only modern ARM64 CPUs are supported.

=== ":fontawesome-brands-android: Android"

    [:fontawesome-solid-download: Download the APK](/cerf_latest_arm64.apk){ .md-button .md-button--primary }

    !!! warning "Supported platforms"

        Only for ARM64.

</div>

## Manual download

If you can't or don't want to use an installer, download the archive for your platform from the [latest release](https://github.com/gweslab/cerf/releases/latest).

## Unstable builds

[:fontawesome-solid-list: Build list](https://github.com/gweslab/cerf/actions/workflows/build.yml?query=branch%3Amain+is%3Asuccess){ .md-button }
