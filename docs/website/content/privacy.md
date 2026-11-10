---
hide:
  - navigation
---

# Privacy Policy

This policy covers CE Runtime Foundation, the emulator by Yaroslav Kibysh.

CE Runtime Foundation has no accounts, no ads and no analytics. It does not collect personal data, and it does not sell or share data with anyone.

## Data on your device

- **Devices.** The ROM images that you add, the settings of each device, its saved state and its storage images stay in the app storage.
- **Files that you pick.** When you create a device, the app copies the ROM files that you pick into the folder of that device. If you turn off "Copy files to device directory", the app uses them where they are. Other files that you pick, for example a shared folder, stay where they are.
- **Microphone audio.** When an emulated device uses its sound input, the app gives it the audio of your microphone. The app does not record the audio and does not send it anywhere. On Android, the app asks for the microphone permission when you start a device.
- **Screenshots.** On a phone, a screenshot that you save from the emulator menu goes to your gallery, in Pictures/CERF. Other apps that can read your photos can read it.
- **Logs and crash reports.** The app writes them into its app storage. They leave your device only when you share them, to the app that you pick, or in an Android backup.
- **Android backup.** Android can include the app's data in the backup of your phone. When the data is 25 MB or less, Android uploads it to your Google Drive, where your Google account protects it. Android can also copy the data to a new phone when you move to it. The backup settings of your phone control both.

## Network connections

The app connects to the servers below. Each request carries your IP address, the program name and version (`CERF/<version>`) and the language setting of your system. Each server handles the request under its own privacy policy.

- **GitHub**, to check for a new release, to download it on a computer, and to show the open issues on the Feedback page. The copy from Google Play has no Feedback page. These connections use HTTPS.
- **cerf-bundles.dz3n.net** (Cloudflare R2), to check for a new build on the unstable update channel, and to download it on a computer. These connections use HTTPS.
- **The bundle repositories that you add, and the servers that their lists name**, to list and download device bundles. A repository list can send a download to another server. Each of these connections uses HTTPS or HTTP, as its address says. The app has no bundle repository by default.

When the network of an emulated device is on, the software inside that device can reach the internet through your connection, as a web browser does.

The links in the app open in your browser. This website uses Google Analytics cookies only after you accept them in its cookie banner.

## Discord Rich Presence

On a computer, you can turn on Discord Rich Presence in the settings. It is off by default. When it is on, the app sends its window title, the Windows CE version of the running device and the start time of the session to the Discord app on the same computer. The window title holds the device name, its operating system and the program version. Discord then shows them on your profile.

## Deleting your data

The app keeps no data about you on a server. To remove a device and its files, delete the device in the app. On a phone, uninstall the app to remove its data from the phone. The screenshots in your gallery stay. Delete them in your gallery app. A copy in your Google Drive backup can remain, and Android restores it when you install the app again. On a computer, the app keeps your devices, saved states and settings in its installation folder. To remove them, delete that folder.

## Contact

For a question about privacy, write to [cerf.commercial@yaroslavkibysh.com](mailto:cerf.commercial@yaroslavkibysh.com).

Last updated: November 10, 2026.
