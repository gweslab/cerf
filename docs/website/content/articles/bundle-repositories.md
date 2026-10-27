# ROM bundle repositories

The emulator installs and updates ROMs from bundle repositories. A bundle repository is a set of
static files on an HTTP server. The emulator reads `<repository-url>/manifest.json`, lists the
devices in it, and downloads one archive for each device over HTTPS. A repository needs no account,
no API and no code on the server.

## Finding and adding a repository

CERF distributes no ROMs out of box. There are chances you might run into a 
community hosted repository. Seek those on our [Discord server](https://discord.gg/QREE9Y2v2d).

To add a repository:

1. Click **New**, then click **Download ROMs**.
2. Click **Sources…**.
3. Click **Add…**.
4. Type the base URL of the repository, for example `https://example.com/bundles`, and click **OK**.
   Do not type the path to `manifest.json`.
5. Click **OK** in the **Bundle repositories** window.

A new repository is enabled. To disable a repository, clear its tick. To remove a repository,
select it and click **Delete**.

CERF keeps the list in the `cerf.json` of its installation folder, under the `bundle_repositories` key.
[The configuration files](cerf-json.md) describes this file.

## What the emulator does with a repository

- The emulator downloads the manifest of each enabled repository. It merges the manifests into one
  list in **Download ROMs**. Two repositories can publish a device under the same name, and you can
  install both.
- Each manifest entry contains the full `cerf.json` of its device. The board, the OS, the screen size
  and the notes are therefore known before the ROM downloads.
- An installed device records the repository that it came from. When the archive hash in the
  manifest changes, an update is offered. When only the `cerf.json` in the entry changes, the new
  `cerf.json` is written and the ROM is not downloaded again.
- Each entry gives the compressed size and the unpacked size of the archive. It also gives a SHA-256
  hash, and the downloaded archive is compared with that hash.

## Running your own repository

To run your own repository, use the toolchain at
[gweslab/bundles](https://github.com/gweslab/bundles). The toolchain packs a ROM tree into archives,
makes `manifest.json`, and publishes the result. The same place has the contract that a repository
must follow, and its documentation.

## Copyright removal

The CERF project does not host, control or audit bundle repositories. It cannot remove anything from
them.

Each repository can publish its own contact address for removal requests. The address is optional.
The **Copyright removal** window shows the addresses. This window opens from the **Download ROMs**
window. It lists each repository of your configuration with its address. A repository also publishes its
address in the top-level `abuse_email` field of its `manifest.json`.

If a repository publishes no contact address, send your request directly to its operator or to its
host.
