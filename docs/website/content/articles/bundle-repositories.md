# ROM bundle repositories

The launcher installs and updates ROMs from bundle repositories. A bundle repository is a set of
static files on an HTTP server. The launcher reads `<repository-url>/manifest.json`, lists the
devices in it, and downloads one archive for each device over HTTPS. A repository needs no account,
no API and no code on the server.

## Finding and adding a repository

CERF distributes no ROMs out of box. There are chances you might run into a 
community hosted repository. Seek those on our [Discord server](https://discord.gg/QREE9Y2v2d).

To add a repository:

1. In the launcher, click **New**, then click **Download ROMs**.
2. Click **Sources...**.
3. Click **Add...**.
4. Type the base URL of the repository, for example `https://example.com/bundles`, and click **OK**.
   Do not type the path to `manifest.json`.
5. Click **OK** in the **Bundle repositories** window.

The launcher enables a new repository. To disable a repository, clear its tick. To remove a
repository, select it and click **Delete**.

CERF keeps the list in `cerf.json` next to `cerf.exe`, under the `bundle_repositories` key.
[The configuration files](cerf-json.md) describes this file.

## What the launcher does with a repository

- The launcher downloads the manifest of each enabled repository. It merges the manifests into one
  list in **Download ROMs**. Two repositories can publish a device under the same name, and you can
  install both.
- Each manifest entry contains the full `cerf.json` of its device. The launcher therefore knows the
  board, the OS, the screen size and the notes before it downloads the ROM.
- An installed device records the repository that it came from. When the archive hash in the
  manifest changes, the launcher offers an update. When only the `cerf.json` in the entry changes,
  the launcher writes the new `cerf.json` and does not download the ROM again.
- Each entry gives the compressed size and the unpacked size of the archive. It also gives a SHA-256
  hash, and the launcher compares the downloaded archive with that hash.

## Running your own repository

To run your own repository, use the toolchain at
[gweslab/bundles](https://github.com/gweslab/bundles). The toolchain packs a ROM tree into archives,
makes `manifest.json`, and publishes the result. The same place has the contract that a repository
must follow, and its documentation.

## Copyright removal

The CERF project does not host, control or audit bundle repositories. It cannot remove anything from
them.

Each repository can publish its own contact address for removal requests. The address is optional.
The launcher shows the addresses in the **Copyright removal** window. This window opens from the
**Download ROMs** window and from the confirmation that the launcher shows before a download. It
lists each repository of your configuration with its address. A repository also publishes its
address in the top-level `abuse_email` field of its `manifest.json`.

If a repository publishes no contact address, send your request directly to its operator or to its
host.
