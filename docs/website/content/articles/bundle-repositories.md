# ROM bundle repositories

Some people host "ROM bundle repositories" - a static HTTP storage in a format the emulator reads which lets you to download their ROMs.

The Device Manager lets you also to update ROMs if they have anything new in their configuration, metadata or if their ROM got updated.

!!! note
    A repository usually supports only the latest emulator version. If you update your ROMs too early you might get your devices bricked
    until you update the emulator itself.

## Finding and adding a repository

CERF distributes no ROMs out of box.

There are chances you might run into a community hosted repository. Seek those on our [Discord server](/discord).

!!! warning
    Be careful - someone might host a malicious repository. If there are any vulerabilities in the code we are unaware of, a hacker might expose those and obtain an access to your device. Add only verified sources.

To add a repository:

1. Click **New**, then click **Download ROMs**.
2. Click **Sources…**.
3. Click **Add…**.
4. Type the base URL of the repository, for example `https://example.com/bundles`, and click **OK**.
5. Click **OK** in the **Bundle repositories** window.

Fun fact: you can't edit a bundle repository and nobody wants to develop that "feature". So you have to delete and add it again if you do a typo.

## Running your own repository

If you want to be a pirate - use the toolchain at [gweslab/bundles](https://github.com/gweslab/bundles). Improvements are welcome too.

## Copyright removal

If you are a serious person, a representative of some company and want your company's ROMs removed - we can't help with that. 
We don't host those ROMs. But we give to both you and a repository owner a tool to contact each other. 

Click **Contacts** in the emulator's "Download ROMs" window to obtain hoster's email address.

You can also read that data raw: append ``/manifest.json`` to the repository URL and find `abuse_email` top-level property.
