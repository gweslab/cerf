CE Runtime Foundation for macOS

If you downloaded the app with a web browser - macOS blocks it, or runs it
from a read-only copy that cannot save your devices and settings.

Before you open the app, fix this by by running this command once in Terminal

    xattr -dr com.apple.quarantine EMULATOR_DIRECTORY_PATH
