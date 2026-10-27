# Contributing to CE Runtime Foundation

> [!IMPORTANT]
> This document is not finished yet - expect this content to change.

Thank you for your interest! Any features you add will be attributed to you in the changelog and in the About window!

## Working from a fork

Only the author can push to the CERF repositories. To send a change, work in your own forks on GitHub.

1. Fork `gweslab/cerf`, `gweslab/libCerfCore` and `gweslab/libCerfEngine`. If you change the service locator, also fork `dz333n/libservicelocator`.
2. Clone your fork of `cerf`. Then do the steps in [Building](../README.md#building). `tools/dev_setup.py` initializes the submodules.
3. Point each library at your fork:

   ```
   git -C libCerfCore remote set-url origin https://github.com/<you>/libCerfCore.git
   git -C libCerfEngine remote set-url origin https://github.com/<you>/libCerfEngine.git
   ```

4. Push each changed library to your fork before you push the `cerf` commit that points at it.
5. Open a pull request in each changed repository.
6. When the author merges the library pull requests, update your `cerf` pull request to point at the merged library commits.

## Low-quality contributions are **forbidden**

A low-quality contribution might be one of these:

- It damages the code quality or the emulator quality, suggesting that the author doesn't understand programming principles or doesn't want to respect those and the project rules
- It leads to unhealthy communication patterns with a reviewer (e.g., psychological manipulation, persuading to merge shitty code into the tree, etc.) and endless review cycles.
- The author doesn't understand the code he wrote, doesn't know what a code editor is (e.g., VS Code) or doesn't use one, and doesn't know how to use GitHub or Git itself. A general understanding is absent.
- You want other contributors/reviewer to give you lessons and teach you how to code, or your failures form a shape where a reviewer has to teach you step by step. Programming lessons are paid.

Of course, this is all subjective - you may have a worse level of understanding or even a better one than the author of the project. We are talking specifically about unhealthy attempts to contribute to the project. It's fine when you make a mistake due to a lower level of experience. It's bad when you vibe code and can't explain the output.

> [!CAUTION]
> **You will be banned from all community and project resources** if you attempt this.

If you feel the itch to vibe code an enhancement to the emulator that suddenly appears to be working, you can create a pull request as a draft and leave it there with explicit text that it is done badly and doesn't deserve a review. Maybe someone will decide one day to pick it up, take your code, maybe co-author you, and finish your feature. But do NOT attempt to smuggle this as a proper pull request and lie about your understanding. This is easy to detect, and you won't be happy to get a ban. 

This is more about being a sane community member and a sane developer rather than about any kind of skills.

## UI, pictures, complex changes
 
Some stuff like new UI elements which have no example in tree should be discussed first with the project owner and other developers. Discord is the best communication channel for that. Same goes for any other architectural change you think you shouldn't do yourself. Same goes for e.g. ``cerf.json`` schema changes which we'll support forever - that's a careful decision. It's OK if you see a good example in the tree and you are confident in your change. If you are not - go ahead and discuss with others.
