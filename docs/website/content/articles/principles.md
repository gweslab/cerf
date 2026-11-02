# Principles

The emulator under the hood - decomposing author's personal choices; the emulator story; high level architecture facts

!!! note
    Page is under construction

## Submodules

The emulator consists of in-house parts that have some long story.

- [`dz333n/libservicelocator`](https://github.com/dz333n/libservicelocator) - a service locator pattern implementation. It was an experiment in C++ code, but now it's gluing the whole emulator. Seems to work so far.
- [`libCerfEngine`](https://github.com/gweslab/libCerfEngine) - a dynamic recompiler. JIT. Parses guest instructions, turns them into intermediate representation, then turns that into host instructions. Gives you abstractions to define the rest.
- [`libCerfCore`](https://github.com/gweslab/libCerfCore) - the whole emulator. Only lacks a UI.
- [`gweslab/cerf`](https://github.com/gweslab/cerf) - root repository. Contains all the UIs, this website source code and other stuff.

## Why it is Windows CE only?

You would think that if it's an emulator why it is exacly bound to Windows CE in all those articles. Worse, it's known that this emulator runs JLime Linux and NetBSD on appropriate devices.

Of course that's by conception, it was meant to be a Windows CE emulator and has grown from that. The primary shortcut we have - for 99% of ROMs we skip the whole boot machinery part. No ROM masking, no bootloaders, we just parse ROM containers (with a 91% success rate, because that code is broken and we still lack knowledge how OEM itself has intended to place ROM data in some scenarios, we just guess it until it works), place those in RAM and invoke the kernel's entry point. That just works somehow.

In rare cases you might be met with, for example, OEM's settings app showing garbage/blank values. That's the drawback. Because either on a real device a bootloader stores data there in a specific format, that's how you get blank data (CERF stubs that address) or because CERF places ROM where actual bootloader stores special data, which gives you garbage.

The Guest Additions driver is a ROM mod that can also exist only in a logic that parsers this ROM. A different operating system has a different ROM container or whatever it uses to boot.

The reason behind this is not just a shortcut to get stuff done more quickly, it's also that dumping ROMs is super hard, at least it was at the first developemnt stages. Thanks to everyone who participates in ROM preservation - just some time ago a Windows CE 1.0 ROM available online was a dream, not something regular.

## CE Runtime License Introduction

The emulator is using a custom license based on ``PolyForm Noncommercial``.

My vision is that this project is a historical preservation effort and must not be used for anything "enterprise". I also can't imagine where you can use a 1996 machine emulator for enterprise. If the conception of your business aligns with our historical preservation goals, for example you are doing an old device showcase or something in that order, that's something I appreciate a lot and in our discussion you will receive a permissions for free and fast. However, if your goal is replacing industrial hardware with my software, I believe that's a heavy *commercial* job that you are paid for and since we are both doing this job - we must align somehow.

Oh, and I didn't forget about the community: if there a *hypothetical* enterprise version of the emulator being developer in parallel - all the new emulation code, unless it's under heavy NDA, - is going into the code tree. So all the **commercial outcome** is **available for everyone** in a following emulator release. 

## Project story

This project originates from WCECL, a compatibility layer I was working on back in 2019. It was supposed to be a WinAPI-to-WinAPI forwarder: from mobile APIs straight into desktop APIs. At some point with help of external contributors it was able to run x86 versions of solitaire and just a few super simple apps. The conception was doomed from the beginning because WinCE apps everyone cares about were built for SH3/MIPS/ARM platforms, and at that point of time I got busy. I had no time and no wish to write even a simple interpreter variant. That's how WCECL has been fading away.

At the beginning of 2026 I was testing some AIs - I actually have never used LLMs before. I was wondering if an LLM could bring an interpreter to WCECL and run ARM apps. To my surprise it actually was able to do that. It printed an ARMv4 interpreter in just 20 minutes and ran the same solitaire but the ARM version. Project has been renamed to CERF and that was a fun but also a garbage vibecode experiment that has ended because it appears the conception was doomed again. I wanted it to run the whole shell but vibecoding an emulator is actually hard. That was a corruption mess and I hit the limit I forgot about. You can't run the whole operating system inside a single process because WinAPI gives you some limits. That's how the project has died again.

At that point I have decompiled parts I've never managed earlier and a shady thought has been tickling my mind that giving up without an artifact is bad. Gathering my learnings about ROM containers, how internals works, how drivers work and how exactly to wire a dumb GPIO through JIT into a peripheral code and back - a new version of CERF has been done, but now it's a hardware level emulator. The goal was to build MS Emulator clone that supports a few more light devices and throw it away. 

However, the story doesn't end here. There were people interested in bringing more devices to the emulator. The project has actually received support which I'm thankful for and will always be. We had events with some community members - we spent weeks figuring out how to dump a specific device and bring it to the emulator. The 7.0-8.0 version period took 4 months and brought barely anything new for users - I've been doing my own JIT barely from scratch, rewriting all the vibecode warcrimes and doing an actual nice software. I might attempt to predict that the actual evolution stop point is here - I can't imagine what else we can rewrite, and the future is now purely adding more devices until there will be no reason to do so.
