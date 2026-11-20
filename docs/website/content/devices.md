---
hide:
  - navigation
  - toc
---

!!! example "This page is in sync with the code tree - a stable CERF release might support less boards."

!!! warning "It's not a hardware database"
    This is a collection of metadata the emulator cares about. Some hardware facts are false here. Some data here might be a best-effort guess, some data goes from Linux/NetBSD/HPC:Factor/old aricles online.

!!! question "Why boards repeat?"
    We have a hierarchy of how boards are defined. **It starts with a family**. A family defines everything a single board has shared accross all members. Unusual family names here appear from guest's PDB paths which is the BSP name an OEM built it with.

    Members represent here different real-life models. Sometimes we merge a few members into a single one if it doesn't break a representation.

    Boards displayed here either **boot** or boot **without a hardware deviation modeling** (the software is fine with it). Since there are many ROMs we never obtained - emulator itself also lets users to add boards with unknown support. We only guess a corresponding board type still should boot based on public information or on Linux/NetBSD implementations.

<div class="cerf-boards" markdown>

{boards_table}

</div>
