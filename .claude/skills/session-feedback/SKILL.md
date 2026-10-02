---
name: session-feedback
description: Propose a durable rule from a failure in this session, for the user to approve.
---

# Session Feedback

A future agent starts with no memory of this session. When that agent walks into the same wall you hit today, an entry in the durable documents is what stops it. That is the only reason to add one.

Keep the bar high. The documents work because each line earned its place, and every weak line makes the next agent read more to learn less.

## The test

Propose an entry only when all of these are true:

- **A future agent repeats the failure.** You hit a wall today, and nothing in the current documents stops the next agent from hitting it.
- **The documents do not say it.** Not in CLAUDE.md, not in any `agent_docs/` page, not in user memory, not even approximately.
- **You confirmed it.** You reached the situation and saw the outcome. A hunch does not qualify.
- **It stays true.** The entry reads the same in a year. A fact about one function, one bug, or today's tree does not.
- **It saves hours.** Minutes do not justify a line that every future agent must read.

## Where the entry goes

| The entry is about | Target |
|---|---|
| The project - rules, architecture, subsystems, workflow | `agent_docs/<page>` or `CLAUDE.md` |
| This machine or this user - local paths, host tooling, personal preference | User memory |

Project knowledge never goes into user memory. CLAUDE.md § Documentation Targets names this skill and redirects such an entry to the matching `agent_docs/` page.

## The highest-value category: subsystem map gaps

Ask this first: did `agent_docs/subsystems.md` mislead you, omit something, or cost you time to find a subsystem that is basic project knowledge? More agent hours die here than anywhere else. Two triggers, and both usually qualify:

- **You hunted for a subsystem that already existed.** One line in `subsystems.md` would have ended the search. That line is missing.
- **You built or reshaped a subsystem.** A new agent expects it in basic project knowledge, and `subsystems.md` does not mention it. Add what it is, where it lives, and what it owns, in the voice of its neighbors.

File paths and subsystem names belong in these entries, because they are the navigation target. Offsets, log lines, and function internals still do not.

## What does not qualify

- Session trivia: today's bug in X, the missing null check in Z.
- Anything that rots: IDA offsets, log excerpts, file:line pointers, function names, commit hashes, struct layouts. These live in code comments or investigation documents.
- A restatement of a rule the documents already carry.
- Speculation. When you would hedge it with "I think" or "seems like", drop it.
- Padding written because you feel you owe the user an entry.

## Style

Write the principle, not the case study. The rule carries the meaning alone, and the thing that triggered it today disappears.

- Wrong: "`imx51_nfc.cpp` returns 0 from its default case, so the guest read garbage for two hours before anyone saw it."
- Right: "A register switch whose default returns a value hides an unmodelled path. An unimplemented register must fatal, so the gap surfaces at the first touch."

- Wrong: "The Jornada 720 hangs at boot until SA-1111 register 0x1800 reads back 0x40."
- Right: "A guest that spins forever on one peripheral register waits for a bit the emulation never sets. Find that bit in the datasheet before you change anything on the guest side."

- Wrong: "cerf.log line 'EmulatedMemory::Translate unmapped 0x4A000000' means the INTC is missing."
- Right: "An unmapped-MMIO halt names the peripheral block by its address. Decode that address against the SoC memory map before you suspect the driver."

Do not use offsets, log lines, filenames, or the words "today I found". The claim must read the same five years from now.

## Protocol

1. **When nothing new qualifies**, a rule for the failure already exists and did not stop you, so that rule is broken. Never reply `Nothing to add this session.` Reply that the existing rule needs an improvement. Then give it: the document and section, the line as it stands, and the replacement text.
2. **When something qualifies**, write each entry as one bullet in the voice of its neighbors: a short bold title, an em-dash, one abstract sentence.
3. Under each bullet add one line, `  ↳ target: <document> § <section>`. This line guides the review and never enters the document.
4. Propose only what you can defend. One strong entry beats three weak ones.
5. **Stop. Edit nothing.** Wait for the user.

## After the review

- When the user approves, add the approved entries to their targets in the matching style. Drop the `↳ target` line.
- When the user approves some, add those and drop the rest without comment.
- When the user rejects or rewrites an entry, take that as final and do not pitch it again.
- When the user says nothing conclusive, drop all of it.

## Commit

Once the edits land on disk, run `Skill(leak)` and `Skill(simple-english)` over the diff of the edited documents. Fix what they flag. Only then ask in one line whether to commit. Then stop and wait.

When the user approves, invoke `Skill(commit)` and follow it. That skill owns staging and message style.
