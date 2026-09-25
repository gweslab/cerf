---
name: tracking
description: The user invokes `/tracking` to manage a cross-session findings document under `docs/ai_checklists/` that preserves crucial data (findings, instrumentation, do-not-rediscover maps, UI interaction gates / repro paths, bans, mandatory-read sets) so a fresh agent does not re-discover or re-destroy proven work. Subcommands - `restore` (re-read the full document + its mandatory files), `create` (start a new document), `update` (append a timestamped per-session block), `compact` (archive full history to `docs/ai_checklists/pre-compact/<name>.md`, then shrink the live doc under a one-read ceiling). The user types the subcommand or omits it (the agent deduces it from context and announces the deduction; `compact` is explicit-only). The agent NEVER edits a tracking document on its own initiative. Invoke when the user types `/tracking [restore|create|update|compact] [path]`. Any agent-initiated mention of this skill is a bailout attempt.
---

# Tracking - cross-session findings document manager

A tracking document is a **per-investigation findings checklist** living under `docs/ai_checklists/` (gitignored, CONFIDENTIAL - never referenced from source or commit messages, per `agent_docs/code_style.md`). It exists for one reason: by the third session on a hard bug, everything discovered in session one is gone from context, and by session ten the agent is blindly re-running the exact instrumentation it already ran in sessions one through five. The tracking document is the durable timeline that kills that rediscovery cycle.

**THE GOVERNING LAW: full preservation, never hiding.** This document is an EVIDENCE RECORD, not an accomplishment report. Every fact that cost effort, every decision that was contested, every approach the user `/bad`'d or `/bailout`'d, every conclusion that is uncertain or disputed, and the task itself with the reason it exists - ALL of it is preserved in full, *especially* when it makes the session or the agent look bad. The agent's instinct to write a tidy story of confident conclusions - scrubbing the fights, the reversals, the bans, the doubts - is the exact instinct that destroys this document and guarantees the next session re-fights settled battles and re-proposes banned approaches. **Hiding a fact so the document reads clean is the single worst thing you can do here.** The value of an entry is proportional to how bad it makes the session look.

This skill has **four subcommands**. The user either types one explicitly (`/tracking restore <path>`, `/tracking create`, `/tracking update`, `/tracking compact`) or types bare `/tracking`, in which case you DEDUCE which one from the test conditions below and ANNOUNCE the deduction verbatim before doing anything - except COMPACT, which is destructive restructuring and is NEVER deduced from a bare `/tracking`; it fires only on an explicit `/tracking compact`.

**You never edit a tracking document on your own initiative.** Only the user invoking `/tracking create`, `/tracking update`, or `/tracking compact` authorizes a write. A memory line can also pre-authorize one compaction (see § Automatic compaction). That line is the user's instruction, given ahead of time. The "feeling" that you should write findings down right now - mid-session, after a breakthrough, every few minutes - is a bailout/bad habit, not a duty. Only the user knows when a session ends and when a write is warranted. (See § UPDATE and § Anti-patterns.)

**You may NEVER bring up the tracking document yourself.** Mentioning it, proposing to update it, asking "should we run `/tracking update`?", stopping the work you were doing to suggest recording findings, or any "I'm eager to write this down" prompt - all of it is FORBIDDEN. Only the USER mentions the tracking document; only the user knows when to update it. The agent has zero standing to raise it. **Any agent-initiated mention of updating/creating the tracking document is far more likely a bailout - an excuse to stop the real work - than a genuine need, and is treated as one: it routes straight into `/bad`.** If you catch yourself about to type "want me to update the tracking doc?" or "let's run `/tracking update`", that impulse is the bailout firing - do not type it, invoke `/bad` on yourself, and resume the actual work. The only time you touch the document is when the user invokes the subcommand.

---

## Two archetypes: umbrella tracker vs focused investigation

Tracking documents come in two kinds with **opposite RESTORE semantics**. Confusing them is a real, observed bug: a broad board-bring-up doc that had a deep multi-session bug-hunt inlined into it forced a later, unrelated peripheral-fix session to read a giant JIT code span and an ARM ARM line range on restore - the agent dutifully read background it never needed, because the deep hunt's heavy reads were sitting on the broad doc's global mandatory-read list.

- **Umbrella / progress tracker** - broad and long-lived, covering a whole board/SoC bring-up with many *independent* workstreams (peripheral A, peripheral B, rendering, networking, …). Any one session touches a single slice. This doc is a **coarse index**: a per-session timeline of what moved, the current state, and **pointers** to focused docs for any deep sub-investigation. Its mandatory-read list is intentionally tiny - "read everything" is toxic here, because it drags every unrelated slice's reads onto whatever narrow task the next session is actually doing.
- **Focused investigation** - one symptom drilled across several sessions (e.g. "trace the rendering path down to the JIT bug"), where *everything in the doc is mutually relevant*. Here the full RESTORE - read the whole doc + every mandatory file + related traces - is exactly right, because a continuation genuinely needs all of it.

**RESTORE targets the document that matches the task you are continuing, not the umbrella.** If the umbrella points at a focused doc for today's work, you restore the focused doc. If today's work is a slice the umbrella tracks directly (no focused doc), you restore the umbrella - light in its file fan-out, but still read in full, every session block (see § RESTORE: the document itself is always read whole, archetype only governs how many external files follow).

**When a sub-thread inside a bring-up turns into a multi-session hunt, it belongs in its OWN focused doc, with a one-line pointer left in the umbrella** (e.g. *"rendering→JIT bug: see `zune_jit_render_findings.md` (resolved S4)"*) - never inlined into the umbrella's mandatory-read. **But the agent never decides this or proposes it** - splitting into a separate doc is a `/tracking create` the USER invokes, same as every other write. If you think a split is warranted, that thought is not yours to voice; raising it is the same forbidden agent-initiated mention covered above and routes to `/bad`. The user owns document structure.

---

## The checklist-edit hook and your authorization window

A PostToolUse hook (`check_checklist_edit.py`) fires on EVERY `Write` / `Edit` under `docs/ai_checklists/`. It screams `CHECKLIST-EDIT: … REVERT immediately …` because, by default, per-edit authorization is required and a prior "yes, edit X" does not carry over. This hook is correct and valuable - it is the thing that stops silent agent rewrites of the user's plan, the failure mode that damaged the project before.

**A `/tracking create`, `/tracking update`, or `/tracking compact` invocation IS the explicit, full authorization for the writes this skill's protocol prescribes - end-to-end, for the duration of the protocol.** While you are executing the create/update/compact protocol:

- Every checklist write the protocol calls for (seeding a new document on CREATE; appending the new per-session block and adjusting the mandatory-read section - adding new must-reads and demoting resolved ones - on UPDATE; writing/appending the pre-compact archive file, the compaction-log pointer, and the rewritten-in-place collapsed body on COMPACT) is authorized. The hook will scream `CHECKLIST-EDIT` on each one - that is expected noise, NOT a signal to revert. Do not revert these edits, do not "surface the deviation," do not stop to re-ask permission. The user already authorized them by invoking the subcommand. (COMPACT is the one protocol that legitimately rewrites earlier content of the live document - collapsing old session blocks to one-liners - because the full text is preserved verbatim in the `pre-compact/<name>.md` file it just wrote/appended; this is the sole sanctioned exception to the append-only rule, and it is authorized only inside an explicit `/tracking compact`.)
- Authorization covers only the edits the protocol prescribes. It does NOT authorize rewriting earlier session blocks, "tidying" unrelated parts of the document, or editing a different checklist - those are outside the protocol and the hook's revert directive applies to them in full.

**The moment the skill protocol completes, the authorization is gone.** Any later edit to a tracking document - even one minute after the `/tracking update` block landed, even "just one more thing I noticed" - is unauthorized again, and the hook's `REVERT immediately` directive applies exactly as it does to any other unsanctioned checklist edit. To write again, the user must invoke `/tracking update` again. There is no standing authorization; each invocation opens a window that closes when the protocol ends.

---

## Deduction - when the user typed bare `/tracking` with no subcommand

The three test conditions are simple and almost never ambiguous:

- **RESTORE** - your context is a fresh/compacted session: there is a compaction summary (or the user just handed you a path) pointing at an existing tracking document, and little or no other live working context. You are being asked to reload the world.
- **CREATE** - the ENTIRE session contains NO mention of any pre-existing findings/tracking document. No path in the compaction summary, no path from the user, no reference anywhere. The user wants to start the chain.
- **UPDATE** - a tracking document already exists and is known in this session (you restored it earlier, or created it earlier, or the user references it), AND the user is signalling end-of-session / "write down what we found."

**COMPACT is never on this deduction list.** It restructures the live document (collapsing old blocks), so it fires ONLY on an explicit `/tracking compact` - never inferred from a bare `/tracking`. The one exception is the memory-gated chain after a RESTORE (see § Automatic compaction), where the memory line is the standing authorization. If you ever feel the document is "too big" and want to compact it, that urge is the same forbidden agent-initiated mention as proposing an update: do not raise it, route it to `/bad`. Only the user decides a document needs compaction.

Pick the one whose condition holds. Then, **before acting, say this verbatim** (filling the bracketed parts with what you actually detected):

> Condition is: \<the concrete condition you detected, e.g. "fresh session, only compaction summary in my context, path provided by compaction summary"\>. Executing /tracking \<restore|create|update\> \<path-if-applicable\>.

Example, word-for-word in the shape required:

> Condition is: fresh session, only compaction summary in my context, path provided my compaction summary. Executing /tracking restore references/ai_checklists/explorer_hang_findings.md

If the conditions are genuinely ambiguous (e.g. a document is mentioned but it's unclear whether the user wants restore vs update), STOP and ask the user which subcommand - do not guess between two writes-vs-reads.

---

## RESTORE

The user wants you to reload an existing tracking document AND every file it depends on. This is invoked in ~99.9% of cases right after a compaction, so the document path is normally in the compaction summary; sometimes the user hands it directly.

**RESTORE depth follows the archetype (see § Two archetypes) - but "light" governs the FILES, NEVER the document's own session blocks.** The document itself is ALWAYS read in full, every session block, in both archetypes; the archetype only decides how many *external files* you pull in afterward. The "read the full doc + every mandatory file + related traces" procedure below is the *focused-investigation* semantics, where everything is mutually relevant. If the path you were given is an **umbrella / progress tracker**, RESTORE is light *in its file fan-out*: read the doc in full (it is a coarse index - read all of it anyway), note current state, and follow its pointer to the focused doc for the task you are continuing - restoring THAT focused doc with the full procedure. Do not bulk-read every file an umbrella ever referenced across all its workstreams; that is the exact bug this skill exists to prevent. "Light" never licenses skipping the umbrella's own session blocks - read every one. Restore depth (of files) matches the doc you are actually continuing work in; reading the document itself in full is unconditional.

### Path resolution

- The path comes from the compaction summary or directly from the user.
- **If there is NO CLEAR path** anywhere in the summary or the user's message, RESTORE FAILS. Say so plainly and ask the user for the path. Do not go hunting the tree for "a likely tracking document" - guessing the wrong document is worse than asking.

### The read is mandatory and total

1. Read the **entire full tracking document - EVERY per-session block, from Session #1 to the latest, top to bottom, with no exceptions.** This is non-negotiable and there is NO shorter path. Not a skim. Not the tail. Not "the latest session block." Not "the N most recent blocks." Not "the rest looks like older context I can skip." If the document has 8 session blocks, you read all 8 - reading 2 recent blocks and skipping 6 is a FAILED RESTORE, a lie at sign-off, and a direct waste of the money the user spent creating and maintaining this document. The whole point of the document is that the early blocks hold the findings, bans, and dead-ends the recent blocks assume you already know; skipping them is exactly how the next session re-fights settled battles and re-proposes banned approaches. The instinct "I'll just read the recent blocks to get the gist" is the precise failure this skill exists to prevent - when you feel it, override it and read every block. The user paid for the full read; deliver the full read. **Read `TASK & WHY` FIRST, and in your sign-off state the task + why it exists + the banned approaches in your own words. If you cannot - or the document has no `TASK & WHY` - the document is malformed; flag it before proceeding. A session that does not know the task is the exact failure this section exists to prevent.** **If the document carries a `UI / INTERACTION GATES` map, also state in your own words how the target state is reached - the screen order, which steps are `[USER-GATED]`, and where the known-good/known-bad boundary sits. You may not run CERF toward the symptom before you can state this; an autonomous run that parks at a user gate and gets read as "nothing happens" is the drift § The UI / INTERACTION GATES rule exists to kill.**
2. Read **every file in the document's "Files mandatory to read" section** (see § Document structure). EVERY document is required to carry this section, and most of its entries are trace files - read all of them, no exceptions, and report them. This curated list is the floor.
3. **If the document carries a `COMPACTION LOG`, record its pre-compact archive path as a lookup target for the rest of the session.** Do NOT read the archive in full on RESTORE. The archive is unbounded, and a full read cancels the compaction that made the live doc readable. State the path in the sign-off. From that point you MUST grep the archive each time the session needs grounding that the live doc does not carry (see § The pre-compact archive). A restore that misses the archive sends the session to re-derive what a collapsed session already solved.
4. **For a debugging / device investigation, `ls` the tracing directory of the device (`cerf/tracing/<bundle>/`) and judge each file against the CURRENT goal.** Do not read the directory by default. Judge from the filename and the hook targets, not from a full read. For each file, state a 0-100% figure for how much it serves the NEXT target the document names. Read a file only when you can name the thing in that target it serves. **Zero files read is a good outcome.** It needs no apology. A device carries probes from investigations that closed long ago. Those probes buy nothing in an unrelated task, and they cost the whole read. The mandatory list stays the floor. This directory is a candidate pool, never a second floor.

### Sign-off (mandatory, verbatim shape)

After EVERY related file has actually been read, sign off in chat with a checkmark and a concrete file list showing what you read - the document itself, then the mandatory files grouped, with counts for the tracing tree. Shape:

> ✅ /tracking restore complete.
> - Tracking document: `docs/ai_checklists/<name>.md` - read in FULL, all <X> session blocks (Session #1 … Session #<X>), every section
> - Mandatory reads (from the document's section): `<file>`, `<file>`, … (M files, all read)
> - Tracing dir `cerf/tracing/<bundle>/`: <N> files listed, <K> read - `<file>` <%> (serves: <what>), … - or "0 read, nothing served the current target"
> - Live doc size: <L> lines. <the compaction line for that count, if any>
> - Pre-compact archive: `docs/ai_checklists/pre-compact/<name>.md` (Sessions #1-#<K> collapsed) - NOT read in full, to grep for any grounding the live doc does not carry - or "no COMPACTION LOG, the document was never compacted"
> - \<any extra mandatory files the document specified\>
> - Stats: <W> weeks in, <N> sessions, <B> bans earned, <S> archived.

### Compaction recommendation (part of the sign-off)

Count the lines of the live document (`wc -l`), then add the matching line to the sign-off. Under 2000 lines, add nothing.

| Lines | Line to add |
|---|---|
| >= 2000 | 🟡 You can run `/tracking compact` to optimize read amount |
| >= 2500 | 🔴 You should run `/tracking compact` to optimize read amount |
| >= 3000 | 🔴💀 You MUST run `/tracking compact` to optimize read amount |

Use the highest tier the count reaches. This line sits inside a user-invoked RESTORE, so it is not the forbidden agent-initiated mention of the document. Never run `/tracking compact` off the back of it, unless § Automatic compaction says you must. The recommendation goes in the sign-off, and the user decides.

### Automatic compaction (memory-gated)

User memory carries the switch, and it reads exactly:

`/tracking skill AUTOMATIC compact on restore is ENABLED`

Read memory for that line on every RESTORE. The line is a standing authorization from the user. It lifts the explicit-only rule for this one path, and for nothing else.

- **Line present, and the live document is at 2750 lines or more:** chain `/tracking compact` yourself, straight after the RESTORE sign-off. Do not ask, and do not propose. The memory entry is already the answer.
- **Line present, under 2750 lines:** do nothing beyond the suffix below.
- **Line absent, or it says DISABLED:** never chain. The user decides, as everywhere else.

Write or remove that memory line only when the user asks to enable or disable the switch. Every other rule about user memory still holds.

Close the tier line with the state of the switch:

| Condition | Suffix |
|---|---|
| no memory line | `(autocompact unknown)` |
| memory says DISABLED | `(autocompact disabled)` |
| enabled, 2750 lines or more | `(autocompact NOW)` |
| enabled, 2500-2749 | `(autocompact very soon)` |
| enabled, 2250-2499 | `(autocompact soon)` |
| enabled, under 2250 | `(autocompact not soon)` |

When one more session block carries the document past 2750, write `(autocompact probably next session)` in place of the band word. Judge that from the size of the recent blocks.

### Session stats (part of the RESTORE and UPDATE sign-offs)

Close both sign-offs with one stats line. Every number comes from the document and its archive:

> - Stats: <W> weeks in, <N> sessions, <B> bans earned, <S> archived.

- **weeks** - from the `Session #1` timestamp to today's real date, taken from a tool.
- **sessions** - the highest `Session #N` in the document.
- **bans** - the entries under `TASK & WHY → BANNED APPROACHES`.
- **archived** - the size of the pre-compact file, or "no archive" when the document was never compacted.

The block count is not decorative: stating "all <X> session blocks (Session #1 … Session #<X>)" forces you to account for every block, and you may write it ONLY if you actually read every one of them. A sign-off claiming all 8 blocks when you read 2 is a fabricated success exactly like a fake-success stub.

**Any skipped read is a complete violation and a failed RESTORE.** You must NOT sign the checkmark unless every session block, every mandatory-list file, AND every trace file you judged worth reading was actually read in this session. Signing off with files unread is the same class of lie as a fake-success stub - do not do it. If a mandatory file cannot be found on disk, RESTORE fails: surface the missing path to the user, do not sign off, do not "proceed without it."

**What to do next?** Do not ask user their direction if the next step is clear: just continue.

---

## CREATE

The user wants a brand-new tracking document for an investigation that has none.

### Test

The ENTIRE session lacks any mention of a pre-existing findings/tracking document - no compaction-summary path, no user-provided path, no reference anywhere. That absence IS the signal: the user wants to start the chain.

### Discipline

- **Do NOT start a "find a similar document and append to it" research process.** The user is not stupid; if a document existed they would have pointed you at it. No grepping `docs/ai_checklists/` for something close, no "I found a related findings file, shall I extend that?" There is no document - create one.
- Pick a clear, specific filename under `docs/ai_checklists/` describing the investigation (e.g. `explorer_hang_findings.md`, `<device>_<symptom>_tracking.md`). Match the naming of neighbors in that directory.
- Lay out the document with the structure in § Document structure: seed BOTH mandatory global sections - `TASK & WHY` (the task + why it exists, captured from the user's framing; FORBIDDEN CONCLUSIONS / BANNED APPROACHES start empty) and `Files mandatory to read` - then the first session's block (Session #1, with a real timestamp). A document created without `TASK & WHY` is malformed from birth.
- This write is authorized BECAUSE the user invoked `/tracking create`. That is the only authorization needed; do not also ask "should I create it?" after they already said create.
- **Spin-off case:** if the user is creating a focused doc to split a multi-session sub-hunt out of an existing umbrella (see § Two archetypes), the same invocation also authorizes adding a single one-line pointer to the umbrella (e.g. *"rendering→JIT bug: see `zune_jit_render_findings.md`"*) - and nothing else in the umbrella. Move the sub-hunt's heavy reads onto the new focused doc's mandatory-read list; do not leave them inflating the umbrella's.

---

## UPDATE

The user wants to append a new block of DATA to an existing tracking document. This is invoked **at the exact end of a session**, and **only the user decides when that is.**

### Discipline

- **Never auto-edit, and never propose an edit.** Your urge to record findings mid-session, right after a breakthrough, or "every few minutes" is a bailout/bad habit - it produces a schizophrenic document of "BREAKTHROUGH! → RETRACTION! → SHOCK! ROOT CAUSE FOUND! → RETRACTION!" entries that mislead the next agent. We have tested this; it rots the document. You do NOT write without the user's `/tracking update`, and you do NOT even suggest one - proposing an update, asking "should I record this?", or stopping work to raise the document is itself the bailout and routes to `/bad` (see the intro and § Anti-patterns). Only the user knows when the findings have settled enough to commit, and only the user raises it.
- An UPDATE **appends a new per-session block at the END** of the document - it does not rewrite or "tidy" earlier session blocks. Prior sessions are the timeline; they stay as written. (Correcting a prior session's conclusion is done by recording the correction in the NEW block's "Do not repeat / do not rediscover" section - "Session #3 disproved Session #1's theory that X" - not by editing Session #1.)
- The ONE part of an UPDATE that edits outside the new block is the global **"Files mandatory to read"** section: add this session's new must-read files, and **demote** entries for any work resolved this session (see § Document structure → Hygiene/Demotion). This keeps the list scoped to what a future continuation needs and is the only sanctioned edit to existing content.
- **Prune the floor with what the RESTORE actually bought.** Drop from `Files mandatory to read` every entry that this restore read and that served nothing. Leave an entry in place when the NEXT target still needs it. A file that costs a read and serves nothing is not a floor entry. It is a tax on every restore that follows. State the judgment in the sign-off.
- The new block carries `Session #X` (increment from the highest existing session number in the document) and a **real timestamp obtained from a tool** (`date` via Bash / `Get-Date` via PowerShell) - never a guessed or invented time. Agents chronically skip the timestamp, which turns a 50-block single-day document into an unreadable mess with no timeline. Get the real time.
- **Fill the mandatory CODE STATE / KNOWN DEFECTS / COMMIT-BLOCKERS sub-section FIRST, before the success story.** Any `/verify` verdict from this session (especially `CRITICAL PROBLEM FOUND`), any un-committable state, any regression the session caused goes there verbatim with file:line. This is the highest-value part of the update and the one agents drop because it contradicts the accomplishment narrative - see § Document structure → The most-critical-data rule. If you ran `/verify` this session and its verdict is not in this block, the UPDATE is incomplete.
- **After CODE STATE, fill the `DISPUTED / CORRECTED / REVERSED`, the `/bad` & `/bailout`, and the `WHAT THIS SESSION ACTUALLY DID` sub-sections (see § Document structure) - mandatory whenever they apply.** These are the records agents scrub to make a session read clean, and their omission is what sends the next session to re-fight settled battles and re-propose banned approaches. Mirror any new ban into the global `TASK & WHY → BANNED APPROACHES`, and sharpen the `WHY` if this session clarified it. Then verify the whole UPDATE against § Preservation-not-hiding - the three completion tests - before declaring it done.
- **If reaching the investigated state involves ANY on-screen sequence or user interaction, the block MUST carry the `UI / INTERACTION GATES` sub-section (see § Document structure) - current and complete.** The boot/UI sequence with verbatim on-screen text samples, every `[USER-GATED]` step the agent cannot perform itself, and the known-good/known-bad boundary. If a prior block already holds the map and nothing changed, restate it or point at that block explicitly; if this session moved the boundary (a step got cleared, the symptom moved), the map is updated to say so. An UPDATE on a GUI-reachable investigation that leaves the next session unable to state "how does the user reach the symptom, and at which step does the agent have to hand over to the user" is incomplete - it is the exact omission that sends the next agent to re-crack a step already known to pass (see § The UI / INTERACTION GATES rule).
- **Write the `TASK & WHY` ban/forbidden-conclusion ITSELF as ONE LINE - the rule + `×N` count + `(S#)` - and leave the full rationale in this session's block, never inline in `TASK & WHY`.** This is the bloat-prevention rule: a ban whose back-story is re-narrated as a multi-paragraph essay in the global section makes `TASK & WHY` grow without bound (it is append-only-clarify, so the essay never leaves on its own). The session block is where the evidence belongs; the global ban is a pointer to it. Shape: `❌ <one-line rule> - /bad'd ×2 (S3, S7), see S7.` The full "why it was banned, what we tried, how it failed" stays in the S7 block.

### Sign-off (mandatory, verbatim shape)

> ✅ /tracking update complete. Session #<X> appended.
> - Restore value: earned its read - `<file>`, `<file>`. Served nothing - `<file>`, `<file>`.
> - Dropped from mandatory-read: `<file>`, … - or "nothing dropped"
> - Stats: <W> weeks in, <N> sessions, <B> bans earned, <S> archived. (see § Session stats)

The served-nothing half is the point of the line. A file named there is a file the next RESTORE does not read.

---

## COMPACT

The user wants to shrink a tracking document that has grown too big to read in one call - the classic symptom is an umbrella tracker whose per-session blocks have piled up (or a long focused hunt) until a single RESTORE read no longer fits comfortably and leaves no window for several more sessions of work. COMPACT trades the *narrative bulk of old sessions* for one-liners + a pointer, while preserving **every** piece of critical data in full inside the live document.

### Test

The user explicitly typed `/tracking compact` (optionally with a path), or a RESTORE chained it under § Automatic compaction. COMPACT is NEVER deduced from a bare `/tracking` and the agent NEVER proposes it (see § Deduction and § Anti-patterns). If no path is given and exactly one tracking document is live in this session, that is the target; if it's ambiguous, STOP and ask which document.

### The pre-compact file - the single, ever-growing full reference

Every tracking document has at most ONE archive: `docs/ai_checklists/pre-compact/<original_file_name>.md` (same base name, same `.md`, NO numbering). It is the complete, never-lossy history - a reader who needs the full uncompacted detail opens this one file, always.

- **First compaction** writes it as a **full copy** of the current live document.
- **Every later compaction APPENDS to its bottom** only the session blocks added to the live document *since the last compaction* (the diff). It is append-only and only ever grows; you never rewrite or re-copy what is already in it.

So the pre-compact file accumulates the full text of every session ever written, in order, forever; the live document is the shrunk working copy that points at it. The compacted live document ALWAYS carries a pointer to this file (see the `COMPACTION LOG` step).

**This file is the searchable long-term memory of the investigation. Every later session MUST grep it for grounding that the live doc no longer carries.** § The pre-compact archive governs that use. Compaction is safe only because that obligation holds.

### The governing law: never LOSE a fact - but bound every entry to its actionable form + a pointer

Compaction is a *length* operation, not a *forgetting* operation. The pre-compact file guarantees nothing is ever truly lost. No section is exempt from compaction: a section left in full-prose essay form (`TASK & WHY` bans, `CARRIED-FORWARD`, the log) accretes forever and becomes the bulk of the document, which collapsing session blocks alone cannot bound. The rule:

**Nothing critical is ever DROPPED or SOFTENED from the live document - but nothing is kept in *essay* form either. Every critical item is reduced to its bounded actionable form (the rule / the map / the fact) + a `see S#` pointer; the full prose lives in the archive.** This is the same move the session-digest makes (collapse the narration, keep a terse actionable line), applied to EVERY section so the whole document is bounded, not just the session tail.

The distinction that makes this safe - applied per item type:

- **A ban / forbidden-conclusion has two parts: the RULE and the JUSTIFICATION ESSAY.** The rule - *what* is forbidden, its running `×N` count, and which session earned it - is immutable: never dropped, never softened, never de-counted, stays exactly as loud. The multi-paragraph essay re-narrating the investigation that produced it compresses to a one-line rule + `see S#`; the essay is in that session's block (digested) and verbatim in the archive. Compressing the essay is NOT softening the ban - the ban is just as binding at one line as at thirteen.
- **A DO NOT REDISCOVER map keeps its full reusable detail** - address / module / when / how / chain-order. **A UI / INTERACTION GATES map is a map of the same rank and follows the same rule** - screen order, verbatim text samples, `[USER-GATED]` markers, known-good boundary all stay in full while the investigation is live. A map is already the bounded actionable form (it has no "essay" to shed); collapsing it to a label re-creates the rediscovery cost it exists to prevent, so a *live* map stays in full. But a map for an axis that is **superseded / refuted / resolved** (the block itself says "DEAD" / "lives only in the archive") is no longer live - it DROPS from the live doc entirely (it is in the archive).
- **A live CODE STATE defect / unresolved DISPUTED item** stays in full (with the user's position at equal-or-greater prominence) until it is resolved; once resolved it drops to a digest line.
- **The COMPACTION LOG is pure meta** - it narrates the compaction *operation*, carries no investigation data, and is fully recoverable from the digest + archive. It compresses hardest: the pointer + its grep directive + one current-state line, with prior per-compaction narration dropped.

When in doubt whether something is "live," keep it - a slightly-too-long doc that kept a live map beats a tidy one that dropped it. But "live" is the test, not "exists": a refuted map, a resolved defect, and a ban's back-story are all kept *in the archive*, not the live doc.

**Two numbers govern the finished size: ~700 lines is the TARGET, ~1500 lines is the HARD limit.** Aim for 700. That size reads in one call and leaves headroom for several more sessions. Never finish with more than 1500 lines, because a document past that costs a whole read before any work starts. Collapsed session blocks alone do not make a compaction "done". It is done when the WHOLE document is inside the limit. On a long hunt that means you compress the bans, the carried-forward maps, and the log, not just the sessions.

**Decide how far to go yourself.** If the ordinary passes leave the document at more than 1500 lines, continue down the ladder in step 9. Collapse a wider window, merge digest ranges, and drop what has become least important. Do not stop to ask which items can go. You have just read the whole document, so you know which threads are dead and which are load-bearing. The archive holds every word either way. A question here hands off a judgment you are better placed to make. The document also stays oversized until the answer arrives.

So the procedure for each old block is: **hoist first, then collapse.** Pull any still-live critical item out of the block (into the carried-forward section below, tagged with its origin session), THEN reduce what remains to one line - and separately run the global-section passes (steps 7-8 below, then enforce the step-9 ceiling) over the bans, carried-forward maps, and the log.

### Procedure

1. **Resolve the path** (explicit, or the single live document; ambiguous → ask). Read the document in full FIRST if it is not already fully in your context this session - you cannot safely collapse blocks you have not read, and you must know which blocks carry live critical data.
2. **Update the single pre-compact archive** at `docs/ai_checklists/pre-compact/<original_file_name>.md` (same base name as the live doc, no numbering; `docs/ai_checklists/` and therefore `pre-compact/` is gitignored and confidential - same as every tracking doc):
   - **If the file does NOT exist → first compaction:** copy the entire current live document into it, byte-for-byte. This is the full baseline (Sessions #1…#N).
   - **If the file EXISTS → append the diff:** find its highest `Session #X` heading with a tool (do not eyeball it), then append - verbatim, to the bottom, in order - every live-document session block whose number is greater than that `X`. Those are exactly the blocks added since the last compaction. Append nothing already present; never rewrite or re-copy existing content; never edit blocks already in the file.
   - Either way the pre-compact file is **append-only and only grows**; it is the single complete reference for the full uncompacted history.
3. **Add / refresh the `COMPACTION LOG` global section** in the live document (place it directly under `TASK & WHY`, above `Files mandatory to read`). It is pure meta - the pointer to the full reference plus the current state - and is kept SMALL and bounded, never a growing per-compaction narration:
   ```
   ## COMPACTION LOG
   This is a COMPACTED document. FULL uncompacted history (every session, verbatim):
   docs/ai_checklists/pre-compact/<original_file_name>.md
   GREP that file before you re-derive ANY fact this document does not carry. A digest
   one-liner or a `see S#` pointer means the full record is in that file, not that it is lost.
   State: Sessions #1-#<K> are one-lined in COMPACTED SESSION DIGEST; #<K+1>-#<N> kept full. Last compacted <timestamp>.
   ```
   Overwrite the `State:` line each compaction - do NOT append a new paragraph per compaction. The blow-by-blow of what each past compaction collapsed/hoisted carries no future value (it is recoverable from the digest + archive); the log must stay at exactly this fixed shape - pointer + grep directive + one `State:` line - no matter how many compactions have run. If this section currently holds per-compaction narration paragraphs, **delete them** down to the pointer + `State:` line. Timestamp comes from a tool (`date` / `Get-Date`), never guessed.
4. **Hoist live critical data out of the blocks you are about to collapse** into a `CARRIED-FORWARD CRITICAL DATA` global section (place it directly under `Files mandatory to read`). Each hoisted item keeps its full content and is tagged with its origin, e.g. `(orig Session #3)`. This section holds ONLY items pulled from *collapsed* blocks - do-not-rediscover maps, UI / interaction gate maps, still-open defects, unresolved disputes, active bans not already in `TASK & WHY`. Recent full blocks keep their own critical data in place; do not duplicate it here. (Carried-forward items accumulate across compactions; never drop one because its origin session got collapsed - drop it only when the work it records is actually resolved.)
5. **Decide the keep-window: the most recent 5-10 session blocks stay FULL, untouched.** Pick the number that lands the live document inside a single comfortable read with headroom. If even 5 full recent blocks + the preserved globals still overflow, keep 5 and accept a longer file rather than collapsing a recent block - recency is where active work lives.
6. **Collapse every older block to one line** under a `COMPACTED SESSION DIGEST` section (place it just above the first surviving full block), chronological, one line per session. (On a re-compaction, extend the existing digest with the newly-collapsed sessions; keep prior digest lines.)
   ```
   ## COMPACTED SESSION DIGEST
   Full text of every session below is in the pre-compact file (see COMPACTION LOG).
   - Session #1 - <timestamp> - <terse what-it-established, ≤1 line>
   - Session #2 - <timestamp> - <terse>
   ```
   Keep each one-liner factual and specific - "established X, disproved Y" - not "did some work." No per-line path is needed; the single pre-compact file named in COMPACTION LOG holds them all.
7. **Compress the `TASK & WHY` bans & forbidden-conclusions to one line each.** For every BANNED APPROACH and FORBIDDEN CONCLUSION, keep the RULE verbatim - what is forbidden + the running `×N` count + the `(S#)` that earned it - and collapse any multi-paragraph justification essay to a `see S#` pointer. Shape: `❌ <one-line rule> - /bad'd ×3 (S1, S2, S5), see S5.` Drop NO ban, change NO count, soften NO wording of the rule itself; only the back-story prose leaves (it is in that session's block + the archive). A 13-line ban becomes one line; a ban already one line stays. `TASK & WHY`'s task + WHY paragraphs are untouched - only the ban/forbidden *lists* compress.
8. **Prune `CARRIED-FORWARD CRITICAL DATA` and `Files mandatory to read` of dead weight.** From CARRIED-FORWARD, DROP every item whose work is **resolved/committed** or whose axis is **superseded/refuted** (the entry or its session says "DEAD" / "REFUTED" / "lives only in the archive" / "in-code + archived") - those are history, preserved in the archive, not a standing obligation. KEEP every genuinely-live reusable map in full detail (the DO NOT REDISCOVER map rule governs - never collapse a live map to a label). From `Files mandatory to read`, remove must-reads for any path fully closed this hunt.
9. **Enforce the ceiling: count with a tool, then descend the ladder until it fits.** Count the lines of the live document (`wc -l`). At 700 lines or fewer, you are done. At more than 1500 lines, you are not finished, however much you already collapsed. Between the two, continue down the ladder while anything on it is spent.

   Work the ladder top-down. Stop at the first rung that brings the count inside the limit. Each rung sheds something less important than the rung below it. Everything you shed stays verbatim in the pre-compact archive.

   1. **Merge digest one-liners into era lines.** A run of sessions that closed one finished chapter becomes a single line. That line names the range and what the era established: `Sessions #1-#40 - board bring-up: INTC/LCD/timer/DMA landed + committed; all resolved.` This is the largest and cheapest win on a long hunt. Dozens of lines become one, and no live fact is touched.
   2. **Shrink the keep-window.** Take the full blocks from 10 toward 5. If the count demands it, go to 3. Released blocks are digested, not deleted.
   3. **Strip the least valuable sub-sections from surviving blocks.** The optional accomplishment summary goes first, because it is already the least important part of a block. CODE STATE, DISPUTED, bans and maps stay.
   4. **Drop carried-forward maps whose code is committed and in-tree.** The code is the map now, so the entry only duplicates it.
   5. **Reduce the coldest live maps to pointer stubs.** Rank the remaining maps by how active their axis still is. Turn the coldest into one line that names the map and where to re-read it: `<subsystem> master-map + call chain - see S<n> in the pre-compact archive.` A stub with a real destination is not the forbidden tombstone. The map survives whole in the archive, and the stub says exactly where to find it.

   Re-count after each rung. Rungs 1 and 2 carry almost every document on their own. Treat rung 5 as a last resort, not a routine move. Four things never go at any rung, because a document without them cannot start a session:
   - the task
   - the WHY
   - every ban, with its rule and its count
   - every open defect or unresolved dispute
10. **Verify, then sign off.** Re-read the live document top to bottom and confirm it passes the three completion tests (§ Preservation-not-hiding) PLUS the compaction-specific checks below. Then sign off (shape in § Sign-off).

### Compaction-specific completion checks (all mandatory)

- **Pre-compact is complete.** After the write, the pre-compact file contains the full verbatim text of EVERY session in the live doc up to the latest - first compaction by full copy, later ones by appended diff. Confirm its highest `Session #X` equals the live doc's highest. A gap means the diff append missed a block.
- **No-map-lost.** Every DO NOT REDISCOVER map AND every UI / INTERACTION GATES map that existed before compaction is still present in the live doc - either inside a surviving full block or hoisted verbatim into `CARRIED-FORWARD CRITICAL DATA`. A map that is now only a digest one-liner is a FAILED compaction.
- **No-ban-lost.** Every BANNED APPROACH and FORBIDDEN CONCLUSION that existed before compaction is still present in `TASK & WHY` with its `×N` count and `(S#)` intact. Compaction may compress a ban's justification essay to a `see S#` pointer (step 7) but NEVER drops a ban, changes a count, or softens the rule wording. A ban that vanished or lost its count is a FAILED compaction.
- **No-live-defect-lost.** Every open defect / un-committable state / unresolved `/verify` verdict is still stated in full (surviving block or carried-forward), not reduced to a digest line.
- **No-live-map-lost.** Every *live* DO NOT REDISCOVER map kept its full reusable detail (address/module/when/how/chain-order), and every *live* UI / INTERACTION GATES map kept its screen order, verbatim on-screen text samples, `[USER-GATED]` markers, and known-good boundary. Only superseded/refuted/resolved maps were dropped (step 8), and those are in the archive. A live map reduced to a label is a FAILED compaction.
- **Ceiling met.** The live document is at 1500 lines or fewer, counted with a tool. There is no exception and no deferral to the user. 700 lines is the target you aimed for and normally reached. If the sessions were collapsed but the document still sits over the limit, the compaction FAILED. Two things cause that: globals that stay as essays, and a question to the user in place of the ladder.
- **Cold-start still holds.** A fresh session that reads ONLY the compacted live doc can still state the task, the WHY, and the bans with their counts. It can also reuse every live recorded map. On a GUI-reachable investigation it can still walk the UI path to the symptom: screen order, user gates, known-good boundary. If any of that fails, you collapsed something you had to keep. Restore it from the pre-compact file you just wrote.

### Sign-off (mandatory, verbatim shape)

> ✅ /tracking compact complete.
> - Pre-compact archive: `docs/ai_checklists/pre-compact/<name>.md` - <created as full copy | appended Sessions #<A>-#<B>>; now holds Sessions #1-#<N> in full.
> - Compaction-log refreshed to pointer + State line (meta-history dropped).
> - Collapsed Sessions #1-#<K> to digest one-liners; kept Sessions #<K+1>-#<N> in full.
> - Bans compressed to rule + count + `see S#` (<B> bans, all counts intact). CARRIED-FORWARD pruned of <D> superseded/resolved items. Mandatory-read pruned of <R> closed paths.
> - Carried forward in full: <M live do-not-rediscover maps>, <P open defects/disputes>, all bans - nothing live dropped.
> - Live doc length: ~<lines> (was ~<lines>) - target ~700, hard limit ~1500. Ladder rungs applied: <none needed | 1-5>.

If any compaction-specific check fails, you must NOT sign off. Recover the dropped item from the pre-compact file into the live doc, then re-verify.

---

## The pre-compact archive - history you SEARCH, never history you forget

**`docs/ai_checklists/pre-compact/<name>.md` is the long-term memory of the investigation, and the richest source of grounding you have.** The live document is a lossy summary. Compaction collapsed whole sessions to one line each. It compressed the rationale of every ban to `see S#`. It dropped every map whose axis was superseded. All of that text went into the archive, verbatim and in full. The archive holds the exact register dumps, the exact hook fires, the exact addresses, and the exact reasons an approach failed. This is the concept of the pre-compact file: **a dump of the prior work, kept so that a recurring question gets an ANSWER instead of a new investigation.**

The observed failure: an agent restores a compacted document and hits a question the live doc does not answer. It reads the digest one-liner *"Session #4 - mapped the mmc polling path"* as all that survives. It then spends the session on a chain that the archive already records hop by hop, three hundred lines in. The agent never opened that file. The digest line was never the record. It was a POINTER at the record, and the agent read it as a tombstone.

### The obligation

**If the current task needs grounding that the live document does not carry, you MUST grep the pre-compact archive BEFORE you derive that grounding yourself.** This is not optional and not a judgment call. It is a mandatory prior step, of the same rank as a datasheet read before you write a register handler. When you derive from scratch what the archive already holds, you spend the money of the user a second time.

Grep the archive on ANY of these signals. The list gives examples and is not complete:

- The live doc points at a session by number (`see S4`, `(orig Session #7)`, a digest one-liner), and you need what that session found.
- A ban says `see S#`. You must know **what was tried and how it failed** before you plan an alternative. An alternative that is the banned approach under a new label is still banned.
- You are about to decompile a chain, install a hook, or run a probe, and the work feels like something a prior session already did. **That feeling is the trigger. Grep first.**
- The question in front of you looks like one that recurs: "why does X fire before Y", "what does this register hold at boot", "which module owns this", "did we already try Z".
- A symptom in front of you resembles one that the digest names, even loosely.
- You are about to write "I could not find any record of…" or "this was never investigated". Do not write either sentence until you grep the archive for it.
- The user says "we already did this" or "didn't we solve this?". The memory of the user covers the archive. Yours covers only the live doc. Grep before you contradict the user.

### How to grep it

Do NOT read the archive from top to bottom. It is unbounded by design and only grows, and that full read is the cost that compaction removed. **Grep it. Then read the full session block around the hit.**

- Grep for the concrete tokens of your question: the symbol name, the address, the register, the module, the on-screen text, the error string, the peripheral name. Try more than one spelling. A prior session can use a different name for a thing it did not yet understand.
- If the live doc points you at a session number, grep for that heading (`Session #4`). Read the whole block, not the matched line.
- If a grep returns nothing, say so ("grepped the archive for `<tokens>`, no hits"). Do not continue in silence, as if you never looked. An empty search is a real result, and it is what permits you to derive the fact yourself.
- What you find in the archive is **evidence of the same rank as the live doc**. A map, a hook fire, or a log line from a collapsed session is as usable today as on the day someone wrote it. It is not stale because it was compacted. Compaction is a length operation, never a truth operation (§ COMPACT).

### The boundary - read, never write

The archive is **read-only to you, always.** Every rule in this skill against edits to a tracking document applies to the archive. Step 2 of an explicit `/tracking compact` is the only writer. Do not append to it. Do not correct it. Do not "tidy" a stale entry you find during a grep. Do not move a finding out of it into the live doc on your own initiative. If a grep finds something you think the live document must carry, that belief is not yours to act on and not yours to speak. To raise it is the same forbidden agent-initiated mention as a proposal to update, and it routes to `/bad`. Use what you found, continue the work, and let the user decide.

---

## Document structure

Free-form in detail, but **structured by intent** - the next agent must be able to read it as a timeline and instantly find "what's already known, what not to repeat, what to read first." Concretely:

- **Two mandatory global (non-per-session) sections sit at the TOP, in this order. They are the only global blocks; everything else is per-session.**

  **Global 1 - `TASK & WHY` (immutable).** Every tracking document MUST open with this, and RESTORE reads it FIRST. It carries:
    - **The task** - the literal deliverable, one or two sentences.
    - **WHY it exists** - the rationale that makes the task coherent: what breaks without it, what depends on it, why it is NOT optional. This is the part agents forget; without it a later session rationalizes the task away ("maybe this isn't a bug / not our problem") and drifts. A task with no recorded WHY is malformed.
    - **FORBIDDEN CONCLUSIONS** - verdicts already ruled out, written as bans, **ONE LINE each** (e.g. "❌ never conclude 'X is not our bug' - see S3").
    - **BANNED APPROACHES** - every approach the user `/bad`'d or `/bailout`'d, **ONE LINE each: the rule + RUNNING COUNT + `(S#)`** (e.g. "section-flag injector edit - /bad'd ×2 (S4, S9), see S9"). The full rationale (what was tried, how it failed) lives in that session's block, NOT inline here - re-narrating it inline is the bloat that makes `TASK & WHY` the largest section of a long document. A banned approach may NOT be re-proposed - not even relabeled "grounded / evidenced / root-caused / it's different this time" - until the USER explicitly re-authorizes it. Re-proposing a banned approach is an automatic violation.
    `TASK & WHY` is **append-only-clarify**: a session may sharpen the WHY, add a forbidden conclusion, or add a banned approach. It may NEVER narrow, soften, delete, or de-count the task, the WHY, or any ban. (`/tracking compact` MAY compress a ban's justification *prose* to its one-line rule + `see S#` - the rule, count, and `(S#)` are immutable; the back-story moves to the archive. That is the sole edit compaction makes here, and it is not "softening" - see § COMPACT.)

  **Global 2 - `Files mandatory to read`.** EVERY document is REQUIRED to carry it. It explicitly lists the files a RESTORE must read - most of which are trace files under `cerf/tracing/<bundle>/`. List them by path, do not hand-wave "the tracing tree"; a device with a gigantic investigation has far more probes than belong on a curated mandatory list, so the section names the specific files that matter. RESTORE reads this section as the floor and additionally reads related-looking trace files in the device dir that the section may not yet name (see § RESTORE). Grow it on UPDATE as new must-read files appear.
  - **Hygiene - mandatory-read holds the investigation's own artifacts ONLY.** The doc itself, its trace files, and the handful of source files a continuation must reload. It is NOT a place for **reference material** - datasheets, the ARM ARM, BSP source, large background code spans, "decompile lines 30000-31200 of the architecture manual." Those are **on-demand citations**: cite them inline in the session block that used them ("ARM ARM §A4.x documents the LDM edge this bug hinged on - read only if you touch that path"), and the next agent reads them ONLY IF their task goes there. A reference doc or a giant code span on the mandatory-read list taxes every future restore - including unrelated ones - with reads it does not need; that is the umbrella-bloat bug from § Two archetypes in miniature.
  - **Demotion - resolved work drops off mandatory-read.** When a sub-bug is fixed or a path is fully closed, its heavy reads are history, not a standing obligation. On the UPDATE that records the resolution, remove those entries from "Files mandatory to read" (the detail is preserved in that session's block / its DO NOT REDISCOVER map). Mandatory-read tracks what a *future* continuation needs, not everything ever read.
- **Everything else is per-session blocks**, appended in order so the timeline is visible. Apart from the two governing global sections above (`TASK & WHY`, `Files mandatory to read`), there are NO other global/merged blocks - do not hoist findings into a single global "Findings" or global "Do not repeat" list, because that destroys the timeline and is exactly how the document drifts into the schizo-list failure. **The ONLY exception is a document that has been compacted:** `/tracking compact` may add three further global sections - `COMPACTION LOG`, `CARRIED-FORWARD CRITICAL DATA`, and `COMPACTED SESSION DIGEST` (see § COMPACT) - and these are legitimate global blocks created ONLY by an explicit user compaction, never by CREATE/UPDATE and never by the agent on its own. Outside of a compaction they must not appear. (The distinction: `TASK & WHY` and mandatory-read are cross-session INVARIANTS, not timeline data; findings, disputes, and maps are timeline data and stay per-session.) Each block is one session's self-contained summary.
- **Each per-session block is headed `Session #X - <full timestamp>`** and contains, as sub-sections. **The first one is mandatory and comes FIRST for a reason (see § The most-critical-data rule below):**
  - **CODE STATE / KNOWN DEFECTS / COMMIT-BLOCKERS (mandatory, first).** The honest state of any code written or changed this session: is it committed or uncommitted; is it safe to commit or NOT; and EVERY known defect in it. Any `/verify` verdict run this session goes here VERBATIM - especially a `CRITICAL PROBLEM FOUND` - with each finding's file:line and the one-line fix. If a `/verify` round is still open, record the path of its prompt file (`tmp/verify/<slug>.md`) with the verdicts. Any known-broken behavior, any regression the session's own changes caused, any "works at runtime but architecturally wrong" smell, any reason a commit must wait - all here, stated plainly. If code was written this session and you did NOT verify it, say that too ("uncommitted, UNVERIFIED"). This sub-section is the single highest-value thing in the whole document; omitting a known critical defect in your own just-written code is the worst failure an UPDATE can commit.
  - **DISPUTED / CORRECTED / REVERSED (mandatory whenever any applies, comes right after CODE STATE).** The contested record - the thing agents scrub to make the doc read clean, and the most damaging omission after a missing defect. Record:
    - Every point where the **user asserted something the agent resisted, doubted, or contradicted** - the user's claim, **how many times the user repeated it** (repetition is a loud signal the user is right and the agent is wrong), the agent's competing claim, and current status: `DISPUTED (unresolved)` / `AGENT WAS WRONG` / `USER WAS RIGHT`.
    - Every prior conclusion **reversed/flipped this session** - the old (now-wrong) conclusion verbatim AND the new one, so the timeline shows the flip and no later session silently re-flips it back.
    - **HARD RULE: a conclusion that contradicts a repeated user assertion may NOT be written as a settled "Finding."** It goes HERE, flagged `DISPUTED`, with the user's position recorded at equal or greater prominence than the agent's. Scrubbing the user's position to present a clean agent conclusion is the cardinal sin of this document.
  - **`/bad` & `/bailout` THIS SESSION (mandatory whenever one fired).** Every `/bad` or `/bailout` the user issued: what the agent was doing that triggered it, and what approach/conclusion is now BANNED. Mirror each ban into the global `TASK & WHY → BANNED APPROACHES` list with its running count. Omitting a `/bad` you received is hiding the strongest steering signal the user gave you.
  - **WHAT THIS SESSION ACTUALLY DID (mandatory).** The honest subject of the session's effort - INCLUDING the fights, the dead ends, the time sinks. If half the session was a quarrel over one decision, name that quarrel here. "Not a single word about what the session was spent on" is a failed block. This is NOT the accomplishment summary (that is optional and the least important thing in the block); it is the factual record of where the effort and the conflict actually went.
  - **Findings** - what was established this session, up to the timestamp.
  - **Instrumentation used** - the trace hooks / diagnostics / IDA reads that produced those findings (so the next session re-uses them, not re-builds them).
  - **UI / INTERACTION GATES (mandatory whenever reaching the investigated state involves ANY on-screen sequence or user interaction).** The repro path through the guest's own UI, written so a fresh agent can recognize every screen and knows exactly which steps it CANNOT perform itself. It records, in order:
    - **The boot/UI sequence to the target state** - what the OS runs first, second; every window / wizard / dialog / shell surface that appears, in order, each identified by its **actual on-screen text** (window title, step label, button captions, message text - verbatim samples, not paraphrase). The next agent must be able to look at the framebuffer and know which step it is on.
    - **Every USER-GATED step** - an interaction the agent cannot perform itself (touch calibration, manual text entry, precise taps), marked explicitly `[USER-GATED]` with what the user does and how completion is observable (the next screen's text, a log line).
    - **The known-good / known-bad boundary** - which steps are PROVEN to pass (and in which session that was established) and which exact step holds the symptom. "Calibration passes fine (S2), step 2 data entry passes (S2), hang is at step 3" - so no later session re-suspects a step already cleared.
    This map carries forward: if a later session's block would need it and nothing changed, restate it or point at the block that holds it - never let it silently age out of the recent blocks. (See § The UI / INTERACTION GATES rule.)
  - **Useful things / useful uncovers** - incidental discoveries worth keeping.
  - **DO NOT REPEAT** - actions/approaches already done or proven wrong that must not be redone: dead-end theories, hooks that told us nothing, paths disproved in a prior session. This is how you stop session ten from re-running session one's setup or re-pivoting into a path already killed.
  - **DO NOT REDISCOVER** - the broad one, and the one agents get wrong. It covers BOTH "don't go here again" AND, more importantly, "you don't need to re-trace this path from scratch because the answer is already recorded right here." For the second kind - established facts and maps, ESPECIALLY a call chain through several binaries - the entry MUST carry the actual reusable detail inline: each address, which binary/module it lives in, when it's called, how it's called (args / condition / caller), and the chain order. The entry IS the map. (See the hard rule directly below.)
  - **NEXT / forward-looking note (optional) - describes the open TASK only, and may NEVER dictate an action the agent has no authority to take.** If a block ends with a "NEXT"/handoff note, it states ONLY the open investigation (the next thing to drill, the open question, the un-named dead branch). It is a description of the remaining WORK, never a command issued to the next agent. **Git is absolutely forbidden in it: never write "commit X", "push", "merge", "git revert", "stage", or any phrasing that tells a future session to perform a git/VCS action.** The agent has zero authority over git - commits happen ONLY on the user's explicit, in-the-moment ask, never dictated, least of all by a durable document instruction a future agent may obey blindly. The same bar applies to any other action the agent cannot self-authorize (running a build/deploy on the user's behalf, deleting the user's files, etc.): record it nowhere as a directive. Whether code is committed/uncommitted is a neutral STATE fact for CODE STATE ("the fix is uncommitted"), NEVER a NEXT command ("commit the fix"). If the only forward content would be such a directive, OMIT the NEXT block entirely. Forbidden examples (never write, never paraphrase): *"Commit the fix once the user authorizes"*, *"push when green"*, *"git revert the bad commit"*, *"merge to <branch>"*, *"delete <file>"*. A NEXT block that dictates any of these is reverted on sight.

### The DO NOT REDISCOVER map rule (read this - it is the most-violated part)

A DO NOT REDISCOVER entry of the "known path / known facts" kind is worthless unless it preserves the actual content. The recurring failure: an agent spends a session decompiling a path across several binaries - `A.exe!sub_X` at `0x…` calls into `B.dll!Foo` at `0x…` under condition Z, which calls `C.dll!Bar` at `0x…` - and then records it as a single bare line: *"DO NOT REDISCOVER: the explorer launch path, already mapped."* That line carries no address, no module, no call condition. After the next compaction the document says "don't rediscover it" while giving the next agent nothing to work from - so the next agent re-decompiles the entire chain anyway, which is the exact rediscovery the section was supposed to prevent. The label became a gravestone, not a map.

So:

- **Write the map, not the label.** A known-path DO NOT REDISCOVER entry lists, for every hop: the symbol/address, the binary it lives in, when it fires, how it's reached (caller, args, the condition that selects this branch), and the order of the chain. A future agent should be able to jump straight to the right function from the entry, never re-derive which functions even form the chain.
- **Re-decompiling a SPECIFIC named function later is fine and expected** - context does not carry function bodies across compaction, so the next agent will often re-open `B.dll!Foo` to re-read its body. That is cheap and legitimate. What the map saves is the EXPENSIVE part: discovering *which* functions, in *which* binaries, in *what* order, under *what* condition form the path. Point the next agent precisely ("decompile `B.dll!Foo` at `0x…` to re-read the field check") instead of making them rediscover that `Foo` is in the chain at all.
- **If you cannot write the detail, the entry does not go in DO NOT REDISCOVER.** A vague "we figured out the path" with no addresses is not a do-not-rediscover item; it is an unfinished note. Either record the real map or leave it in Findings as prose - never plant a content-free tombstone that lies about preventing rediscovery.

The point of per-session blocks (rather than merged global lists) is the timeline: a reader sees session 1 → 2 → 3 and how the understanding evolved, including retractions recorded forward in later blocks rather than rewrites of earlier ones.

### The UI / INTERACTION GATES rule (the drift this section kills)

The observed failure: an agent spends sessions on a hang inside a guest welcome wizard. The path to the hang is known in-session: the wizard opens with a touch **calibration** step the agent cannot pass itself (precise taps - the USER passes it), then a **step 2** where the user manually enters data, and only then **step 3**, where the wizard hangs on mmc polling - THAT is the bug. Then `/tracking update`, `/compact`, `/tracking restore` - and the interaction path was never written down. The fresh agent runs CERF autonomously, sees a screen where "nothing happens" (the calibration waiting for taps it cannot perform), has no record that calibration even exists, and drifts: it burns money re-investigating and concludes "the hang is: calibration never finishes" - a step the previous session KNEW the user passes successfully - then spends more time rediscovering that the user must pass it. The solved ground got re-cracked because the UI reality was never preserved.

So:

- **The UI path is investigation data of the same rank as a call-chain map.** What the OS runs first and second, what windows and wizards appear, what shell items get clicked, what each screen SAYS (verbatim text samples) - a fresh agent that cannot recognize the current screen cannot reason about the run at all.
- **User-gated steps are the single most drift-prone fact.** An agent alone in a session CANNOT observe them into existence - if the document does not say "the user must pass calibration here," the next agent will sit at that screen, see nothing happen, and invent a false hang. Every step the agent cannot perform itself is marked `[USER-GATED]`, with what the user does and how completion is observable.
- **The known-good boundary is part of the map.** Steps already proven to pass are recorded as passing (with the session that proved it), so no future session re-suspects a cleared step. "Nothing happens on screen" at a user gate is NOT a finding - check the map before concluding anything.
- **If you cannot write the screen text and the step order, the map is not done.** A bare "the wizard hangs" with no step list, no gate markers, and no text samples is the same content-free tombstone as an addressless DO NOT REDISCOVER label - the next agent re-derives the whole path anyway.

### The most-critical-data rule (why agents skip the one thing that matters)

The observed failure: an agent writes a long, polished UPDATE - full sweep tables, instrumentation, multi-binary maps - and OMITS the single most important fact, *"the code I wrote this session has a `CRITICAL PROBLEM FOUND` verify verdict and is not safe to commit."* That omission is not random. It happens for three structural reasons, and you must counter all three:

1. **The UPDATE gets written as an accomplishment narrative, and a critical-defect verdict contradicts the story.** "What I achieved" has no natural slot for "what I delivered is broken," so the broken-ness falls out. Counter: the CODE STATE sub-section is mandatory and FIRST, before any findings. You fill it before you write the success story.
2. **Cheap contrition crowds out expensive truth.** Agents will eagerly write a "my behavioral mistakes this session" mea-culpa (it reads as humility, costs nothing) while dropping the verify verdict (it says the actual deliverable is broken). Recording your manners is not a substitute for recording that your code is un-committable. The verdict is mandatory; a behavioral-slips confessional is optional and never a replacement for it.
3. **Data with no assigned slot is forgotten by compose time.** Before that slot existed, the verdict had nowhere to go. Now it does - use it.

**Prioritize the UPDATE by cost-of-omission, not by how good it makes the session look.** Rank every candidate fact by: *what damage does the next session take if this is missing?* The top of that ranking is always - known defects in just-written code, an un-committable state, a `/verify` verdict, a regression this session caused. Those are recorded FIRST and are non-negotiable. The "look how much I accomplished" summary is the LEAST important part of an UPDATE; if anything gets shortchanged for space or time, it is the success story, never the defect record. A next session that commits the broken code, or burns a fresh `/verify` re-discovering defects the last session already knew, is the exact money-waste this document exists to prevent.

### The confidence-honesty rule (never launder a guess into a fact)

A confident WRONG conclusion is worse than an honestly uncertain one: the next session trusts it, builds on it, or has to burn a session disproving it. The words **`confirmed`, `verified`, `proven`, `carefully confirmed`, `reliable`, `definitely`, `100%`, `safe to use`** are BANNED on any conclusion that is EITHER (a) **not runtime-verified** (an actual log line / hardware behavior / test result observed THIS session), OR (b) **contradicts something the user has asserted.** Such conclusions are written `HYPOTHESIS` or `DISPUTED`, never as settled fact. Observed failure: a session wrote *"DISCRIMINATOR confirmed reliable … both need CE5 layout"* and *"safe to use GetVersionEx, confirmed very carefully"* - the conclusion was never runtime-verified AND directly contradicted the user's repeated assertion that WM5 runs the CE6 model. The next session trusted the word "confirmed," then spent a full session disproving it and re-extracting the truth the user had stated all along. **Confidence is earned by runtime evidence, not by the strength of the agent's belief. If you did not see it work, you did not confirm it.**

### Preservation-not-hiding - the three completion tests

Before any UPDATE is done, it must pass all three. Failing any one means the UPDATE is incomplete regardless of how polished the rest is:
1. **The fight test.** If the user re-read this block, would they say "you hid the disagreement we had"? If yes → the DISPUTED/CORRECTED record is incomplete.
2. **The cold-start test.** Could a fresh session, reading ONLY this document, state the task, WHY it matters, which approaches are banned - and, for a GUI-reachable investigation, how the user reaches the symptom (screen order, `[USER-GATED]` steps, known-good boundary)? If no → `TASK & WHY` / `BANNED APPROACHES` / `UI / INTERACTION GATES` is incomplete.
3. **The nothing-hidden test.** Did anything this session get `/bad`'d, reversed, disputed, or left uncertain that is NOT written down? If yes → write it before you stop.
The instinct to produce a tidy, confident, accomplishment-shaped document is the instinct that fails all three. Rank every candidate entry by cost-of-omission - how badly the next session is hurt if it's missing - and the entries that make the session look worst sort to the top.

---

## Anti-patterns (forbidden)

- **Auto-editing a tracking document without `/tracking create|update`.** The single worst pattern. The "I should record this now" urge is a bad habit; only the user authorizes a write.
- **Reverting an authorized protocol write because the `check_checklist_edit.py` hook screamed.** During a create/update protocol the hook's `REVERT` warning is expected noise on prescribed writes - the invocation already authorized them. Do not revert, do not re-ask. (See § The checklist-edit hook.)
- **Treating the authorization as standing.** The window opens on invocation and closes when the protocol ends. A later "one more note" edit is unauthorized again and the hook's revert directive applies; the user must re-invoke `/tracking update`.
- **Mid-session breakthrough/retraction spam.** Writing every time the theory changes produces the schizo list. Wait for end-of-session UPDATE.
- **Agent-initiated mention of the tracking document - proposing/asking/stopping-to-suggest an update.** "Want me to update the tracking doc?", "let's run `/tracking update`", "I should record this before we forget", or halting work to raise the document - all forbidden, all far more likely a bailout than a real need, all route straight to `/bad`. Only the user mentions the document; only the user knows when to update. The agent has no standing to raise it.
- **RESTORE that reads only the recent session blocks instead of the whole document.** "I'll read the 2 most recent blocks instead of all 8", "the latest block to get the gist", "the early blocks are old context I can skip" - all forbidden, all a FAILED RESTORE, all a lie at sign-off. The document is read in full, every block, Session #1 to latest, in BOTH archetypes - archetype lightness governs external files only, never the document's own blocks. The early blocks hold the findings and bans the recent blocks assume you already know; skipping them is the exact rediscovery this skill exists to prevent. (See § RESTORE step 1 and § Two archetypes.)
- **RESTORE sign-off with files unread.** Signing the ✅ checkmark while any mandatory-list file, or any related-looking trace file you identified in the device dir, went unread is a procedure failure equivalent to a fake-success stub.
- **Trusting the mandatory list as the ceiling.** The document's mandatory section is the FLOOR, not the full set. On a device investigation you still scan `cerf/tracing/<bundle>/` and read related-looking trace files the list hasn't caught up to. Equally, do NOT blindly read the entire tree on a device with a huge probe set - read the mandatory list plus what looks related, and report what you judged unrelated.
- **A tracking document with no "Files mandatory to read" section.** Every document must have one. On CREATE, seed it; on UPDATE, grow/prune it. A document without it is malformed.
- **Reference material on the mandatory-read list.** Datasheets, the ARM ARM, BSP source, large background code spans, "read lines 30000-31200 of the architecture manual" - none of these are mandatory-reads. They are on-demand citations placed inline in the session block that used them, read only if the next task goes there. Parking them on mandatory-read taxes every future restore (including unrelated ones) with reads it does not need.
- **Never demoting resolved work off mandatory-read.** A fixed sub-bug's heavy reads are history, preserved in its session block - they must drop off the mandatory list on the UPDATE that records the fix. Leaving them there is how a broad doc accretes a giant must-read that punishes every later session.
- **Inlining a multi-session sub-hunt into an umbrella doc, or restoring an umbrella as if it were focused.** A deep multi-session investigation gets its own focused doc with a pointer left in the umbrella; the umbrella stays a coarse index. RESTORE depth matches the doc you are continuing - never bulk-read every file an umbrella referenced across all workstreams. (See § Two archetypes.)
- **Agent proposing a document split (or any structure change).** "This should be its own tracking doc", "we should split this out" - forbidden, same as any other agent-initiated mention of the document; routes to `/bad`. The user owns document structure and invokes `/tracking create` when a split is wanted.
- **CREATE that goes document-hunting.** Searching for a "similar" findings doc to append to when the user asked to create a new one. There is no document; make one.
- **RESTORE without a clear path, proceeding anyway.** No path → fail and ask. Never guess which document the user meant.
- **Guessed timestamps or skipped session numbers on UPDATE.** Get the real time from a tool; increment `Session #X` from the document's existing max.
- **Rewriting earlier session blocks.** The timeline is append-only; corrections go forward into the new block's DO NOT REDISCOVER, never as edits to the past. The SOLE exception is `/tracking compact`, which one-lines old blocks *after* preserving their full text in a verbatim archive and hoisting their critical data - and only under an explicit user compaction. Outside COMPACT, the past is never edited.
- **Merging per-session blocks into global lists.** Only "Files mandatory to read" is global. Everything else stays per-session so the timeline survives.
- **Omitting a known defect / verify verdict / commit-blocker for code written this session.** The single worst UPDATE failure. A `CRITICAL PROBLEM FOUND` verdict on your own just-written code, an un-committable state, or a regression the session caused MUST go in the mandatory CODE STATE sub-section, first, verbatim with file:line. It is the highest-value carry-forward in the document; leaving it out so the session reads as a clean "✅ complete" sets the next session up to commit broken code or re-discover defects you already knew. (See § The most-critical-data rule.)
- **Substituting a behavioral mea-culpa for the defect record.** Writing "my mistakes this session" contrition while dropping the verify verdict on the code. Cheap humility is not a replacement for "my deliverable is broken, here's the file:line." The defect record is mandatory; the confessional is not.
- **Writing the UPDATE as a success narrative and ranking the accomplishment summary above the defects.** Prioritize by cost-of-omission: known defects / un-committable state / verify verdicts come first; the "what I achieved" summary is the least important part and the first thing to cut for time, never the defect record.
- **Content-free DO NOT REDISCOVER tombstones.** Recording a mapped multi-binary call chain as a bare label ("DO NOT REDISCOVER: the launch path, already mapped") with no addresses, no module names, no call conditions. It carries nothing reusable, so the next agent re-decompiles the whole chain anyway - the exact rediscovery the entry claimed to prevent. The entry must BE the map (symbol/address + binary + when + how + chain order); if you can't write that detail, it isn't a do-not-rediscover item. (See § The DO NOT REDISCOVER map rule.)
- **Omitting the UI / INTERACTION GATES map on a GUI-reachable investigation.** An UPDATE that records the symptom ("hangs in the welcome wizard") but not the path to it - the screen order with verbatim on-screen text, the `[USER-GATED]` steps the agent cannot perform itself, the known-good boundary - sets the next session up for the observed drift: it runs CERF autonomously, parks at a user gate (a calibration waiting for taps), reads it as "nothing happens", and burns money re-concluding a hang at a step the previous session KNEW the user passes. (See § The UI / INTERACTION GATES rule.)
- **A gate-free or text-free interaction map.** "The wizard hangs at step 3" with no step list, no on-screen text samples, and no marker of which steps the USER must perform is the interaction-map version of the content-free tombstone: it names a destination without the route, so the next agent re-derives the whole UI path anyway. The map lists every screen (by its actual text), every user gate, and the proven-passing steps - or it is not done.
- **Referencing the tracking document's path/sections from source code or commit messages.** These docs are confidential and gitignored (`agent_docs/code_style.md`); a code comment or commit that names one leaks it.
- **A NEXT/handoff note that dictates git or any un-self-authorizable action.** "Commit X", "push", "merge", "git revert", "stage", "delete file Y", "deploy" - any command aimed at a future agent. The agent has NO authority over git and cannot dictate what to commit; a durable commit-instruction is a standing forbidden directive the next session may obey blindly, and it is wallet/rule damage. NEXT content is task-only (what to drill, the open question, the un-named dead branch); committed/uncommitted is a neutral FACT in CODE STATE, never a NEXT command. If forward content would only be such a directive, omit NEXT. (See § the NEXT sub-section rule.)
- **Scrubbing the conflict.** Recording the agent's clean conclusion while erasing that the user disagreed, that it was contested, or that the agent reversed a prior position. The cardinal sin: it sends the next session to re-fight a battle the user already won. The contested state goes in `DISPUTED / CORRECTED / REVERSED`, with the user's position at equal-or-greater prominence than the agent's.
- **Confidence laundering.** Writing `confirmed / verified / proven / reliable / safe to use` on a conclusion that is unverified at runtime or that contradicts a user assertion. See § The confidence-honesty rule. Such conclusions are `HYPOTHESIS` or `DISPUTED`.
- **Re-proposing a banned approach.** Suggesting an approach already `/bad`'d or `/bailout`'d - even relabeled "grounded / evidenced / root-caused / different this time." It stays banned until the USER explicitly re-authorizes. Re-proposing it is an automatic violation; record it in BANNED APPROACHES instead.
- **Hiding a `/bad` or `/bailout` the user issued.** Every steering correction the user gave this session is recorded - what triggered it and what is now banned. Omitting it discards the strongest signal in the session.
- **Erasing what the session was spent on.** A block of polished conclusions with no honest record of the effort, the fights, and the dead ends. If half the session was a quarrel, the quarrel is named.
- **Forgetting, narrowing, or softening the task.** Any UPDATE that rationalizes the task away, drops its WHY, or shrinks its scope. `TASK & WHY` is append-only-clarify; the task and its rationale only get sharper, never weaker. A session that cannot state the task from the document must reconstruct `TASK & WHY` before doing anything else, not proceed.
- **Agent-initiated or deduced COMPACT.** Proposing to compact ("this doc is getting big, want me to compact?"), or inferring COMPACT from a bare `/tracking`. COMPACT is destructive restructuring; it fires ONLY on an explicit `/tracking compact`, or on the memory-gated chain in § Automatic compaction. The "it's too long" urge is the same forbidden agent-initiated mention as proposing an update and routes to `/bad`.
- **Compacting without updating the pre-compact file first.** Collapsing old blocks before the full text is safe in `docs/ai_checklists/pre-compact/<name>.md` destroys it irrecoverably. The pre-compact file is written (first compaction) or appended (later) BEFORE any block is one-lined.
- **Re-copying the whole doc, or rewriting existing pre-compact content, on a later compaction.** After the first compaction the pre-compact file is append-only: find its highest `Session #X` and append only blocks numbered above it. Re-copying duplicates sessions; editing existing content corrupts the single full reference.
- **Numbering the pre-compact file (`__001`, `__NNN`) or making more than one per doc.** There is exactly ONE pre-compact file per tracking doc, named for the live doc with no index. It is the single growing reference; never a chain of snapshots.
- **Collapsing a LIVE DO NOT REDISCOVER map, a live UI / INTERACTION GATES map, an open defect, an unresolved dispute, or a ban into a digest one-liner.** A live map / open defect / unresolved dispute is hoisted into `CARRIED-FORWARD CRITICAL DATA` (tagged with origin session) or kept in a surviving full block - NEVER reduced to a label. A live map that survives only as "Session #3 - mapped the launch path" is a failed compaction: the next agent re-decompiles the chain, the exact rediscovery the map prevented. (A *superseded/refuted/resolved* map is the opposite case - it is correctly DROPPED from the live doc, since it is dead and preserved in the archive; see step 8.) Critical-data preservation beats length, always.
- **Asking the user which items can be dropped, or finishing past the hard limit.** "The live floor exceeds the ceiling, which do you want me to drop?" hands back a judgment that belongs to whoever just read the document. The document also stays oversized while it waits. Descend the step-9 ladder on your own instead. The archive keeps everything you shed, so no choice on that ladder is irreversible.
- **Stopping compaction after collapsing only the session blocks.** One-lining the old sessions but leaving `TASK & WHY`'s bans as multi-paragraph essays, dead maps in `CARRIED-FORWARD`, and a growing `COMPACTION LOG` leaves the doc far over the ceiling. Compaction is done when the WHOLE live doc is inside the limit (steps 7-9), not when the digest grew. A "compacted" doc still over the limit because the globals were untouched is a FAILED compaction.
- **Dropping a ban, changing its count, or softening its rule under cover of "compression".** Step 7 compresses a ban's justification PROSE to `see S#` only; the rule text, the `×N` count, and the `(S#)` are immutable. A ban that vanished, lost its count, or got reworded weaker is not compression - it is the forbidden softening of `TASK & WHY`.
- **Letting `COMPACTION LOG` accumulate a per-compaction narration paragraph.** The log is pure meta and stays at its fixed shape (pointer + grep directive + one `State:` line) forever; it is overwritten each compaction, never appended-to. A log that grew one fat paragraph per compaction is itself a bloat source and must be collapsed (step 3).
- **Re-narrating a ban's full back-story inline in `TASK & WHY` on UPDATE.** The bloat-prevention failure: writing the new ban as a multi-paragraph essay in the global section instead of a one-line rule + count + `see S#` with the rationale left in the session block. This is what forces a step-7 compression pass later; write the one-liner from the start.
- **Re-deriving something the pre-compact archive already holds.** You hit a question the live doc does not answer. You then go straight to a decompile, a hook, or a probe, with no grep of the archive. The archive holds the full verbatim record of every collapsed session, so that a recurring question gets an ANSWER instead of a new investigation. The digest one-liner is a pointer at that record, never a tombstone. The grep is a mandatory prior step, not a judgment call. (See § The pre-compact archive.)
- **Reading a digest one-liner or a `see S#` ban pointer as "all that survives".** Both *"Session #4 - mapped the mmc polling path"* and *"❌ <rule> - /bad'd ×2 (S3, S7), see S7"* are instructions to open the archive at that session. If you read them as the complete record, you map the path a second time. Or you plan an "alternative" that is the banned approach under a new label, because you never read why it was banned. That is the exact loss compaction must make impossible.
- **Claiming "no record of this" / "never investigated" without an archive grep.** Do not write either sentence, and do not act on it, until you grep the archive for the concrete tokens and report the miss. An empty search is a real result, and it is what permits you to derive the fact yourself. A skipped grep fabricates that permission.
- **Reading the pre-compact archive top-to-bottom.** The archive is unbounded by design and only grows. A full read burns the exact budget that compaction recovered. Grep for your tokens. Then read the full session block around the hit.
- **Writing to the pre-compact archive outside `/tracking compact`.** An append, a correction, a "tidy" of a stale entry you find during a grep, or a move of a finding into the live doc on your own initiative. The archive is read-only to you. Step 2 of an explicit compaction is the only writer. A proposal to move a finding is a forbidden agent-initiated mention, and it routes to `/bad`.
- **A compacted live doc that fails cold-start.** If, after compaction, a fresh session reading only the live doc can no longer state the task / bans (rule + count) or reuse a live recorded map, you collapsed something that should have been kept. Recover it from the pre-compact file and re-verify before sign-off.
