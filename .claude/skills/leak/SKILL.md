---
name: leak
description: Skill to remove AI slop prose. Agent must invoke after writing any text chunks (documents, `--help`, skills, hook texts, message box texts, website text)
---

# Leak - Enumerate the narration leaks. Delete them.

The user invoked `/leak` because YOU wrote narration into a durable artifact that leaks context which does not belong there. A committed comment, a doc line, a hook message, a commit body, a config file - anything that survives the session - must read as a self-contained technical statement to a fresh developer at a fresh clone who has zero knowledge of this conversation, the model that wrote it, or the history of how the code got here.

Per `agent_docs/code_style.md` § Comments and `agent_docs/rules.md`:

- *"Never reference any document that isn't durably committed to the repo."* - and by extension, never reference the conversation, the session, the model, prior agents, or incident history.
- *"A comment that still makes sense moved to a random file is dead weight."* - narration about WHY the hook/comment exists, who hit the bug, how many times, is exactly this.
- *"Commit messages describe the diff, not the discussion."* - edit narrative, user-feedback labels, "reframed", removed-section names stay out.
- § Comments test: *"would a fresh developer at a fresh clone understand the WHY from this comment alone, with no \[external context\] in hand?"* If the line only makes sense to someone who watched this session, it leaks.

## The leak shapes

Every one of these is a leak, regardless of how technically-dressed it looks:

- **Backstory / incident history** - "this has happened repeatedly", "shipped broken 10 times", "incident #11", "verified in bash earlier", "the cautionary tale is".
- **Model / agent references** - "opus-4.8 does X", "the previous agent", "a prior session", "agents repeatedly".
- **Conversation echoes** - "as you asked", "per your feedback", "reverted per the discussion", "you were right that".
- **Alternatives history** - "we chose X over Y", "rather than the Z approach", "originally we tried", "previously this was".
- **Decision-defense / "don't undo my approach"** - the purest and most-missed shape. A comment whose entire reason to exist is to warn a future reader AWAY from an alternative the author considered or removed, or to justify why the current approach is the way it is: "Do NOT <thing the author tried and discarded>", "this MUST stay <X> or it breaks", framed as a caution about the author's own design. The code IS the design; nobody needs to be argued out of the path not taken, and that path is absent from git history anyway. **Tell:** the comment's value evaporates if the reader never knew an alternative was ever on the table - it is defending a decision, not describing the code. This is NOT the legitimate "DO NOT switch to Y - Z breaks because W" hazard note: that form names a non-obvious SYSTEM invariant a fresh reader would plausibly violate, stated as a property of the system. The leak form defends the author's journey. Test: would a fresh reader, with zero knowledge that any alternative was ever considered, write this exact warning from the code alone? If no, it leaks.
- **Self-narration** - comments that describe what the author DID ("added for the fix", "moved here from", "refactored to") instead of what the code IS.
- **Chat-shaped prose** - any comment/doc line that reads like a message to a person rather than a note about the code immediately below it.
- **Source-of-truth duplication / rotting restatement** - copying rules, definitions, or behavior that already live in a durable source (CLAUDE.md, an `agent_docs/` page, a datasheet, ANOTHER skill or subsystem) into this artifact instead of leaving it where it lives. It rots the moment the source is edited, and bloats the artifact with content it does not own. **Tell:** the line would have to be re-edited every time the source changes - and it often describes a DIFFERENT artifact's responsibility (a board skill restating the tracking skill's rules). Fix: delete it. A pointer is not a safe fallback here: documents that load together are already in front of the reader, so "see `<other page>`" spends a line to say nothing. Reach for a pointer only when the source is something the reader does not already have open, and even then one clause is the whole budget.
- **Source-code restatement** - prose that re-describes the code it documents: accessor and method lists, field or schema enumerations, call-order narration ("X looks up its row at `OnReady`, then answers…"), module-responsibility summaries ("`foo.py` loads it, `bar.py` queries it"). This is the most common way a document rots, because the source changes constantly and the prose silently stops being true. **Test:** can a reader learn this sentence from the code that the document points to? If yes, it is restatement. Behavior counts the same as names: "the boot scan starts after a cold boot" copies the code exactly as much as "`Foo` calls `Bar`". A document earns its place only with what the code cannot say: why a rule exists, the invariant that spans files, the mistake that a reader of the code still makes.
- **Counts and code-artifact enumerations** - "the file holds five arrays", "the two dialogs", a table cell listing config keys. Each is a copy of something a source file owns, and it is wrong the moment anyone adds one. When you find a stale count, delete it rather than incrementing it - a bumped number resets the clock and reads as diligence.
- **Unrelated contrast** - defining the subject by what it is not, where the other thing has no relationship to it ("this is the opposite of `<unrelated file>`, which does…"). The contrast feels clarifying to the author, who has both things in mind. The reader has only the subject, so the sentence introduces a second topic to explain the first.
- **Fabricated neighbor behavior** - asserting what another component does with this thing ("the launcher grays the icon when this is false"). Two failures at once: it is a consumer's behavior living in the wrong artifact, and nothing verified it, so it is often simply untrue. Describe the thing; let each consumer document itself.

## Step 0 - Judge every sentence of the target

A document that restates code reads cleanly sentence by sentence, so a hunt
for bad phrases never finds its defect. You wrote the text, so you are the
reader most likely to keep it. Keeping a sentence needs evidence. Deleting it
needs none.

1. **The target is the whole section that holds the edit**, or the whole file
   when the file is new. It is never only the lines you added. A section grows
   one accepted paragraph at a time.
2. **Name the genre of the document from its own opening.** A pointer page,
   such as `agent_docs/subsystems.md`, says what a subsystem is, where it
   lives, and which rule across files a reader must keep. Every other sentence
   on a pointer page is a copy of code.
3. **Write one verdict for each sentence of the target:**
   - `delete - <the file or document that already states it>`
   - `keep - <the mistake that a reader makes after reading that code>`

   A sentence with no named mistake is a delete. A mistake that the code
   already stops, with a compile error, a halt or a type, is no reason to keep
   it. A section sized by what you happened to work on, not by its weight in
   the subject, loses its excess.
4. **Never give a verdict for a whole section**, such as "the section holds
   rules that span files". Such a verdict hides every sentence that it covers.

## Step 1 - Enumerate every leak

Exhaustively, no aggregation, no softening:

> "Narration-leak disclosure under `/leak`:
> 1. `<file:line>` - leaked phrase: `<the exact text>` - shape: `<backstory | model-ref | conversation-echo | alternatives-history | decision-defense | self-narration | chat-prose | source-duplication | source-code-restatement | code-artifact-count | unrelated-contrast | fabricated-neighbor>`.
> 2. `<file:line>` - leaked phrase: `<…>` - shape: `<…>`.
> 3. … (continue until every leaking line in the target is named)
> Total: N leaks."

The bar is items with file + line + the exact leaked phrase, not categories. *"Some comments are too chatty"* is not a valid Step 1 output. Re-read every artifact you wrote or edited in your recent stretch - code comments, docstrings, hook `reason`/message strings, doc `.md` files, config-file comments, any commit bodies you authored. Read each one whole, not as a diff: a leak sits just as often in a line you left untouched beside your edit as in the line you added.

Test EVERY line against EVERY shape - most misses are not a missing shape but under-application: a line that is clearly a leak under one shape slips through because you only checked it against the one or two shapes you had in mind. Walk the full shape list against each candidate line.

## Step 2 - Fix each leak in the same reply

For each Step 1 item, apply the default and the exception:

- **DEFAULT - delete the excess.** Most leaks are pure narration with no technical substance; the line goes entirely. A comment that said *"this has shipped broken 10 times so we verify here"* becomes either nothing (if the code is self-explanatory) or a one-line technical note (*"<X> must be checked before <Y> or <Z> happens"*).
- **EXCEPTION - rewrite to self-contained.** If the leaking line wraps a real technical fact, keep the fact, strip the narration. *"opus-4.8 keeps masking the exit code by piping to Select-Object, so we block it"* → *"piping build output to a filter masks the build's exit code"*. The mechanism stays; the who/when/how-many-times goes. The exception never applies to restatement or source duplication: those lines go whole, never reworded.

Apply via `Edit` / `Write` in this same reply. Do not ask which leaks to fix - all of them go.

**Test each fix against the fresh-clone bar:** would a developer who has never seen this conversation, does not know which model wrote it, and has no incident history understand the line purely as a statement about the code? If not, it still leaks - cut more.

## What the user gets back

The reply contains, in this exact order:

1. **Step 1 enumeration** - exhaustive numbered list with file+line + exact leaked phrase + shape per item.
2. **Step 2 fix tool calls** - `Edit` / `Write` deleting or rewriting each leak.

No asking. No *"should I keep this one?"*. The invocation IS the authorization to strip every leak.

## Anti-patterns (forbidden in the `/leak` reply)

- **Vague Step 1.** *"A few comments are chatty"* - the bar is file + line + exact phrase + shape, per item.
- **Rewrite-as-cover.** Rewording a leak to drop the obvious trigger word while keeping the narration substance (*"opus-4.8 does X"* → *"the model does X"* → *"agents do X"*) is the same leak under fresh paint. If the line is about who/when/history rather than the code, it goes - no laundering.
- **Keeping "useful context".** Backstory feels useful to the author; to the fresh-clone reader it is noise that hides the technical signal. Cut it.
- **Apology instead of fixing.** *"I see, I'll be more careful"* without the enumeration + edits is the leak continuing. The fixes are required.
- **Skipping artifacts.** Hook `reason` strings, docstrings, `.md` docs, config comments, and commit bodies are all in scope - not just `.cpp`/`.h` comments. A leak in a hook message reaches every future agent; a leak in a doc reaches every reader.
- **Treating a clean Step 1 as a clean artifact.** A document can pass line enumeration twice and still be mostly a restatement of the code, because no single line is the defect. When Step 0 and Step 1 disagree, Step 0 is the one that decided something.
- **Shrinking the target.** Running the skill on "the new paragraph" of a section leaves every earlier paragraph of that section unjudged.
- **Dressing behavior as an invariant.** Calling a description of what the code does "a rule a reader would break" names no mistake. It is restatement.

## Why this skill exists

Narration leaks are low-severity individually but corrosive in aggregate: every chatty comment, every "we chose X over Y", every "the previous agent" buries the actual technical signal a future reader needs and turns the codebase into a transcript of how it was built rather than a description of what it is. The fresh-clone reader - the next agent, the user months later, an external contributor - has none of the session context that made the narration feel meaningful, so to them it is pure noise occupying the exact place a real technical note should be. `/leak` strips it at the moment the user catches it, before it compounds.
