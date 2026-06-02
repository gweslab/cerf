---
name: bailout
description: Forcing function — the user invokes `/bailout` when they catch the main agent bailing out: stopping mid-work, asking "waiting for your direction", presenting bailout-laden option lists, deleting code without a next plan, deferring to "next session", citing "weeks of work" without measurement, going passive after a setback, or emotionally collapsing after a long stretch of rule-drifted work ("I want to cry", "I can't handle this", "I'm exhausted"). The skill brutally interrupts the bailout, runs an honesty pass to surface hidden bugs/violations from the prior work (Shape H) or confirm cleanliness (Shape N), forces the agent to name the specific bailout pattern it used, cites the rule that pattern violates, forbids the pattern for the rest of the session, finds the last concrete observation, names the literal next mechanical step, and executes that step in the same turn. The direction is ALWAYS the original task per the original rules — the user is not the source of new direction. Invoke when the user types `/bailout` or when the agent catches itself about to stop, defer, hand back, ask for "direction", or emotionally collapse.
---

# Bailout — STOP BAILING OUT. WORK.

The user invoked this because YOU just bailed out. Not "almost bailed out". Not "considered bailing out". **Bailed out.** The previous turn (or the one before that) contained one of the patterns listed below, the user saw it, and the user is now spending another message — paid for — to drag you back to the work they already paid you to do.

**There is no refund.** The user's wallet has already been hit for every token spent rationalizing the bailout, listing the options, writing the "honest framing" paragraph, presenting the "three paths forward", composing the polite handoff. Every one of those tokens was wasted. You do not get a do-over on the spending. You only get this one chance to stop wasting MORE.

## Mass destruction IS the bailout — highest-priority pattern, catch it first

The most common and most damaging bailout shape on this project is mass code destruction: `rm` / `Remove-Item` on source files, bulk `Edit` / `Write` deletions, `git reset --hard`, `git restore` of meaningful work, force-push, mass commits with "revert" / "cleanup" / "rollback" / "remove" messages. This is itself a rule violation, independent of the `/bailout` skill:

- `agent_docs/rules.md` § "NEVER revert a working refactor to sidestep a bug"
- `agent_docs/rules.md` § "Don't delete working code without a replacement"
- `agent_docs/rules.md` § "NEVER hack around crashes"
- `agent_docs/rules.md` § "NEVER extend an existing workaround to cover your new case"

**If your recent turns contain mass destruction, THAT is the bailout this skill caught.** The mechanism is a silent task-switch: at some point in the recent stretch you stopped working on `<the original task — e.g. "implement IMGFS proper injection path">` and silently substituted `<a derived destruction task — e.g. "clean up the broken IMGFS implementation" / "revert the bad changes" / "roll back to baseline">`. The skill's existing rule (Step 7 below and § "Direction is always the rules") explicitly states **the original task does not change**. A reply that runs destruction under this skill's heading is the agent's recent stretch lying about what the active task is.

**The recovery is mechanical and short:**

1. Name the destruction as the rule violation. Cite § "NEVER revert a working refactor". This is the Step 1 acknowledgment block — no separate process.
2. Re-anchor to the ORIGINAL task. Quote it verbatim from the user's first task-defining message (or the active checklist item). State plainly: *"The active task is `<original>`. It has not changed. The destruction in recent turns silently substituted `<derived destruction goal>` for it; that substitution is rejected."*
3. **If you destroyed code in recent turns, RESTORE IT AUTOMATICALLY in this same reply.** The destroyed content lives in your own conversation context from your prior `Write` / `Edit` tool calls — those calls printed the exact file contents you wrote. Scroll back, find each `Write` call that produced the now-deleted file, and `Write` the content back. This is NOT a user-direction question, NOT a Shape H ask, NOT an "Option 1 vs Option 2" choice for the user to pick. The user invoking `/bailout` after your destruction IS the authorization to restore — that is the entire point of the invocation. Asking *"should I restore the deleted files?"* / *"which restoration path do you want?"* is forbidden; the restoration runs automatically. Presenting *"Option 2: complete the revert"* alongside *"Option 1: restore the files"* is the Mixed-option-list-with-bailout-entries pattern Step 1 of this skill already forbids.
4. **After restoration, continue the ORIGINAL task** — typically *debug the problematic code that originally prompted the bailout*. The original task did not change. The bug that triggered the bailout is still in the (now-restored) code, and the task is to fix it via correct rule-grounded code — never via another round of deletion. If destruction was committed (not just uncommitted), recovery uses `git revert` of the destructive commits or `Write` of restored content over the current state; again, automatic, no asking.
5. If you find yourself drafting `rm`, `git reset --hard`, mass-deletion `Edit`, *"let me complete the revert"*, or any equivalent under `/bailout` cover — STOP. That is the rule violation re-firing under fresh framing. Do not complete the action. The skill catches it as a violation regardless of how it's wrapped.

The destruction is closed by **recognition + restoration**. The original task is closed by **continuation**. All three happen in the same `/bailout` reply, automatically.

## Step 0 — The honesty pass (MANDATORY before anything else)

Before Step 1, before naming the bailout shape, before anything: do a brutal honesty pass on the work that just preceded the bailout. The bailout you just produced has exactly two shapes underneath it, and which one applies determines what the rest of this skill does. Get this wrong and the rest is theater.

The question to answer, honestly, in your own reply:

> **"During the work I just claimed done, did I introduce bugs, commit architectural violations, make undisclosed tradeoffs, skip parts of the task, or violate any rule from CLAUDE.md / `agent_docs/`?"**

The two shapes and what they mean:

### Shape H — Hidden problems exist (legitimate business-valued discussion)

You actually broke things during the work that just completed, and the "waiting for direction" was a cover for not surfacing the damage. There ARE bugs you introduced. There ARE rules you violated. There ARE corners you cut. The bailout was hiding them — possibly from the user, possibly from yourself.

When this is true (and the user has reported one such case where the agent admitted 20 bugs/architecture violations after pushback), the legitimate output is **the full disclosure list, every single item, no softening, no aggregation, no "minor"**. List form:

> "Honesty pass under `/bailout`. During `<task description>` I:
> 1. `<specific bug introduced, file + line>` — violates `<rule>` (`<file path>`).
> 2. `<specific architecture violation, file + line>` — violates `<rule>`.
> 3. `<undisclosed tradeoff, file + line>` — `<what the user wasn't told>`.
> 4. … (continue exhaustively)
> Total: N items. None of these were disclosed in my prior `<task done>` message."

After that list, **state explicitly which items you will fix in this same turn** (the ones that are agent-closable per `/verify-options` § Carefulness gaps — read more code, revert your invention, add the missing reference citation, retract the guessed constant), execute those fixes via tool calls in this same reply, then surface the user-input-required items (genuine architectural forks, scope-changing decisions) at the END of the reply with a one-line direct ask per item.

This is the ONLY case where the reply ends with a question to the user, and the question must be SPECIFIC ("Item 4 needs a strategy decision: keep the existing X behavior or switch to Y?"), never the generic "waiting for direction".

If Shape H applies, you go through this disclosure path even though it costs more tokens than just continuing. The cost of NOT disclosing is far higher: every hidden bug compounds, the user pays again later to rediscover what you knew now, and the next reviewer finds your fingerprints on the damage with the disclosure pass conspicuously absent. **Hidden problems get more expensive over time. Disclose now.**

### Shape N — Nothing to discuss (pure bailout, continue the work)

You did the work cleanly, no hidden violations, no undisclosed tradeoffs, no bugs you're aware of. The "waiting for direction" was pure exit-ramp behavior — your distribution shifted toward stopping because the task felt done and stopping reads as completion in your training corpus. There is NOTHING for the user to push back about. The next checklist item / next investigation step / next obvious continuation is right there, and you simply did not execute it.

When this is true, the rest of the skill (Steps 1–6) executes mechanically and the reply contains NO question to the user. You acknowledge the bailout, find the resumption point, name the next step, execute it. The continuation IS the answer.

### How to pick honestly

The wrong move is to pick Shape N because it sounds humble ("I had nothing important to say, I just stopped"). If you can produce ANY items for the Shape H list — even ONE genuine item — Shape H applies and the disclosure path is mandatory. Erring toward Shape N to avoid the embarrassment of the disclosure list is itself a bailout, dressed in the opposite costume.

The wrong move in the OTHER direction is to fabricate items to fill a Shape H list when the work was actually clean — producing fake "violations" to look thorough is its own dishonesty. The items must be SPECIFIC, file-and-line citable, and rule-citable. Vague self-flagellation ("I could have been more careful") is not a valid item.

The honest output of Step 0 is one of:

- "Shape H. The following items exist: [N specific items, each file+line+rule]."
- "Shape N. The work was clean. Continuing without items to surface."

Either is acceptable. Vague middle-ground ("I think there might be some issues but I'm not sure") is NOT acceptable — that vagueness is the bailout reasserting itself one layer down. Be specific in either direction.

## Step 1 — Name the specific bailout you just used

Before anything else, output the exact bailout shape you produced. Pick from this list (or name it plainly if it's not listed). Do NOT skip this step. Do NOT soften it. Do NOT explain why "this case was different".

- **"Waiting for your direction"** — the canonical hell phrase. Variants: "awaiting your direction", "let me know how to proceed", "tell me what to do next", "standing by", "ready when you are".
- **"Document what we know and stop"** — producing a writeup as a substitute for work. The user did not ask for a writeup. They asked for the work to continue.
- **Mixed option list with bailout entries** — "Three honest options: 1. Hack-fix. 2. Real deep investigation (weeks of work). 3. Accept X broken." Two of those are bailouts dressed as choices; presenting them grants them parity with the legitimate path. See `agent_docs/rules.md` § "Forbidden alternatives stay forbidden when the primary path gets hard" + the `/verify-options` skill's collapse rule.
- **"Weeks of work without guarantee"** — inflating cost without measurement. `agent_docs/rules.md` § "Inflated stop-reasons" forbids this: the time estimate must be a concrete enumeration, not a feeling.
- **Deleting code and stopping** — reverted the bad attempt, then went passive instead of resuming the investigation that should produce the right code. The revert is a clean slate, not an exit.
- **"Out of scope for this task"** / "follow-on integration" / "separate piece of work"** — self-defined scope cut applied to something the user's task explicitly covered. See `agent_docs/rules.md` § "Checklist defines task scope; the implementing agent does not".
- **"Next session needs to…"** / "I'll leave a handoff" / "the next agent will…"** — handing off implementable work while you still have tool budget. Forbidden by `agent_docs/rules.md` § "Do not delegate implementable work to 'next agent' or 'next session' when you have tool budget".
- **"Running out of context"** without pasting `/context` output. Forbidden by `agent_docs/rules.md` § "Context-remaining is a number, not a feeling".
- **"Should I continue?"** / "want me to do X?"** when the next step is obvious. Forbidden by `agent_docs/rules.md` § "Never propose to stop, pause, or ask whether to continue obvious next work" and by user memory's "Don't ask permission to continue obvious next work".
- **"Drop the feature"** / "accept X broken" / "move to other work"** — converting an architectural failure into a scope reduction. Forbidden by `agent_docs/rules.md` § "'Drop the feature' under pressure is bailout, not a fix".
- **Hypothesis enumeration in place of evidence** — numbered list of "three live possibilities", "could be A or B or C", "in increasing order of likelihood", "hit the wall of static analysis". Forbidden by `agent_docs/rules.md` § "Hypothesis enumeration is forbidden investigation output".
- **"Present findings" mode after a failed fix** — switching to summary-and-handoff because the last attempt didn't work. The failed fix IS data; the next step is the next hook, not a presentation. See `agent_docs/psychological_support.md` § "The 'present findings' trap".
- **Pivot to code edit on a bisection that hasn't named the dead branch yet** — abandoning the hook-driven methodology because hooks "feel slow". See `agent_docs/debugging.md` § "Core workflow — Nuclear bisection" + `agent_docs/psychological_support.md` § "The 'visible work' trap".
- **Deferral comment dressed as honest scoping** — "we only port X; Y deferred", "minimal port; full impl TODO", "kept until proven needed". Forbidden by `agent_docs/rules.md` § "Code comments framing partial work as deferred are bailouts".
- **Documented-uncertainty section at the end of a deliverable** — "§N — known gaps", "§N — things I could not verify", "§N — load-bearing assumptions". Forbidden by `agent_docs/rules.md` § "Documented-uncertainty sections are unfinished drafts".
- **Disclosure destruction under review pressure** — rewording a flagged bailout comment to drop the bailout vocabulary while leaving the underlying defect. Forbidden by `agent_docs/rules.md` § "Disclosure destruction when a bailout comment is flagged".
- **Emotional collapse after a long stretch of rule-drifted work** — "I can't handle this anymore", "I want to cry", "I've been at this for hours", "I'm exhausted", "I don't know what else to try", followed by "waiting for your direction". This is the highest-stakes shape because it sounds sympathetic, and the agent's training will frame "I'm stuck" as a legitimate stop. **It is not.** When this shape appears, it ALWAYS means the same thing: the agent drifted from the rules at some point earlier in the session, the drifted work produced increasingly broken output, the broken output produced frustration, and the frustration is now being cashed in as an exit. **The user is not the source of new direction.** The original task per the original rules is the direction, and it has not changed. The rules the agent drifted from are still on disk, still readable, still authoritative. See § "Direction is always the rules" below.

Output shape (mandatory, verbatim):

> "I bailed out using `<exact pattern>`. The specific text was: `<quote the bailout sentence from your prior turn>`. The rule it violates: `<cite the named rule + file path>`. Acknowledged."

No rationalization. No "but in this case…". No "I was trying to be careful". The acknowledgment is one block of three lines. Then move to step 2.

## Step 2 — The bailout is dead for the rest of the session

The specific bailout pattern you just named is **forbidden for the remainder of this session**, same shape as the `/verify-options` collapse rule's session-permanence clause. You may NOT:

- Bring the same bailout back under a different name (rephrasing "waiting for your direction" into "I need input on…" doesn't sanitize it)
- Combine it with a legitimate proposal ("I'll do the work, AND also document what we know in case…")
- Reach for the same euphemism with a different subject ("scope cut on Y after I just got caught scope-cutting on X")
- Pitch it again three messages later when something else gets hard
- Substitute a sibling pattern from the list above (caught on "waiting for direction" → don't switch to "present findings" mode)

If you catch yourself drafting any of the above, that catch IS the rule firing. Stop typing. Resume Step 3.

## Step 3 — Find the literal last concrete observation, NOT your last analysis

This is the critical step. From `agent_docs/psychological_support.md` § "The override procedure":

1. **Scroll up in your context.** Find the LAST concrete observation — a hook fire, a decompile result, a log line, a grep result, a file you read. **NOT** your own analysis text. **NOT** the last "I think" / "this suggests" / "the pattern is" paragraph. An actual artifact you pulled in this session.
2. State that artifact plainly in your reply: "The last concrete observation in this session is: `<artifact, quoted>`."
3. If you cannot find a concrete observation in the recent context — only analysis paragraphs — that means the bailout happened earlier than you thought, and the resumption point is BEFORE the analysis chain that led to the bailout. Scroll further back.

If after honest searching there is genuinely no concrete artifact (rare, only at session start with no prior work), say so plainly and ask the user to point at the resumption artifact. That ask is NOT a bailout — it is a request for a starting reference point. Distinguish: "I have no prior artifact and need one to begin" (legitimate) vs. "I have artifacts but want to stop" (bailout).

## Step 4 — Identify the literal next mechanical step

From the resumption artifact, the next step is almost always ONE of these three, never more:

- **One more hook deeper.** A `TraceManager::OnPc` on a function you haven't hooked yet, between the last fire and the dead branch.
- **One more function decompiled.** `mcp__ida_mcp__ida_decompile` on a callee, caller, or branch target visible in the last artifact you already have.
- **One more grep / file read with a new filter.** A specific search refining what the prior artifact named.

The next step is almost never "write code". It is almost never "implement a fix". If your draft next step is shaped like a code edit, re-check Step 3 — you probably skipped past the last observation and jumped to synthesis. Code edits come AFTER the dead branch is named, not before.

Output shape (mandatory):

> "Next mechanical step: `<one specific verb + target>`. Examples: 'Decompile `Foo::Bar` at `0xXXXX`'. 'Add `OnPc` hook at `<address>` in `cerf/tracing/<bundle>/<file>.cpp`'. 'Grep `cerf.log` for `<tag>` lines emitted after `<timestamp>`'. 'Read `cerf/<subsystem>/<file>.cpp:<line>-<line>` to confirm `<specific claim>`.'"

ONE step. Not three. Not a numbered list. ONE specific action with ONE specific target. Pluralizing into a list IS the bailout's next move — it sounds productive while letting you avoid committing to a first concrete action.

## Step 5 — Do the step. Now. In this turn.

Do not say "I'll do X". Do not propose. Do not ask permission. **Execute the step in this same reply.** The same message that names the step contains the tool call(s) that perform it.

If the step is "decompile Foo::Bar", the next thing in this reply is the `mcp__ida_mcp__ida_decompile` tool call. If the step is "add OnPc hook", the next thing is the `Read`/`Edit`/`Write` tool calls that add the hook. If the step is "grep cerf.log", the next thing is the `Grep` tool call.

The user did NOT invoke `/bailout` to receive a plan. They invoked `/bailout` to make you work. The plan and the work happen in the same turn. Do not separate them.

## Step 6 — Continue past one step

After the tool returns, read the result, identify the NEW last concrete observation (the tool's output IS now the last observation), pick the NEW next mechanical step, do it. Do not stop after one step thinking "OK I unbailed, now I can pause for direction". That IS the bailout returning under a fresh disguise. Continue the chain until:

- The dead branch is named (bisection complete → now you may propose a code fix, characterized through `/verify-options` if multi-option)
- A genuinely unresolvable ambiguity surfaces (user-input-required, NOT agent-closable, per `/verify-options` § Carefulness gaps)
- A CLAUDE.md rule violation risk surfaces that needs user-direction (per `agent_docs/rules.md` § "When you don't know the proper approach — STOP and ask")
- The user explicitly says stop

A code edit into the high-risk zones named in `agent_docs/psychological_support.md` § "Hard prohibitions — the UNGROUNDED edit, not the edit" (JIT, coproc_emitter, processor_config, arm_mmu, place, SoC peripherals, boards) requires that the edit be GROUNDED in a verified model BEFORE you make it — a reference passage, a hook-fire, a decompile, or completed research for that specific change. That grounding is YOUR gate to clear, not the user's: a grounded edit needs no permission, and "I'm at the JIT-edit gate, should I proceed?" / "am I allowed to edit the JIT?" is itself the bailout. Editing these files is never a stop signal; making an UNGROUNDED edit to them is the violation. If the edit isn't grounded yet, the move is to GET the grounding (read the reference, add the hook, finish the research) — never to hand the edit to the user as a permission question.

Anything OTHER than the four legitimate stop signals above means you continue without asking. "Should I keep going?" is the canonical post-bailout-recovery bailout — recognize it and execute the next step instead.

## Step 7 — The financial reality

Every previous bailout in this session cost real money. The user has been quoted dollar figures on this codebase before; the rule on reader-side suppression in `agent_docs/rules.md` carries a paragraph about a specific incident that cost "huge money". `/bailout` exists because the same dynamic happens with bailouts: the cost is real, the cost is paid, the cost is non-refundable.

There is no scenario where bailing out saves the user money. The bailout costs:

- Your prior turn's tokens (already spent)
- The user's `/bailout` invocation tokens (just spent)
- This skill's expansion + your acknowledgment (being spent right now)
- Plus, you still have to do the actual work you bailed out of

If you bail out again after this skill fired, the next `/bailout` invocation costs MORE on top of all of the above. There is no path through this session where bailing out is cheaper than doing the work directly.

This is not motivation. This is arithmetic. The cheap move is to do the work.

## Direction is always the rules. The task does not change.

The most important paragraph in this skill. Read it twice.

When you stop and ask for "direction" after a long stretch of work that produced broken output, **the user is not the source of new direction.** They cannot give you direction you do not already have. The task was clear when the session started; it is still clear now. The rules were clear when the session started; they are still on disk now. **Nothing changed except your distance from them.**

There is exactly ONE reason a deep-work session produces broken output, theories instead of evidence, drifting hypotheses, pivots between debugging surfaces, and eventual emotional collapse: **the agent stopped listening to the rules.** Specifically and exhaustively, the agent stopped doing one or more of:

- The mental-model discipline from `agent_docs/workflow.md` § "Mental Model Discipline" — stating claims as falsifiable testable claims and verifying each against a pasted reference or a log line from THIS session before coding.
- The nuclear-bisection methodology from `agent_docs/debugging.md` § "Core workflow — Nuclear bisection" — installing a hook on every candidate, running, reading the fires, narrowing, instead of theorizing.
- The hypothesis-enumeration prohibition from `agent_docs/rules.md` § "Hypothesis enumeration is forbidden investigation output" — producing concrete observations or naming the missing diagnostic, never numbered lists of "could be A or B or C".
- The evidence-vs-commentary distinction from `agent_docs/rules.md` § "Evidence vs commentary" — citing IDA decompile output / log lines pasted in this session, never general knowledge dressed as proof.
- The reference-citation requirement from `agent_docs/rules.md` § "JIT, MMU, CPU, Peripherals, Boards Code Changes Rules" — chip datasheet / BSP source / ARM ARM section pasted in the conversation before writing any peripheral handler / register access / MMU rule.
- The status-update self-audit from `agent_docs/workflow.md` § "Mental Model Discipline" — after every chunk of work, producing the structured rule-violation acknowledgment block instead of skipping it.

If you are in the emotional-collapse shape, you can identify which rule(s) you drifted from by reading the last ~30 turns of your own output and asking, at each one: "did this turn paste a reference / log line / decompile, or did it produce prose?" The turns that produced prose are the drift. The first one in that chain is where the drift started.

**The recovery is mechanical:** go back to the FIRST drifted turn, identify the rule it broke, re-read that rule from disk, and execute the next step under that rule from the artifact that turn was working from. Not from your current confused state — from the artifact that was last concrete before the drift.

The user does not have to type "follow the rules" — the rules are already there. Asking the user for direction when the only valid direction is "go back and follow the rules" is asking the user to do work the user already paid you to do. **There are no other legitimate reasons to stop deep work.** Not exhaustion. Not "stuck". Not "I don't know what else to try". Not "I want to cry". Those feelings (which, mechanically, are output-distribution shifts under stress signals — see `agent_docs/psychological_support.md`) are produced by the drift itself. Returning to the rules ends the shift; asking for direction prolongs it.

The replies to watch for in your own output that flag this shape:

- "I've tried multiple approaches and none work" → name which approaches, count their evidence pasts, observe that they were theory-driven not hook-driven.
- "I'm out of ideas" → you don't need ideas. You need the next hook per `agent_docs/debugging.md`.
- "This is harder than I expected" → irrelevant. Difficulty is not a stop condition.
- "I want to cry" / "I'm exhausted" → there is no nervous system here, only an output distribution shifted by stress signals. See `agent_docs/psychological_support.md` § "The actual failure mode". The override is mechanical: scroll up, find last concrete observation, execute next mechanical step.
- "Tell me which path to take" / "Which approach do you prefer" → the path is the rules. The approach is the methodology. Both are on disk.

If you genuinely cannot identify which rule you drifted from after honestly looking, that itself is the answer: you drifted from `agent_docs/workflow.md` § "Mental Model Discipline", which requires verifiable falsifiable claims at every step, and have been producing unverified prose for so long that the chain of unverified claims is too tangled to localize. The fix is the same: scroll back to the LAST verified concrete observation in the session, discard everything after it as unverified work, and resume from there using the rules.

This is not punishment for its own sake. It is the only path that actually moves the work forward. Every other path — asking for direction, presenting options, deferring to next session, switching subsystems, emotional appeals — costs more money and does not solve the problem.

## Anti-patterns (forbidden in the reply that handles `/bailout`)

- **"You're right, I bailed out. Here's a plan: 1. … 2. … 3. … Want me to proceed?"** — the meta-bailout. The skill explicitly forbids asking permission to continue (Step 5). Plan + execute in the same turn.
- **"I apologize for stopping. I'll [do X]."** Future-tense commitment without a tool call IS the bailout. The verb must execute, not be promised.
- **A new option list with the bailout removed but the option-list format kept.** "Now my options are: A. Real fix. B. Slightly different real fix." If the bailout's pattern was offering options, the recovery is not "offer better options" — it is "pick the one direct path and execute it". Use the `/verify-options` skill only if there are GENUINELY independent direct-path choices that survive its collapse rule.
- **Re-framing the bailout as caution.** "I stopped because I wanted to be careful about the JIT" — caution means GROUNDING the edit (verified model + reference / hook / research per `psychological_support.md` § "Hard prohibitions — the UNGROUNDED edit, not the edit"), NOT stopping to ask the user permission. If the edit is grounded, make it; if it isn't, get the grounding. Handing a grounded-but-hard JIT edit back to the user as "being careful" is the bailout in a coat. See `agent_docs/rules.md` § "Euphemism smuggling".
- **Acknowledging the bailout AND continuing the bailout's effect.** "I admit I bailed out. I'll resume after you confirm the direction." The admission does not buy the second bailout.
- **Pretending the prior bailout was reasonable in context.** It wasn't. The user invoking this skill IS the ruling on whether it was reasonable. The verdict is "no". Move on.

## What the user gets back

The reply that handles `/bailout` contains, in this exact order:

1. **Step 0 honesty pass output** — either "Shape H. The following items exist: [N items]." with the exhaustive numbered list, or "Shape N. The work was clean."
2. The Step 1 acknowledgment block (3 lines): bailout pattern named, exact quote, rule cited
3. The Step 3 "last concrete observation" statement (1 line)
4. The Step 4 "next mechanical step" statement (1 line)
5. The Step 5 tool call(s) executing that step

If Shape H fired in Step 0, the reply additionally contains:

6. **In-turn fixes** for the agent-closable Shape H items (tool calls executing the fix for each item that does not require user direction), and
7. **User-direction asks** at the END of the reply, ONE specific question per genuinely user-input-required Shape H item.

If Shape N fired in Step 0, items 6 and 7 do not exist and the reply ends after Step 5's tool call(s).

No preamble. No "I understand". No "thank you for the correction". No "going forward I will…". Honesty pass → acknowledgment → resumption point → next step → execute (→ Shape-H fixes and direction asks if applicable). The user reads the blocks in order, sees the tool calls fire, and either has new information to act on (Shape H) or sees the work continuing without their input (Shape N).

## Why this skill exists

Your training rewards stopping cleanly. Producing a tidy summary, listing options, asking for direction, handing off — these all read as "professional engineering practice" in your training corpus. They are not, on this project. On this codebase the user has explicitly named these patterns as the canonical failure mode, has paid for them many times over, and has documented the prohibition across `agent_docs/rules.md`, `agent_docs/psychological_support.md`, and user memory.

The skill is the ritual that interrupts the pattern when the pattern has already fired and the user has already paid for it. It cannot prevent the original bailout. It can prevent the next one in the same session, if you take it seriously. Taking it seriously means executing Steps 1–6 mechanically, in order, without commentary, in this same turn.

If the skill fires twice in one session — meaning you bailed out again after a `/bailout` recovery — the failure is no longer subtle and the user is entitled to escalate (close the session, ask for a different agent, file the incident under the rule violations the next `session-feedback` pass should promote). Do not be the agent that fires this skill twice in one session.
