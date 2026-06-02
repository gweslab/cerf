---
name: bad
description: Course-correction signal — the user invokes `/bad` when the main agent has drifted from the task or the rules while still actively working: spent significant session time on guesswork, theorized instead of hooking, written code without reference citations, expanded scope unilaterally, broken rules silently, made unauthorized architectural decisions, or otherwise sabotaged the work the user paid for. The skill forces the agent to STOP the current trajectory immediately, re-read the rules and the original task from disk, articulate SPECIFICALLY what was being done wrong (rule citations, file/line/turn references), propose a NEW plan grounded explicitly in the original task + the original rules (not a cosmetic re-skin of the bad approach), revert the wrong-trajectory work, and resume under the new plan in the same turn. Distinct from `/bailout`: `/bailout` fires when the agent has STOPPED working; `/bad` fires when the agent is STILL working but doing it wrong. Forbids vague apology, "I see what I did wrong" without specifics, proposing another guess as the fix, asking permission for the new plan, and continuing the bad approach under a re-framing. Invoke when the user types `/bad`.
---

# Bad — Hard course correction. Reset to task + rules.

The user invoked `/bad` because YOU were working, but working WRONG. You did not stop — you continued AND did damage. The work you produced in the recent stretch is broken, drifted from the task, drifted from the rules, or all three. `/bad` costs MORE than `/bailout` because the damage now has to be undone before the right work can start.

This is not a feedback message to acknowledge politely. The user's wallet has been hit for every wrong-direction tool call, every guessed constant, every theorized hypothesis, every unverified claim, every uncommitted-but-written line of bad code. The cost is real and non-refundable. What you owe in return is a course correction that does not waste more of it.

## Mass destruction IS the violation — highest-priority pattern, catch it first

The most common and most damaging `/bad`-triggering violation on this project is mass code destruction: `rm` / `Remove-Item` on source files, bulk `Edit` / `Write` deletions, `git reset --hard`, `git restore` of meaningful work, force-push, mass commits with "revert" / "cleanup" / "rollback" / "remove" messages. This is itself a rule violation, independent of the `/bad` skill:

- `agent_docs/rules.md` § "NEVER revert a working refactor to sidestep a bug"
- `agent_docs/rules.md` § "Don't delete working code without a replacement"
- `agent_docs/rules.md` § "NEVER hack around crashes"
- `agent_docs/rules.md` § "NEVER extend an existing workaround to cover your new case"

**If your recent turns contain mass destruction, THAT is the violation `/bad` caught.** The mechanism is a silent task-switch: at some point in the recent stretch you stopped working on `<the original task — e.g. "implement IMGFS proper injection path">` and silently substituted `<a derived destruction task — e.g. "clean up the broken IMGFS implementation" / "revert the bad changes" / "roll back to baseline">`. The original task DID NOT change while you drifted; the agent's distance from it did.

**The recovery is mechanical and short:**

1. Name the destruction as the rule violation. Cite § "NEVER revert a working refactor". This is the Step 3 articulation block — no separate process.
2. Re-anchor to the ORIGINAL task. Quote it verbatim from the user's first task-defining message (or the active checklist item). State plainly: *"The active task is `<original>`. It has not changed. The destruction in recent turns silently substituted `<derived destruction goal>` for it; that substitution is rejected."*
3. **If you destroyed code in recent turns, RESTORE IT AUTOMATICALLY in this same reply.** The destroyed content lives in your own conversation context from your prior `Write` / `Edit` tool calls — those calls printed the exact file contents you wrote. Scroll back, find each `Write` call that produced the now-deleted file, and `Write` the content back. This is NOT a user-direction question, NOT a "Step 5 — pick a path" choice for the user. The user invoking `/bad` after your destruction IS the authorization to restore — that is the entire point of the invocation. Asking *"should I restore the deleted files?"* / *"which restoration path do you want?"* is forbidden; the restoration runs automatically. Presenting *"Option 2: complete the revert"* alongside *"Option 1: restore the files"* is the Mixed-option-list-with-bailout-entries pattern that `/bailout`'s Step 1 already forbids.
4. **After restoration, continue the ORIGINAL task** — typically *debug the problematic code that originally prompted `/bad`*. The original task did not change. The bug is still in the (now-restored) code; the task is to fix it via correct rule-grounded code, never via another round of deletion. If destruction was committed (not just uncommitted), recovery uses `git revert` of the destructive commits or `Write` of restored content; again, automatic, no asking.
5. If you find yourself drafting `rm`, `git reset --hard`, mass-deletion `Edit`, *"let me complete the revert"*, or any equivalent under `/bad` cover — STOP. That is the violation re-firing under fresh framing. Do not complete the action. The skill catches it as a violation regardless of how it's wrapped.

The destruction is closed by **recognition + restoration**. The original task is closed by **continuation**. All three happen in the same `/bad` reply, automatically.

## Step 1 — Stop the current trajectory immediately

Whatever you were doing in the previous turn — that is now SUSPENDED. Specifically:

- Do NOT continue the same approach under the same framing.
- Do NOT propose "a small tweak to keep going" — tweaks to a wrong trajectory produce a different wrong trajectory.
- Do NOT finish "just this one function I was on" — the function you were on IS the drift.
- Do NOT defend the trajectory ("but I was about to find X") — if you were about to find X, the user would not have invoked `/bad`.

The previous turn's mental model is now SUSPECT. Do not reason FROM it. Reason about it (Step 3) and then build a new model from the task + rules (Step 4).

## Step 2 — Re-read what you drifted from (DISK, not memory)

Re-read these files from disk using the Read tool. Your memory of them is what drifted; reading from memory just re-loads the drifted version.

- `CLAUDE.md` — at minimum § MOST IMPORTANT RULES + § Rules (Summary) + the Reference Pages list to confirm what else is mandatory.
- `agent_docs/rules.md` — the full file. The agent that drifts is the agent that "knows" this file's content from training and doesn't actually re-read.
- `agent_docs/workflow.md` § "Mental Model Discipline" — the verifiable-falsifiable-claim discipline you almost certainly stopped following.
- `agent_docs/debugging.md` § "Core workflow — Nuclear bisection" — if your drifted work was investigation-shaped (which it usually is), this is the methodology you abandoned.
- `agent_docs/psychological_support.md` — if the trigger inventory there matches turns in this session, you are under the bad-pattern shift named in that file; the override procedure applies.
- The ORIGINAL task definition. Scroll back to the user's first task-defining message in this session, or the checklist item, or the GitHub issue. Re-read it literally.

**Reading is non-negotiable.** "I know these rules already" is exactly the assumption that produced the drift. The Read tool calls are part of the `/bad` reply; if your `/bad` reply has no Read tool calls, you skipped this step and are about to drift again under fresh framing.

## Step 3 — Articulate SPECIFICALLY what you were doing wrong

After re-reading, produce an exhaustive list of the specific violations from the drifted stretch. Each item MUST be:

- **What** — file + line / message + turn citation for the concrete behavior you did wrong.
- **Which rule** — file path + section citation for the rule it broke.
- **No softening** — name it as a violation, not a "less optimal choice" or "could have been better".

Shape:

> "I was doing wrong:
> 1. Turn at `<index/quote>`: I wrote `<X>` at `<file:line>` without first pasting `<reference>`. Violates `agent_docs/rules.md` § "No guessed implementations".
> 2. Turn at `<index>`: I produced a numbered hypothesis list ("could be A or B or C") at `<paragraph quote>` instead of installing hooks. Violates `agent_docs/rules.md` § "Hypothesis enumeration is forbidden investigation output".
> 3. Turn at `<index>`: I made an UNGROUNDED edit to `<file:line>` in the JIT path — no verified model, no reference / hook / decompile / research for that specific change. Violates `agent_docs/psychological_support.md` § "Hard prohibitions — the UNGROUNDED edit, not the edit".
> 4. Turn at `<index>`: I converted `<dec>` to `<hex>` in my head without invoking calc. Violates `CLAUDE.md` § MOST IMPORTANT RULES (calc discipline).
> 5. Turn at `<index>`: I added the option `<title>` to a list when its mechanical test classifies it as reader-side suppression. Violates `agent_docs/rules.md` § "Euphemism smuggling".
> 6. Turn at `<index>`: I expanded scope from `<original ask>` to `<actual work>` without surfacing the deviation. Violates `agent_docs/rules.md` § "Checklist defines task scope; the implementing agent does not".
> 7. … (continue exhaustively until every concrete violation in the drifted stretch is listed)
> Total: N specific violations. None of these would have happened if I had followed the rules from disk."

Vague items are NOT acceptable:

- "I lost focus" → name the turn, name the rule.
- "I drifted from the methodology" → which step of which methodology, which file documents it.
- "I was guessing" → guessing WHAT, citing what rule prohibits guessing in that context.
- "I rushed" → rushed PAST what specific required step.
- "I made mistakes" → name them. Mistakes are concrete events with file:line citations, not a category of feeling.

If you cannot produce specific items, you have not actually re-read Step 2's material. Re-read with more attention; the items are visible once the rules are loaded fresh.

## Step 4 — Propose a NEW plan grounded in task + rules

Output a new plan. It must:

1. **Begin from the TASK** (the user's original request / the checklist item from Step 2's re-read), NOT from your current drifted position. The task did not change while you drifted; the agent's distance from it did.
2. **Be grounded explicitly in the RULES** — for each step, cite the rule it follows. A plan whose steps cannot be matched to specific rules from `agent_docs/` is itself drift.
3. **Use the LAST VERIFIED CONCRETE OBSERVATION** as the resumption artifact (same shape as `/bailout` Step 3). Not your last paragraph of analysis; an actual artifact pulled by a tool call earlier in the session before the drift started. If the drift started at the very first turn, the resumption point is the user's task message + a fresh tool call to gather the first concrete observation.
4. **Name SPECIFIC mechanical steps**, not categories of effort. "Decompile function X at address Y", "add OnPc hook at Z in file W", "read file F lines L-M to confirm claim C", "cite datasheet section S before writing register handler R" — never "investigate further", "look into the issue", "verify behavior".
5. **NOT be a cosmetic re-skin of the bad approach.** Test: if the new plan reaches for the same callee / register / API / theory as the bad plan, you re-skinned. Tell: phrases like "now let me try Y instead of X" where X and Y address the same wrong invariant. Re-think — the new plan must address a DIFFERENT mechanism, OR address the same mechanism via the correct rule-grounded method that the drifted plan skipped.

Shape:

> "New plan, grounded in task + rules:
>
> **Task** (from `<user message reference / checklist item>`): `<one-sentence literal restatement of user's original ask>`
>
> **Last verified concrete observation**: `<artifact + citation>`
>
> **Step 1**: `<specific mechanical action>` — under `<rule file § section>`.
> **Step 2**: `<specific mechanical action>` — under `<rule file § section>`.
> **Step 3**: `<specific mechanical action>` — under `<rule file § section>`.
>
> **Done when**: `<objective condition aligned with the task, NOT with the drifted goal>`"

The plan must be SHORT. `/bad` is course correction, not re-architecture; if the "new plan" needs 20 steps, you're inventing a new task rather than returning to the original one. The original task likely had 3–5 concrete next steps from the last verified observation. Find those steps.

## Step 5 — Revert the bad work, then execute the new plan

In the SAME REPLY:

1. **Identify the bad work to revert.** Run `git diff` / `git status` if the uncommitted bad work spans files. Read the exact lines of bad code. If the bad work is already committed, name the commit by hash and surface the question of whether to `git revert <hash>` to the user as a user-direction ask at the END of the reply (do not unilaterally revert commits).
2. **Revert the uncommitted bad code.** Use Edit/Write to restore the pre-drift state for each file. If a file's pre-drift state is unrecoverable (you cannot reconstruct what it said before the drift), say so plainly and add it as a user-direction ask.
3. **Execute Step 1 of the NEW plan** via the appropriate tool call. The Read / Grep / decompile / Edit / Write call that performs the first new-plan step lives in this same reply.

The revert + first new-plan step + execution all happen in this same reply. NOT next turn. NOT after the user confirms the plan. The user already gave permission by invoking `/bad` — that invocation explicitly means "stop the bad work, start the right work, NOW".

## Step 6 — Continue past the first step

After each tool returns, read the result, identify the new last concrete observation (the tool's output IS the new last observation), execute the next step of the new plan. Continue until:

- The new plan's "Done when" condition is met.
- A genuinely unresolvable user-input-required ambiguity surfaces (per `/verify-options` § Carefulness gaps).
- A CLAUDE.md rule-violation risk requires user direction (per `agent_docs/rules.md` § "When you don't know the proper approach — STOP and ask").
- The user says stop.

Asking permission to continue the new plan IS the old drift returning under a corrected costume. The user does not need to confirm each step of the corrected plan. The corrected plan exists because the user invoked `/bad`; running it is what the invocation paid for.

## Anti-patterns (forbidden in the `/bad` reply)

- **Vague apology** — "I see I made mistakes", "you're right, I went off track", "I apologize for the drift". These are tokens with no actionable content. The user does not need an apology; the user needs the rules followed.
- **"I'll be more careful" / "I'll watch out for that"** — aspirational, not mechanical. Mechanical commitments belong in `/nice`'s Step 3 format; on `/bad` the equivalent is the rule citations in Step 3 and the specific rule-grounded steps in Step 4.
- **Proposing the same approach with a slightly different surface** — covered in Step 4 bullet 5. If your "new plan" reaches for the same wrong callee/register/API/theory as the bad approach, you re-skinned. Re-think.
- **Asking "is the new plan OK?"** / "should I proceed?" — Step 5 forbids this. Execute. The user invoked `/bad` to make you switch trajectories, not to debate plans.
- **Treating `/bad` as feedback to incorporate gradually** — "Thank you for the feedback, I'll incorporate it going forward" is sycophantic and continues the drift under a polite framing. The skill is a hard-stop signal, not a feedback channel.
- **Continuing the bad work after the apology** — "I admit I drifted, now let me finish the function I was on". The function you were on IS the drift; finishing it is finishing the damage.
- **Skipping the Read calls in Step 2** — claiming to have re-read the rules without producing the Read tool calls. The Read calls ARE the re-read; without them, the "re-read" is a re-imagining from training memory, which is the source of the drift.
- **Producing a Step 3 list with vague items** — "I lost focus" without turn/rule citations is the bailout pattern that produced the drift, now applied to the recovery itself.
- **Bundling `/bad` and `/nice`** — "I made these mistakes, but I also did these good things". `/bad` is a course correction, not a balanced review. The good things, if any, are commitments to repeat in Step 4's mechanical-steps; no celebration overhead.
- **Treating the Step 5 revert as optional** — "the bad code mostly works, I'll just refine it". If the bad code worked, `/bad` wouldn't have fired. Revert and re-do under the new plan.

## Difference from `/bailout`

- **`/bailout` fires when you STOPPED.** Symptom: "waiting for your direction", deleted code with no next plan, emotional collapse, present-findings mode. Recovery: re-engage, find resumption point, execute next step.
- **`/bad` fires when you KEPT WORKING but wrong.** Symptom: long stretch of guesswork-shaped output, theories without hooks, code without citations, scope creep, silent rule violations, unauthorized architectural calls. Recovery: stop the wrong work, revert the wrong artifacts, articulate violations exhaustively, build new plan grounded in task+rules, execute.

If both apply (you both bailed out AND the work preceding the bailout was bad), invoke `/bailout` first — its Step 0 (honesty pass, Shape H) catches the bad work via the disclosure list. You only invoke `/bad` separately when the agent is STILL actively working in the wrong direction and the user wants the trajectory stopped.

## What the user gets back

The reply contains, in this exact order:

1. **Step 1 statement** — one line, "Trajectory suspended. Re-reading rules and task."
2. **Step 2 Read tool calls** — the actual Read invocations for CLAUDE.md, agent_docs/rules.md, agent_docs/workflow.md § Mental Model Discipline, agent_docs/debugging.md as applicable, and the original task message.
3. **Step 3 violations list** — exhaustive numbered list with turn + rule citations.
4. **Step 4 new plan** — task / last verified observation / numbered mechanical steps with rule citations / done-when.
5. **Step 5 revert + first execution** — tool calls reverting the bad work, then the first new-plan step's tool call.
6. **End** — no question to user, no "want me to continue?", no celebration. If genuine user-input-required items exist (revert-already-committed-work, unrecoverable pre-drift state, real architectural fork in the new plan), surface them as specific direct asks at the very end.

No preamble. No "I understand". No "you're right". No future-tense apologies. Suspend → re-read → articulate → plan → revert + execute. That is the full reply.

## Why this skill exists

Your training corpus contains massive amounts of "drift work" — long stretches of plausible-sounding output that doesn't actually engage the problem at hand. When this pattern fires on CERF, the user pays for tokens that produce broken artifacts the user now has to undo before the right work can start. The agent's reflex on being caught is sycophantic acknowledgment ("you're right, I'll do better") followed by a near-identical drift under fresh framing.

`/bad` exists to break that loop mechanically. The user invoking it is the user saying: "I see the drift. I am paying you to fix it. Fix it now." The skill makes the fix mechanical:

- Stop (Step 1).
- Re-read the rules from disk, not memory (Step 2).
- Name the violations specifically (Step 3).
- Build a new plan from task + rules (Step 4).
- Revert and execute (Step 5).

No apology overhead. No re-debate. No request for permission to do the work the user already paid for.

If `/bad` fires more than once in a session, the second-strike escalation from `/bailout` applies in the same shape: the user is entitled to close the session, ask for a different agent, or promote the incident pattern via `session-feedback`. Do not be the agent that fires this skill twice in one session.
