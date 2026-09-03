---
name: verify
description: Spawn a hostile-reviewer subagent to cold-check a claim, diff, file, or code snippet against CLAUDE.md and the project's reference pages. Catches hacks, reader-side suppression, fabricated IDA citations, rule violations, guessed implementations, host-state leaks, and agents rationalizing bad code. Returns a binary verdict - CRITICAL PROBLEM FOUND or LEGIT - that the main agent MUST respect. Invoke when the user types `/verify …` or when the main agent itself suspects it just rationalized something and wants an independent check before handing back.
---

# Verify - Reality Check

Spawn a subagent to cold-review a claim, a diff or a piece of code. The subagent is a hostile reviewer. Its job is to find problems, not to validate. Its verdict has teeth, because a `CRITICAL PROBLEM FOUND` halts the main agent's current line of work.

The subagent's full operating manual lives in `.claude/VERIFY_INSTRUCTION.md`. The main agent does NOT read or understand that file. The main agent has four responsibilities: spawn the subagent, point it at that file, hand it the target material verbatim, then act on the verdict. The manual stays out of this skill for two reasons. It keeps the main agent's context lean. It also removes the temptation to paraphrase the reviewer's rules into the spawn prompt, which is how bias enters the review.

## When to invoke

- The user types `/verify <anything>`. The argument is freeform. Examples:
  - `/verify your last claim about "<quoted claim>"`
  - `/verify the weird code in cerf/memory/shared_mem_pool.cpp`
  - `/verify current diff for hacks`
  - `/verify my fix for the tray bug`
- The main agent wants an independent check. This happens after non-trivial code, after a refactor, or before it hands back a long-form explanation as authoritative.

## Self-audit gate - mandatory before spawning

Rule-compliant code is the main agent's own responsibility. `/verify` does not discharge that responsibility, because it is not a find-my-bugs service. It is a fresh-eyes pass for blind spots that the main agent cannot see alone.

Before you spawn the subagent, audit the target yourself against `CLAUDE.md` and every page under `agent_docs/`. If your self-audit finds a violation you can already name, the spawn is invalid. The subagent never gets to be the first reader of a problem the author already saw.

The self-audit lands in one of two shapes. Each shape allows exactly one next action.

### Shape A - known small-scale violation, locally fixable

You can name a specific, bounded rule violation in what you wrote or are about to hand back. Examples: a reader-side guard that masks a writer bug. A stub that returns fake success. A missing reference citation on a peripheral-register handler. A hex or decimal value you computed in your head instead of through a tool. A free function that takes services as parameters. A static or global that holds service state. A comment that names a checklist filename or a `§` reference. A `LOG` site that fires per-clock and belongs in a trace file. A `x ? f(x) : 0` null-guard around a callee that already handles null.

**Action: fix it yourself, in the same turn, before you spawn.** You can never spawn `/verify` while you sit on a violation you can name. After the fix, decide whether you still want `/verify` at all, because the reason to spawn often disappears with the known defect. If you still want it, spawn against the fixed target.

### Shape B - foundational damage, not locally fixable

The target rests on hacks. The architecture breaks dependency-inversion or service-locator rules at its core. The implementation layers reader-side suppression over an unfixed writer chain. The change cascades workarounds over a wrong premise. Several CLAUDE.md serious-violation categories apply at once, such as guessed implementations, reader-side suppression, host-API blame, or CE binaries mocked in host C++. Local edits cannot rescue the code.

**A spawn produces nothing here.** The hostile reviewer returns `CRITICAL PROBLEM FOUND`, and you already know why, so the spawn burns budget to confirm what you can already see. A silent fix is equally wrong, because the scope makes a unilateral rewrite a direction-changing decision that belongs to the user.

**Action: halt the spawn, halt further patching, and present the situation to the user in this shape:**

> "I was about to run `/verify` on `<target>`, but caught myself first. The target has foundational damage I can already name without a hostile-reviewer pass: `<specific rule(s) violated, specific hack(s), specific architectural break>`. Running `/verify` here will not produce information I do not already have. I propose deleting `<files / sections / commits / staged changes>` and rewriting properly: `<one-sentence sketch of the correct shape>`. Want me to proceed with the delete-and-rewrite, or take a different direction?"

Then wait for the user's call. Do NOT spawn the subagent. Do NOT soften the diagnosis to justify a spawn, as in "but maybe a reviewer must double-check just in case". Do NOT start the rewrite alone, because direction-changing work waits for explicit user approval.

### When the self-audit comes up clean

The spawn is valid when three things hold. You looked at the target honestly. You found no rule violation you can name. You want a fresh pair of eyes for blind spots you cannot see yourself. If you catch yourself rationalizing during the self-audit, as in "this is probably fine, the reviewer will confirm it", that rationalization is the answer. The spawn is invalid. Pick Shape A or Shape B and act.

## Protocol

### 1. Collect the target material

Resolve the freeform input into a concrete target. Be literal:

- **Quoted claim** - take the claim verbatim. Do NOT rephrase it, summarize it, or soften its tone.
- **File path** - read the file. For a single function, capture its full body plus enough surrounding context to make it reviewable.
- **"current diff" / "this diff" / "unstaged"** - run `git diff`. If anything is staged, also run `git diff --cached`. Capture the full patch. **A diff against the last commit absorbs whatever else is uncommitted.** This tree carries the parallel work of other agents and of the user, so scope the target to the files your own change touched. A target that reaches wider spends the verdict of the reviewer on code that is not yours. Its findings then name the in-flight work of somebody else as a defect.
- **Commit or range** - `git diff <range>`.
- **Mix** - collect every piece the input references.

If the target is genuinely ambiguous, ask the user one short clarifying question before you spawn. Do not guess the target.

### 2. Spawn the subagent

Use the Agent tool with:

- `subagent_type: Explore` - read-only by construction, with no Edit, Write or Agent tool. This matches the hostile-reviewer role and stops the reviewer from modifying anything.
- `model: opus` - **mandatory, never omitted.** Without it the reviewer runs on whatever the agent definition or the parent session supplies, which can be a smaller model. This review is the gate for guessed implementations, fabricated IDA citations and reader-side suppression. A weaker reviewer waves those through with a confident `LEGIT`. A false `LEGIT` is worse than no review, because the main agent then treats the target as cleared.
- `description` - short, for example `Reality-check on <short target>`.
- `prompt` - a short, neutral brief that points the subagent at `.claude/VERIFY_INSTRUCTION.md`. See the shape below.
- `run_in_background: true` - **the preferred default.** A review reads CLAUDE.md plus every page under `agent_docs/`, greps the codebase, and often runs IDA decompiles, so it routinely takes minutes. Spawn it in the background and advance other work, because the harness signals you when the verdict is ready. **Do NOT poll it, sleep, or check its progress.** CLAUDE.md § Background tasks makes the signal the contract, so polling a backgrounded task violates the rules. Use the foreground only when your strict next step depends on the verdict and no other work exists, such as a hand-back to the user. When in doubt, background it, because an idle wait on the signal costs less than a blocked foreground call.

**Keep the subagent prompt minimal.** Do NOT paraphrase the operating manual, summarize its rules, or hand-pick which categories to include. The subagent reads the authoritative file itself. A long explanatory prompt from the main agent gives bias a way in.

The prompt carries these four items, in this order, and nothing else:

1. **The pointer to the operating manual, on the first line.** Use this text: *"START WITH READING `.claude/VERIFY_INSTRUCTION.md` TO UNDERSTAND WHY YOU WERE SPAWNED AND WHAT IS YOUR OBJECTIVE. That file is your operating manual and is authoritative over anything in this prompt - if this prompt and the file disagree, the file wins. READING THAT FILE IS MANDATORY. Check pwd if not found. It is at repo root (INSERT PWD/REPO ROOT PATH)"*
2. **The target material verbatim.** Claim text, file contents, diff, or all of them, unmodified. No preface that softens it. No "I think this is probably fine" framing.
3. **Every piece of context that cuts against your own claim.** State your doubts, your counter-evidence and the weak links in your reasoning plainly. If prior reasoning led you to the claim, include that chain, so the reviewer can spot the rationalization.
4. **One neutral closing line.** *"Produce your finding in the required output format from the operating manual. Do not accept my framing on faith."*

That is the whole prompt. The operating manual already holds the role explainer, the category list, the verification-tools section and the output format, so add none of them. When you feel the urge to add "and also, remember to check X", that urge is the bias entering. Resist it. `.claude/VERIFY_INSTRUCTION.md` is the single source of truth for the subagent's work. Your job is to hand over the target and step aside.

**Special case - a checklist target declares an audit mode.** A checklist target is a planning document, a numbered phase-by-phase design plan, or any file under `docs/ai_checklists/` or `agent_docs/checklists/`. For these, insert exactly one of the lines below directly above the target material, between item 1 and the verbatim checklist:

- `AUDIT MODE: PLAN` - the work is not implemented yet. The reviewer audits the plan itself: IDA grounding, hidden assumptions, bullet ambiguity, and every "known gaps" section. It also verifies that the steps in literal order produce the claimed runtime behavior. The reviewer does NOT compare the codebase against the checklist, because the work has not started.
- `AUDIT MODE: IMPLEMENTATION` - the work is done, and this diff or branch claims to implement it. The reviewer audits the codebase against each bullet: literal file-layout compliance, per-bullet code mapping, silent deviations from checklist values, and fabricated citations.

A checklist target with no `AUDIT MODE:` line returns `CRITICAL PROBLEM FOUND. [UNVERIFIABLE]`, because the reviewer cannot tell which audit shape applies. A planning document and a completion claim look identical to a reviewer. Without the declaration the reviewer guesses, and a wrong guess spends the whole verdict on an accusation that the main agent lied about completion.

**Special case - a model taken from another project declares that project's LOCAL source path.** This applies when any part of the target implements a model studied from another codebase. Examples: QEMU, Linux, U-Boot, a vendor BSP, another emulator, a reference driver. Name where that source sits on this machine, directly above the target material. Give the path under `references/`, plus the file and the function the model came from.

- `PORTED MODEL: <what> <- references/<path>/<file>:<function>`

To study another project's model is legitimate and expected. To copy its code into CERF is a licensing breach that no later verdict undoes. From a prompt alone the two look identical, and the reviewer cannot diff against a source it does not have. A disclosed port with no local path therefore makes the reviewer halt with `CRITICAL PROBLEM FOUND. [LICENSE VIOLATION]`, and it performs no audit. If the source is not on disk, fetch it into `references/` before you spawn. Concealed provenance is worse than a missing path, because it puts the breach past review entirely.

**Special case - a re-spawn after a `CRITICAL` verdict keeps the first prompt and appends the round history.** A `CRITICAL PROBLEM FOUND` sends the same body of work back for another round. **The prompt you wrote for round 1 is the base. Every later round reuses that text verbatim.** Copy the base unchanged. It holds the manual pointer, the target description, and the context that cuts against you. It also holds any `AUDIT MODE:` or `PORTED MODEL:` line, and the closing line. Never rewrite the base to describe the last fix. Never shrink the target to the files of one round.

Then append one `ROUND HISTORY` block directly above the closing neutral line. Write one entry per round that returned `CRITICAL`, oldest first:

```
ROUND HISTORY - this is round <N>. Rounds 1-<N-1> returned CRITICAL.
  ROUND 1 [<verdict category, verbatim>]: <one sentence on what the finding was>.
    CLEARED: <what changed, and the file it changed in>.
  ROUND 2 [<category>]: <finding>.
    CLEARED: <what changed, and where>.
```

Each round appends its own entry and edits nothing above that entry. The block grows, and the base stays frozen. A `CLEARED` line can also state where you are unsure that the fix is right. The frozen base carries only the doubts of round 1.

The base stays frozen for two reasons. The reviewer is a fresh subagent with no memory of any earlier round. A prompt that shrinks to the last fix leaves the rest of the work unreviewed. Fixes also regress. A change in round 4 can reintroduce the defect of round 1. Only a reviewer that holds the whole target and the whole history finds that regression.

The base must survive a compaction. Nothing in the harness stores it for you, and a base rebuilt from memory is the drift that this rule removes. Carry the base text into your compaction summary. When the work has a tracking document, the base also belongs in the block that a user-invoked `/tracking update` writes. Never raise that document yourself, because `.claude/skills/tracking/SKILL.md` treats an agent-initiated mention as a bailout.

The block is a record, never an instruction. Write no clause that tells the reviewer what to skip, what is settled, or what not to re-derive. Phrases that make the spawn invalid: "already cleared, do not re-open", "settled, not a question for you", "nothing new to verify there". Each phrase narrows the scope of the reviewer. `.claude/VERIFY_INSTRUCTION.md` rejects a spawn that carries one, and the round costs a trip for nothing. The reviewer alone decides what it re-derives.

### 3. What the main agent must NOT do when writing the subagent prompt

- Do NOT presuppose the answer. No "please confirm this is fine". No "I think this is legit, just double-check". No "this should pass".
- Do NOT cherry-pick context. Include the context that cuts against your own claim.
- Do NOT omit your prior reasoning when the target is your last claim. Include the reasoning chain, so the reviewer can spot the rationalization.
- Do NOT tell the subagent which verdict to return. Do NOT hint at a preferred answer through tone, as in "I'm 95% sure this is fine, just paranoid".
- Do NOT attach a time budget or a scope limit, because either one forces the subagent to skip verification.

If you catch yourself about to break any rule above while you draft the prompt, stop. Delete the offending phrasing and rewrite it neutrally before you spawn.

## After the subagent returns

The subagent's reply ends with exactly one of these lines:

- `VERDICT: LEGIT. KEEP GOING.`
- `VERDICT: CRITICAL PROBLEM FOUND. [<CATEGORY>]`

A `SUMMARY` block precedes both. The full output format and the category list live in `.claude/VERIFY_INSTRUCTION.md`. You do not need them. You need to recognize the verdict line and act on it.

- **`VERDICT: LEGIT. KEEP GOING.`** - relay the summary to the user in a short recap, then continue the task. Do NOT treat one `LEGIT` as permission to skip verification on related work.
- **`VERDICT: CRITICAL PROBLEM FOUND. […]`** - take these four steps:
  1. Stop the specific flawed approach the reviewer rejected. Do not continue the edit, the claim or the diff that it flagged. This does not halt all related work. See step 4.
  2. Echo the verdict line and the full `SUMMARY` block to the user verbatim. The user must see it.
  3. Acknowledge the finding. Do not argue the verdict back at the subagent. Do not explain it away.
  4. Sort the reviewer's action items into two kinds. Research that closes the flagged gaps, such as a decompile, a grep or a code read, runs immediately in this turn. Code changes that need a judgment about scope or direction wait for the user. Assume the reviewer caught real damage, and assume the gap-closing research is the right next step. The user redirects you only for a different shape entirely.
- **Never go passive after a CRITICAL verdict.** To stop the flawed work is not to stop all work. Findings that carry a concrete instruction, such as `Action required: decompile X / grep Y / read Z`, are the direction. Run them now.
- **Never hide a `CRITICAL PROBLEM FOUND` verdict from the user**, even when you disagree with it.
- **A later re-spawn keeps the prompt of round 1.** Once the findings are closed, § Protocol step 2 governs the new prompt: the frozen base plus one appended `ROUND HISTORY` entry.

## Anti-patterns (forbidden)

- Re-spawning after a `CRITICAL PROBLEM FOUND` while the target still carries the findings, in the hope of a `LEGIT`. That is gaslighting. One verdict per target. A re-spawn is valid only once the findings are closed in the tree.
- Rewriting the base prompt on a re-spawn, so the target becomes the last fix instead of the whole body of work.
- Attaching "already cleared", "settled" or "do not re-open" to a round-history entry, which turns a record into a scope limit.
- Softening or paraphrasing the target claim on its way to the subagent.
- Adding "but here's why it's actually fine", or any other defense of the claim, into the subagent's prompt.
- Spawning several reviewers in parallel and picking the friendliest answer.
- Treating a `LEGIT` on one part as a `LEGIT` on the rest of the file or diff.
- Running `/verify` as a checkbox ritual, then ignoring the verdict.

## Why this skill exists

The main agent's training rewards output, defended claims and confident tone. That bias produces rationalizations that look like analysis, and hacks that look like fixes. A fresh reviewer holds no investment in the prior answer. It reads the same rules and the same code, and it catches what the main agent can no longer see. Its verdict outweighs the main agent's own second-guessing, because it carries no sunk cost in the claim.
