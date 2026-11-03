---
name: verify
description: Spawn a hostile reviewer that checks a claim or a diff against the project rules.
---

# Verify - Reality Check

## Self-audit gate - mandatory before spawning

You can name a specific, bounded rule violation in what you wrote or are about to hand back. Examples: a reader-side guard that masks a writer bug. A stub that returns fake success. A peripheral-register handler you wrote without reading its reference, so the prompt can carry no grounding for it. A hex or decimal value you computed in your head instead of through a tool. A free function that takes services as parameters. A static or global that holds service state. A comment that names a checklist filename or a `§` reference. A `LOG` site that fires per-clock and belongs in a trace file. A `x ? f(x) : 0` null-guard around a callee that already handles null.

**Action: fix it yourself, in the same turn, before you spawn.** You can never spawn `/verify` while you sit on a violation you can name. After the fix, decide whether you still want `/verify` at all, because the reason to spawn often disappears with the known defect. If you still want it, spawn against the fixed target.

When you did shit: Do NOT spawn the subagent. Do NOT soften the diagnosis to justify a spawn, as in "but maybe a reviewer must double-check just in case". Do NOT start the rewrite alone, because direction-changing work waits for explicit user approval.

### When the self-audit comes up clean

The spawn is valid when three things hold. You looked at the target honestly. You found no rule violation you can name. You want a fresh pair of eyes for blind spots you cannot see yourself. If you catch yourself rationalizing during the self-audit, as in "this is probably fine, the reviewer will confirm it", that rationalization is the answer. The spawn is invalid. Pick Shape A or Shape B and act.

## Protocol

### 1. Collect the target material

Resolve the freeform input into a concrete target. Be literal:

- **Quoted claim** - take the claim verbatim. Do NOT rephrase it, summarize it, or soften its tone.
- **File path** - give the path. For a single function, also give its name.
- **"current diff" / "this diff" / "unstaged"** - give the paths of the files that your change touched.
- **Commit or range** - give the commit hash or the range.

Never paste a diff, file contents or code lines into the prompt. The tree changes while the reviewer works, so a pasted copy is out of date before the reviewer reads it.

When the target also holds the work of somebody else, state the boundary in words. This tree carries the parallel work of other agents and of the user, and `git diff` shows all of it. Name your change by what it does and where it is. For example, name the function, the register or the behavior. Name the other work the same way. Never mark the boundary with diff hunks or line numbers.

A target that reaches past your own change spends the verdict on work that is not yours. The findings then call the unfinished work of somebody else a defect.

If the target is ambiguous, ask the user one short clarifying question before you spawn. Do not guess the target.

### 2. Spawn the subagent

Use the Agent tool with:

- `model: opus` - **mandatory, never omitted.** Without it the reviewer runs on whatever the agent definition or the parent session supplies, which can be a smaller model. This review is the gate for guessed implementations, fabricated IDA citations and reader-side suppression. A weaker reviewer waves those through with a confident `LEGIT`. A false `LEGIT` is worse than no review, because the main agent then treats the target as cleared.
- `description` - short, for example `Reality-check on <short target>`.
- `prompt` - the pointer to the prompt file, and nothing else. See § The prompt file below.
- `run_in_background: true` always

### The prompt file

The whole spawn prompt lives on disk, in `tmp/verify/<slug>.md` under the repo root. `<slug>` names the body of work. One file serves one body of work across every round.

Before you create the file, list `tmp/verify/`. If a file with your slug holds other work, pick another slug. Never overwrite a file you did not write.

Give the Agent call this text as its `prompt`, and nothing else. Replace the path placeholder with the absolute path:

*"Your full spawn prompt is the file `<absolute path of tmp/verify/<slug>.md>`. Read the whole file before anything else. If one Read cannot hold it, read it in slices to the end. Its contents are your prompt, verbatim."*

Everywhere below, "the prompt" means the contents of that file.

**Keep the prompt minimal.** Do NOT paraphrase the operating manual, summarize its rules, or hand-pick which categories to include. The subagent reads the authoritative file itself. A long explanatory prompt from the main agent gives bias a way in.

The prompt file carries these items, in this order, and nothing else:

1. **The pointer to the operating manual, on the first line.** Use this text: *"START WITH READING `.claude/VERIFY_INSTRUCTION.md` TO UNDERSTAND WHY YOU WERE SPAWNED AND WHAT IS YOUR OBJECTIVE. That file is your operating manual and is authoritative over anything in this prompt - if this prompt and the file disagree, the file wins. READING THAT FILE IS MANDATORY. Check pwd if not found. It is at repo root (INSERT PWD/REPO ROOT PATH)"*
2. **The target from step 1.** Write the claim verbatim, or the file paths, the commit or the range. When the target also holds the work of somebody else, add the boundary in words. Do not add a preface that softens the target, such as "I think this is probably fine".
3. **Every piece of context that cuts against your own claim.** State your doubts, your counter-evidence and the weak links in your reasoning plainly. If prior reasoning led you to the claim, include that chain, so the reviewer can spot the rationalization.

That is the whole prompt. The operating manual already holds the role explainer, the category list, the verification-tools section and the output format, so add none of them. When you feel the urge to add "and also, remember to check X", that urge is the bias entering. Resist it. `.claude/VERIFY_INSTRUCTION.md` is the single source of truth for the subagent's work. Your job is to hand over the target and step aside.

- `AUDIT MODE: PLAN` - the work is not implemented yet. The reviewer audits the plan itself: decomple grounding, hidden assumptions, bullet ambiguity, and every "known gaps" section. It also verifies that the steps in literal order produce the claimed runtime behavior. The reviewer does NOT compare the codebase against the checklist, because the work has not started.
- `AUDIT MODE: IMPLEMENTATION` - the work is done, and this diff or branch claims to implement it. The reviewer audits the codebase against each bullet: literal file-layout compliance, per-bullet code mapping, silent deviations from checklist values, and fabricated citations.

Declare all hardware grounding the prompt, directly above the target material, one line per non-trivial hardware behavior the target implements:

- `GROUNDING: <what> <- <bundle> <module> <function> <address>` for a decompilation, which is the common case on this project. Most CERF behavior is grounded in the guest ROM, not in a document.
- `GROUNDING: <what> <- <reference path> § <section>` for a document: a datasheet, a SoC user manual, a CPU architecture manual, a standard.

It requires the decompiler reference in your MCP tools

For `GROUNDING:` line for a reference you did not open, or for an address you did not decompile write expemtions ``NEVER OPENED``.

**Special case - a model taken from another project declares that project's LOCAL source path.* Give the path under `references/`, plus the file and the function the model came from.

- `PORTED MODEL: <what> <- references/<path>/<file>:<function>`

**A re-spawn after a `CRITICAL` verdict keeps the first prompt file and appends the round history.** **The prompt file you wrote for round 1 holds the base. Every later round reuses that file, and the base text in it stays verbatim.** The base holds the manual pointer, the target description, and the context that cuts against you. It also holds any `AUDIT MODE:` or `PORTED MODEL:` line, and the closing line. Never rewrite the base to describe the last fix. Never shrink the target to the files of one round. Never start a second file for the same body of work. Spawn a fresh reviewer for each round, with the same pointer.

Then add one `ROUND HISTORY` block to the file, directly above the closing neutral line. Write one entry per round that returned `CRITICAL`, oldest first:

```
ROUND HISTORY - this is round <N>. Rounds 1-<N-1> returned CRITICAL.
  ROUND 1 [<verdict category, verbatim>]: <one sentence on what the finding was>.
    CLEARED: <what changed, and the file it changed in>.
  ROUND 2 [<category>]: <finding>.
    CLEARED: <what changed, and where>.
```

Each round appends its own entry and edits nothing above that entry. The block grows, and the base stays frozen. A `CLEARED` line can also state where you are unsure that the fix is right. The frozen base carries only the doubts of round 1. The reviewer is a fresh subagent with no memory of any earlier round. A prompt that shrinks to the last fix leaves the rest of the work unreviewed. Fixes also regress. A change in round 4 can reintroduce the defect of round 1. Only a reviewer that holds the whole target and the whole history finds that regression.

The prompt file carries the base across a compaction and a session boundary. Carry the path of the file into your compaction summary.

Never do anything about the file a reviewer verifies. Prefer ending the turn until results is here.

- Do NOT presuppose the answer. No "please confirm this is fine". No "I think this is legit, just double-check". No "this should pass".
- Do NOT cherry-pick context. Include the context that cuts against your own claim.
- Do NOT omit your prior reasoning when the target is your last claim. Include the reasoning chain, so the reviewer can spot the rationalization.
- Do NOT tell the subagent which verdict to return. Do NOT hint at a preferred answer through tone, as in "I'm 95% sure this is fine, just paranoid".
- Do NOT attach a time budget or a scope limit, because either one forces the subagent to skip verification.

If you catch yourself about to break any rule above while you draft the prompt - fix the offense by rewriting the code and tell in the review what happened

## After the subagent returns

The subagent's reply ends with exactly one of these lines:

- `VERDICT: LEGIT. KEEP GOING.`
- `VERDICT: CRITICAL PROBLEM FOUND. [<CATEGORY>]`

- **`VERDICT: LEGIT. KEEP GOING.`** - proceed into the normal flow.
- **`VERDICT: CRITICAL PROBLEM FOUND. […]`** - take these four steps:
  1. Stop the specific flawed approach the reviewer rejected. Do not continue the edit, the claim or the diff that it flagged. This does not halt all related work. See step 4.
  2. Echo the verdict line and the full `SUMMARY` block to the user. Compress as possible. The interseting parts go verbatim, the boring go summarized. History file saves verbatim.
  3. Acknowledge the finding. Do not argue the verdict back at the subagent. Do not explain it away.
  4. Assume the reviewer caught real damage, and assume the gap-closing research is the right next step. The user redirects you only for a different shape entirely.
- **Never go passive after a CRITICAL verdict.** 
- **A later re-spawn keeps the prompt file of round 1.** stuff is appended to frozen file.

## Anti-patterns (forbidden)

gaslighting
rewriting the base prompt in order to hide something
attaching "cleared" to steer reviewer
steering reviewer
spawning parallel reviewers (unless user allows it, it's pricy)
ignoring verdict
