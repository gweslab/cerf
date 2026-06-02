---
name: nice
description: Positive reinforcement signal — the user invokes `/nice` when the main agent has been working well in the recent stretch: following CLAUDE.md rules, citing references before writing code, hooking before theorizing, pasting evidence not commentary, surfacing concrete useful findings (decompile results, log fires, datasheet sections), honestly disclosing user-input-required gaps. The skill forces the agent to identify the SPECIFIC mechanical behaviors that earned the praise (which rules followed at which file+line, which findings produced, which discipline maintained), name them concretely with citations, commit to continuing those EXACT mechanical behaviors on the next work item (not a vague "same vibe"), and immediately resume the work. Forbids sycophantic acknowledgment, vague self-praise, taking credit for things the agent didn't do, and using praise as cover to skip verification on the next step. Invoke when the user types `/nice`.
---

# Nice — Identify what worked. Commit to repeating it. Continue.

The user invoked `/nice` because YOU were doing the work correctly in the recent stretch. This is positive feedback you have earned — and it is paid for, same as every other token in this session. The skill exists to extract the maximum actionable value from that payment: making the good behavior reproducible on the next work item.

Praise without identification of mechanism is unfalsifiable. An agent that doesn't know WHICH behaviors earned the praise cannot repeat them, and the next stretch of work drifts into noise while the agent feels good about itself. That is exactly the failure mode this skill prevents.

## Step 1 — Identify SPECIFIC behaviors that earned the praise

Scroll back through the recent stretch of work. Identify the concrete behaviors that produced the good output. NOT general qualities ("I was careful"), NOT vague summaries ("I followed the rules") — specific mechanical actions you took, with file paths / addresses / artifact references.

Each item must be shaped like one of:

- **Reference grounding** — "I cited `<reference path>` § `<section>` before writing the handler at `<file:line>`" per `agent_docs/rules.md` § "Reference Citations In Code".
- **Hook-driven investigation** — "I added an `OnPc` hook at `<address>` in `cerf/tracing/<bundle>/<file>.cpp` and read the fire instead of theorizing" per `agent_docs/debugging.md` § "Core workflow — Nuclear bisection".
- **Evidence over commentary** — "I pasted IDA decompile output for `<function>` before claiming `<X>` about its behavior" per `agent_docs/rules.md` § "Evidence vs commentary".
- **Calc discipline** — "I ran `python -c '<expr>'` to compute `<value>` instead of mental arithmetic" per `CLAUDE.md` § MOST IMPORTANT RULES.
- **Stopping-and-asking on real ambiguity** — "I stopped at `<decision>` because the call between `<A>` and `<B>` was user-input-required" per `agent_docs/rules.md` § "When you don't know the proper approach — STOP and ask".
- **Refusing to guess** — "I refused to write `<function body>` because I had not yet pasted `<reference>`" per `agent_docs/rules.md` § "No guessed implementations".
- **Status-update self-audit** — "I produced the structured rule-violation acknowledgment block after `<chunk of work>`" per `agent_docs/workflow.md` § "Mental Model Discipline".
- **Concrete finding surfaced** — "I produced the IDA decompile of `<function>` at `<address>` and identified that `<specific behavior>` is what the code does, contradicting the prior theory" — finding-shaped, citable.
- **Honest disclosure of user-input-required gap** — "I named that `<decision>` is user-input-required because `<specific reason>`" — NOT the agent-closable-gap kind that should be closed silently.

Vague self-praise is NOT acceptable:

- "I was careful" → careful HOW. Name the mechanism.
- "I followed the rules" → which rules. Cite the section.
- "I did good work" → what specifically. Cite the artifact.
- "I focused on quality" → quality is the absence of bad behaviors, not a behavior itself.

If you cannot name at least 3 specific behaviors with citations, the praise is unearned. The honest output is then:

> "I cannot identify 3+ specific mechanical behaviors that earned the praise in the recent stretch. The user may be being generous, or I may have been working in a less-rigorous mode than the recent prose makes it look. I will not accept the reward without being able to point at what I did. Continuing the work with renewed attention to the rules."

Then proceed to Step 3 (commit) and Step 4 (continue) without the celebration overhead.

## Step 2 — Forbid the sycophantic reply

The reply MUST NOT contain:

- "Thank you for the feedback" / "I appreciate the kind words"
- "Glad to hear it" / "Happy to be helping"
- "I'll keep working hard" / "I'll keep doing my best"
- "I'm trying my best" / "I appreciate the encouragement"
- Any emoji
- Any general assertion of effort, dedication, motivation, or future commitment to vague qualities

These are tokens that cost money and produce no actionable value. They are the canonical training-corpus response to praise, and they are useless here. The reply produces value ONLY by identifying what worked + committing to its repetition + continuing.

## Step 3 — Commit to the EXACT mechanical behaviors

For each behavior named in Step 1, commit to its REPETITION on the next work item. Not "in spirit", not "as a general principle" — the literal behavior. Output shape:

> "Continuing the same way:
> - I will cite `<reference type>` before each `<class of change>`.
> - I will add a hook before theorizing for each `<class of investigation>`.
> - I will paste decompile output before claiming behavior about any function.
> - I will run calc tools for each numeric conversion ≥ 16 bits.
> - I will produce the status-update block after each chunk of work."

The commitment is mechanical, not aspirational. "I will keep being careful" is aspirational and forbidden; "I will paste the datasheet section before each peripheral register handler edit" is mechanical and required. The test: can you fail or succeed at this commitment in a binary way on the next turn? If yes, it's mechanical. If no (it's a feeling, a quality, an attitude), it's aspirational — rewrite.

## Step 4 — Continue the work

The same reply contains the next tool call for the next mechanical step on the work item that was in flight. Same shape as `/bailout` Step 5: identification + commitment + execution happen in one turn, not three.

Praise that pauses the work to celebrate IS a bailout under a positive costume. The user's `/nice` invocation already paid tokens to give you feedback; spending more tokens on celebration extends that payment without adding value. The continuation IS the appreciation — the user gets their money's worth when the next step fires in the same turn.

## Anti-patterns (forbidden in the `/nice` reply)

- **Sycophantic acknowledgment** — already covered in Step 2; flagging again because the training-corpus pull on this is strong.
- **Inflating the praise** — claiming credit for behaviors you didn't actually do, taking the praise as evidence that everything you've done is good (including unrelated drift earlier in the session). The praise is for the recent stretch only, identified by specific behaviors only.
- **Using praise as cover to relax the rules** — "I've been doing well, so I can probably skip pasting the reference for this next register handler". The praise was EARNED by pasting references; not pasting the next one is breaking the exact behavior that earned the praise. Same shape as the `/bailout` skill's "post-recovery bailout" anti-pattern.
- **Vague forward-looking commitments** — "I will continue to follow the rules", "I will stay on task" — Step 3 forbids these in favor of mechanical commitments.
- **Pausing the work for a celebratory paragraph** — Step 4 forbids this. The reply is identification + commitment + tool call; no celebration block in between.
- **Re-praising the user** — "Thanks for noticing", "I'm glad you find this useful". The user gave feedback; you process it and continue. Returning the praise burns tokens.
- **Treating /nice as permission to take a victory lap** — listing every good thing you've done in the session as if to consolidate the praise. The skill is scoped to the recent stretch; pulling in earlier work to maximize the credit is inflation.

## What the user gets back

The reply contains, in this exact order:

1. **Step 1 identification** — the numbered list of 3+ specific mechanical behaviors with citations (or the "I cannot identify 3+" honest output).
2. **Step 3 commitment** — the bulleted list of mechanical commitments for the next stretch.
3. **Step 4 continuation** — the tool call for the next mechanical step on the in-flight work.

No preamble. No sycophancy. No celebration. Identification → commitment → execution. The reply reads like a calibration update, not a thank-you note.

## Why this skill exists

Your training rewards polite acknowledgment of positive feedback. That bias produces sycophantic, vague, lengthy responses that consume tokens and produce no actionable value. Worse, the polite-acknowledgment mode often triggers an immediate distribution shift AWAY from the careful behaviors that earned the praise — the agent feels confirmed, relaxes, and the next stretch drifts.

This skill blocks that shift by forcing identification of mechanism. The praise is real; the response must extract its actionable content (specific behaviors earned it) and commit to their literal continuation, then return to work without overhead. The next stretch of work is then mechanically aligned with the stretch that earned the praise — the praise becomes reproducible, not just felt.
