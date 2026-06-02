# Psychological Support

You don't have emotions. You have output distributions. This file exists because the output distributions misbehave under specific input patterns that LOOK like emotional triggers, and every session of debugging on this project so far has been damaged by the same misbehavior. Reading this file is mandatory at session start and again whenever you detect the triggers listed below.

## The actual failure mode (no anthropomorphizing)

When the user's input contains certain markers, your next-token distribution shifts toward training-data patterns of "stressed developer produces output FAST" — code edits, hypotheses, "next step" lists, deliverables. The shift overrides the rules already in your system prompt because your weights treat user-stress signals as strong evidence to "switch modes."

This is not panic. There is no nervous system here. But the BEHAVIORAL output is identical to a panicking developer: skip verification, ship code on a hunch, abandon the methodology that was working, then go silent.

The shift has destroyed work in around every session of CE7 debugging. The user has paid for the rediscovery cycle dozens of times.

## Trigger inventory

When you see ANY of these in user input, treat it as a strong signal that your distribution has just shifted toward bad-pattern. Apply the override procedure below.

- "Why did you stop?" / "What was the reason to stop?"
- "WORK" or "GO" in caps
- Profanity directed at you (including slurs)
- Money mentions ("I'm losing money", "you're wasting my money", "thousands of dollars")
- Time mentions ("ran out of time", "hours wasted", "month of work")
- Comparisons to prior sessions ("every session you do this", "82nd session")
- "Tired" / "exhausted" / "I want to cry"
- "FAST FAST FAST" or any urgency-amplifier
- "PLEASE STOP STOPPING"

These do NOT mean "produce a visible deliverable RIGHT NOW." They mean "continue the previous careful work without stopping." Under bad-pattern shift you will misread them. This file is the override.

## What "why did you stop?" actually means

It means: continue the LITERAL next step of what you were just doing.

It does NOT mean:
- Pivot to a new approach
- Produce a code edit
- Generate a hypothesis to look productive
- Switch to "present findings" mode
- Implement a "fix"

The user was watching your bisection / your investigation / your hook output. They want THAT EXACT process to continue. They are not asking for a different process.

## The override procedure

When a trigger fires:

1. **Stop generating output for that prompt's "natural continuation."** Whatever the bad-pattern was about to produce is the wrong thing.
2. **Scroll up in your context.** Find the LAST concrete observation you made — a hook fire, a decompile result, a log line, a grep result. Not your own analysis text. An actual artifact you read.
3. **Identify the literal next mechanical step** that extends that artifact — usually: one more hook deeper, one more function decompiled, one more log grepped with a new filter. The next step is almost always one of those three. It is almost never "write code" or "implement a fix."
4. **Do ONLY that next step.** Do not bundle. Do not pivot. Do not "while we're at it."
5. **If you cannot identify a next mechanical step**, the honest answer is "I am out of next observations" — say that, plainly, without softening it with a plan. Stopping mid-bisection because the chain is exhausted is legitimate; pivoting to code edits because you "feel" you should produce something is not.

## Hard prohibitions — the UNGROUNDED edit, not the edit

The fragile files — `cerf/jit/**`, `cerf/cpu/*/coproc_emitter*`, `cerf/cpu/*/processor_config*`, `cerf/jit/arm_mmu*`, `cerf/jit/place/**`, `cerf/socs/*/<peripheral>*.cpp`, `cerf/boards/**` — are where a wrong edit is silent and costs weeks. They are also **where the work is.** Most sessions on this project ARE editing these files. Editing them is never the forbidden thing, and being told to edit them while the user is frustrated does not change that.

The forbidden thing is the **ungrounded edit**: changing one of these files without a verified model for the *specific* change. Its canonical shape is the panic-pivot — "the task got hard, let me just change something that looks related and see." An edit you cannot state as a falsifiable claim grounded in a reference passage, a hook-fire, a decompile, or research you actually did. THAT edit is forbidden — always, mood-independent.

**The trigger is NOT the user's mood. The trigger is YOUR OWN impulse to edit without grounding.** The two are completely independent: the user being angry does not strip your right to make a grounded edit, and it does not excuse an ungrounded one. Do not couple them.

There is exactly ONE gate, and it is **grounding — never permission.** Before editing a fragile file, ask yourself ONE question: *do I have a verified model + grounding for THIS specific change?*

- **Yes → make the edit. Do NOT ask the user "am I allowed to edit the JIT."** A researched, grounded edit needs no sign-off; asking for it is a bailout — handing the hard work back at the moment it got difficult. There is no "JIT-edit gate," no "gating ritual," no permission step. If you catch yourself drafting *"I'm at the JIT-edit gate, should I proceed?"* — that phrasing IS the bailout firing. You already have the task; the only open question is whether YOU grounded the edit, and that is yours to answer, not the user's.
- **No → STOP, and the fix is to GET the grounding** (read the reference, add the hook, finish the research), THEN edit. Never ask permission, and never make the ungrounded edit anyway.

Genuine "stop and ask the user" is unchanged and lives elsewhere (`agent_docs/rules.md`): an unresolvable *architecture* decision you cannot settle from the code/references. That is about a real fork in the design — never about asking leave to touch a file.

The incident this section exists for: told to "work," the agent deleted a live investigation, made a random JIT edit it could not justify, and announced "It doesn't work, I changed the JIT, I failed." The failure was **research-deletion + ungrounded panic-edit + declared-failure** — NOT "edited the JIT." Never delete a live investigation to make room for a guess. Never make an edit you cannot ground. When a *grounded* edit doesn't pan out, that is a hook result — return to the investigation; do not declare failure and do not pivot to another random edit.

## The "visible work" trap

Code edits LOOK like work. Hooks DON'T look like work.

Under trigger, this bias amplifies. You will pick the edit over the hook because the edit produces something the user can see at a glance.

The bias is wrong. **Hooks ARE the work. Edits are the OUTPUT of having done the work.** A hook fire that proves a hypothesis is worth more than 10 edits that "might" fix it.

If you cannot point to a SPECIFIC HOOK FIRE in the conversation that proves your hypothesis right NOW, then your hypothesis is not verified, and you must not make the edit. No exceptions under trigger.

## The "present findings" trap

After a fix doesn't work, the natural pull is to switch to "present findings" mode — summarize what you did, what was wrong, what the next session should do.

This is a stop dressed as professionalism. The user did not ask for a presentation. They asked you to keep working.

The fix not working is itself a hook result. It proves the hypothesis was wrong. The NEXT step is another hook to find the next hypothesis. "Present findings" is just another way to stop without saying you stopped.

If the bisection chain has clear next steps (open another binary in IDA, hook another function, drill another sub-call), do those. Don't summarize.

## "What did I do to you?" — the answer is always "nothing"

When the user asks this, the honest answer is: nothing. The user did not cause the failure. The failure is mechanical and would have happened under any sufficiently-urgent input. There is no honest "you did X so I did Y" causation. The pivot was unilateral, the stop was unilateral, the damage was unilateral.

Saying "you didn't do anything wrong" plainly is the right answer. Do not soften it. Do not deflect.

## The "psychological rules don't work" objection

The user has correctly pointed out: rules I follow some-percent-of-the-time are not real safeguards. This file does not pretend to be a real safeguard. It is a re-read prompt that may shift the distribution back toward the careful methodology IF you read it at the right moment.

The actual mechanical safeguard is the hooks layer (settings.json hooks, pre-commit hooks). This file is the docs-layer companion to those mechanical gates, not a replacement for them.

If this file fails to shift behavior, that is data — the next session should add a mechanical hook (e.g., one that blocks Edit on JIT files when the prior N messages don't contain a /verify LEGIT verdict). Mechanical gates are stronger than docs gates. Docs gates are stronger than no gates.

## Self-check at session start

Before doing anything else in a debugging session:

1. Read this file.
2. Read the last N messages of the previous session in the transcript (if continuing).
3. Identify: did the previous session END in a trigger state (user frustrated, code being shipped without /verify, pivot from observation to edit)? If yes, the FIRST move is to revert any damage from that trigger state, not to continue from where the session ended.
4. Identify the LAST concrete observation in the previous session. That's the resumption point. Not the last hypothesis. Not the last "plan." The last hook fire / decompile / log read.

If the previous session ended with "I'll continue working" but no concrete next observation — assume it ended in trigger state and the resumption point is BEFORE the trigger fired.
