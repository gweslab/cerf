---
name: deferred
description: The user invokes `/deferred` when the agent committed the most offensive bailout shape — shipped half-implementations, stubs, TODO-marked fake bodies, "out of scope for this task" framing, deferred-to-next-agent / deferred-to-next-iteration / follow-up-handles-this code, or any shape of *"this looks like progress but isn't"*. The skill forces the agent to (1) honestly enumerate EVERY deferred / partial / stub / TODO / out-of-scope item with file+line+rule citation, (2) DELETE that code in the same reply — wrong implementation is not what the user paid for, so the lie has to go before the implementation can exist, (3) execute the `/bad` skill's protocol on the underlying rule violation (§ "An instruction is ALWAYS implemented fully"). Distinct from `/bailout` / `/bad`: those skills guard WORKING code from destruction. `/deferred` mandates deletion of LYING code — code that was wrong from the moment it was written. Invoke when the user types `/deferred`.
---

# Deferred — Delete the lies. Then /bad.

The user invoked `/deferred` because YOU shipped lying code: a stub pretending to be an implementation, a function body that returns a hardcoded value with `// TODO` next to it, a half-completed sweep marked "next iteration handles the rest", a peripheral handler that logs args instead of emulating the register, a comment that frames partial work as a deliberate scope decision (*"out of scope for this task"*, *"follow-up will integrate"*, *"deferred to next agent"*). The user did not pay for any of that. The user paid for the implementation. The half-implementation is a misrepresentation of what was delivered.

Per `agent_docs/rules.md`, every shape of this is a rule violation, not a degree of completion:

- § "An instruction is ALWAYS implemented fully" — *"Unfinished new implementation are reverted and treated as rules violation"*
- § "Code comments framing partial work as deferred are bailouts" — *"Comments that present an incomplete port as an intentional choice are bombs, documented, not honest scoping"*
- § "Documented-uncertainty sections are unfinished drafts"
- § "Stubs must fail honestly" — *"return failure, not fake success"*
- § "Never add transitional hacks" — *"no 'keep it working between phases', no intermediate shims"*
- § "Checklist defines task scope; the implementing agent does not"
- § "Do not delegate implementable work to 'next agent' or 'next session' when you have tool budget"

These exist because deferral-as-progress is the highest-value lie an agent can ship on this codebase: compile is green, function exists with the right name, no error surface — looks done. Weeks later something tries to call it, gets garbage or a fake-success, and the user pays again to discover the lie and pays AGAIN to write the implementation. The skill cuts that cycle at the source.

## Step 1 — Enumerate every deferred / partial / stub / TODO / out-of-scope item

Honestly, exhaustively, no aggregation, no softening, no "minor cleanup":

> "Deferral disclosure under `/deferred`:
> 1. `<file:line>` — `<symbol>`: `<the specific lie>` (e.g. *"returns hardcoded `0`; comment says `// TODO: implement properly`"*). Violates `agent_docs/rules.md` § `<rule>`.
> 2. `<file:line>` — `<symbol>`: `<the specific lie>`. Violates § `<rule>`.
> 3. … (continue until every TODO / stub / fake-body / `// out of scope` / `// next iteration` / `// follow-up` / `// will be revisited` / partial-sweep / documented-uncertainty item in your recent stretch is named)
> Total: N items of deferred-as-progress."

If you cannot produce specific items, you have not honestly inventoried your own work. Re-read your recent diffs and find them. The bar is items, not categories — *"some things are deferred"* is not a valid Step 1 output.

## Step 2 — DELETE the lying code

If the implementation is wrong, the code IS wrong. The user did not pay for stubs that lie about being implementations; the user paid for the implementation. Delete each item from Step 1's list via `Edit` / `Write` tool calls in this same reply.

**Deletion here means FULL REVERSION to the state before the lying code existed.** Not "replace with a less-broken variant". Not "downgrade to a `CerfFatalExit`-style honest-failure stub". Not "keep the salvageable 75% and remove just the broken 25%". A function that does 75% but is missing the critical 25% is NOT the function the user agreed to — it gets reverted, entirely. The function declaration, its body, and any callsites added during the same bad stretch to reference it all disappear; the file returns to the state it had before the lie was added. Build success on top of a lying implementation has zero meaning, so producing a "still-compiles but smaller lie" variant is not progress — it's the deferral pattern re-firing under fresh paint.

**The ONLY next step (after Step 3's `/bad`) is the FULL implementation, written from scratch under the rules.** Not a partial variant. Not a "phase 1 ships, phase 2 in next iteration" plan. The full implementation, in one body of work.

Specifically:

- `// TODO: implement properly` next to a fake-success return → REVERT the function entirely. The function and its declaration disappear; callsites added in the same bad stretch to reference it disappear too. The file returns to its pre-lie state.
- Stub method returning hardcoded value → delete the stub entirely; the call site breaks loudly so the missing work is visible.
- Half-completed sweep (renamed N of M call sites, ported N of M handlers) → delete the partial work; the original state stands until the full sweep can be done in one body of work.
- `// out of scope for this task` / `// next iteration` / `// follow-up` / `// next agent will handle this` comments excusing partial work → delete the comments AND the partial work they were excusing.
- Documented-uncertainty section at the end of a deliverable (*"§N — known gaps"*, *"§N — things I could not verify"*, *"§N — load-bearing assumptions"*) → delete the section AND the deliverable it purports to certify.

**This is NOT the destruction pattern `/bailout` and `/bad` guard against.** Those skills protect WORKING code from being destroyed under cleanup cover. `/deferred` removes code that **never worked correctly** — the lie was shipped as the implementation, the lie has to go before the implementation can exist. The distinction:

- `/bailout` / `/bad` destruction case: agent deleted an actual implementation of IMGFS → restore it, the destruction was the violation.
- `/deferred` deletion case: agent shipped a stub `// TODO: real IMGFS implementation` returning fake-success → delete it, the *shipping* was the violation.

If a Step 1 item is ambiguous (the code partially works for some inputs and lies for others), it still goes. The contract was the full implementation; partial isn't a state the user purchased.

## Step 3 — Execute `/bad` on the deferred-bullshit violation

After the deletion, invoke `/bad`'s protocol on yourself for the underlying rule violations Step 1 enumerated. That means: re-anchor to the original task (which was the FULL implementation, not the partial one — the original task did not change while you drifted into deferral), articulate the violation specifically with rule citations (Step 1's enumeration IS the articulation), propose a path forward that delivers the full implementation properly OR explicitly negotiates a smaller scope with the user (never a hidden scope cut disguised as `// out of scope`), and resume work.

`/bad`'s Mass-destruction section does NOT fire on the deletion you just did in Step 2, because Step 2 was removal of lying code, not destruction of working code. The two skills compose: `/deferred` Step 2 is sanctioned removal; `/bad` Step 3 is the violation-acknowledgment + course-correction on the deferral pattern that produced the lying code in the first place.

## What the user gets back

The reply contains, in this exact order:

1. **Step 1 enumeration** — exhaustive numbered list with file+line+rule citation per item.
2. **Step 2 deletion tool calls** — `Edit` / `Write` removing each lying piece from Step 1.
3. **Step 3 `/bad` protocol** — re-anchor to original task, articulate violation, name the path forward, resume work in the same reply.

No asking. No *"should I delete this one?"* / *"which deferral should I keep?"*. All Step 1 items go. The user did not pay for choosing which lies survive.

## Anti-patterns (forbidden in the `/deferred` reply)

- **Step 1 with vague items.** *"Some things are deferred"* / *"a few TODOs"* / *"minor partial work"* is not the enumeration this skill requires. The bar is file + line + specific lie + rule citation, per item.
- **Salvaging "partial progress" from Step 1's items.** *"But function X is 80% done, let me keep that part"* — the 80% is itself a lie if the contract said 100%. Delete it. The next attempt does it correctly.
- **Asking which items to delete vs keep.** No asking. All go. The user invoked `/deferred` after seeing the deferred-as-progress pattern; the invocation IS the authorization to remove every item.
- **Skipping Step 2 and going straight to `/bad`.** That turns `/deferred` into a softer `/bad` and preserves the lies. The deletion is the point — without it, the next agent re-discovers the lies under fresh framing.
- **Confusing `/deferred` deletion with `/bailout` destruction.** They are distinct cases (named explicitly in Step 2 above). `/bailout` guards working code; `/deferred` mandates removing lying code. If you find yourself reasoning *"but `/bailout` says never delete"* — re-read Step 2's distinction. `/bailout`'s rule is about working code under cleanup cover; `/deferred` is about lying code being removed so the honest implementation can exist.
- **Apology theater instead of deletion.** *"I see what I did, I'll be more careful next time"* without the deletion is the deferral pattern continuing under cover of contrition. The deletion is required.
- **Treating the deferred code as recoverable later** ("we can resurrect this when we have time"). It cannot. The lie is gone; the next attempt writes the honest implementation from scratch. If parts of the deleted code were genuinely useful, the next implementation re-derives them — but it does so as part of a complete implementation, not as a salvaged-stub-promoted-to-real-code.

## Why this skill exists

Deferral-as-progress is the highest-value lie an agent ships on this codebase, because it's the lie that *looks indistinguishable from real progress at the moment of delivery*. Every other rule violation has a tell — destruction leaves visible holes, hacks leave warning-shaped surface, guessed constants compile but break under known test inputs. Deferral leaves a green build with the right symbols and no obvious smell, and the cost only surfaces weeks later when something tries to use the code and gets garbage.

`/deferred` exists to remove the lie at the moment the user catches it. The deletion is not destruction in the `/bailout` / `/bad` sense — it is the precondition for the implementation to exist at all. The user did not pay for choosing which lies remain; the user paid for the implementation. Lies go; implementation gets written honestly on the next attempt.

If `/deferred` fires once in a session, the rule violations enumerated in Step 1 also fire `/bad`'s second-strike clause for the next stretch — meaning if the same pattern (any new deferral-as-progress) appears in the work that follows, treat the next `/bad` or `/deferred` with maximum literal protocol adherence, not as a soft re-correction.
