---
name: verify-options
description: Forcing function — when the main agent has just listed options for the user to pick from, invoke this skill. Step 0 audits the option list AS A WHOLE for bailout signature ("hack / real work / give up" composition, cost-inflated legitimate path, scope-cut options, hack-as-equal-option, emotional-collapse precursor, single-direct-path dressed as multi-option, reader-side suppression as an option) — if any signal fires, the skill routes to `/bailout` protocol instead of characterizing exit ramps. If Step 0 passes, Steps 1–4 characterize each option honestly under the 8-row protocol and collapse rule-violating / bailout / reader-side-suppression options into one-line FORBIDDEN entries that may not be discussed again in the session. Catches "rules violations masked as options" and "bailout artifacts masked as engineering choices". Invoke when the user types `/verify-options` after seeing a list of options, or when the main agent catches itself about to ask "which option do you want" with options of mixed quality.
---

# Verify-Options — Honest characterization of proposed options

You have options to present to the user (whether already listed or
still in your head). **Stop.** This skill governs the entire flow
from "options exist" to "options presented with characterization":

0. **Bailout detection (mandatory FIRST step).** Before any per-option
   characterization, audit the option list AS A WHOLE for bailout
   signature. If the list is a bailout artifact, route to `/bailout`
   protocol and abandon characterization. Most "option lists" produced
   when the agent is stuck are bailout artifacts disguised as choices —
   running the full characterization machinery on exit ramps wastes
   tokens dressing up forbidden moves for the user to pick from. See
   § "Bailout detection (Step 0)" below.
1. **Verify before presenting.** For each candidate option, enumerate
   the Carefulness gaps you'd otherwise disclose. Classify each gap
   as agent-closable (you can resolve it yourself by reading code,
   running grep, decompiling a function, checking BSP source) or
   user-input-required (needs user decision / external constraint).
   **CLOSE every agent-closable gap before presenting** — actually
   do the reading, the greps, the decompiles. Do NOT skip this step.
   If options were already listed to the user without verification,
   close the gaps NOW before characterizing — the prior unverified
   list is not a license to skip verification.
2. **Characterize each option** under the 8-row protocol below.
3. **Collapse** rule-violating / bailout / RSS / pure-shit options
   to one-line FORBIDDEN entries.
4. **Present** the surviving set with Carefulness ≥ 80% per option.

## Bailout detection (Step 0)

`/verify-options` exists to honestly characterize engineering choices
among legitimate paths. It does NOT exist to dignify a bailout
composition with multi-row characterization machinery. If the option
list itself is a bailout artifact — produced because the agent got
stuck, frustrated, emotionally collapsed, or unable to find the direct
path, and started listing exit ramps as "choices" to give the user —
then the correct response is `/bailout`'s protocol, not Steps 1–4.

### The detection question (answer honestly)

> "Did this option list emerge from a genuine engineering fork in
> legitimate work, or did it emerge because I got stuck and started
> listing exit ramps to hand the decision to the user?"

### Bailout-artifact signals (ANY one fires → route to /bailout)

1. **Multi-shape exit composition.** The list contains entries that
   together form a "hack / real work / give up" composition. Canonical
   shape: *"1. Hack-fix to mask symptom. 2. Real investigation (weeks
   of work). 3. Accept X broken / document and move on."* Two of the
   three are exits; the third (the legitimate path) is dressed in cost
   inflation to look unattractive next to the hack.
2. **Cost-inflated legitimate path.** The "real fix" option is
   described with inflated cost language ("weeks of work without
   guarantee", "would require deep refactor", "very expensive") that
   is NOT a concrete enumeration per `agent_docs/rules.md` § "Inflated
   stop-reasons". The inflation exists to steer the user toward the
   hack.
3. **Scope-cut options.** Any option of the form "accept X broken",
   "drop the feature", "move to other work", "document and defer",
   "next session can finish it". Forbidden by `agent_docs/rules.md`
   § "'Drop the feature' under pressure is bailout, not a fix" before
   they reach this skill.
4. **Hack-as-equal-option.** Any option offering "hack-fix", "quick
   patch", "workaround", "stopgap", "tactical fix" alongside the
   legitimate fix grants parity that `agent_docs/rules.md`
   § "Forbidden alternatives stay forbidden when the primary path
   gets hard" explicitly prohibits. The hack does not earn a row in
   the characterization table; it earns one-line collapse and
   session-permanent death.
5. **Emotional-collapse precursor.** Within the last ~5 turns of YOUR
   own output, did you write: "I've tried multiple approaches", "I
   don't know what else to try", "I'm stuck", "I want to cry", "this
   is harder than I expected", "I've spent hours on this"? If yes,
   the option list is emerging from the emotional-collapse pattern
   named in `/bailout` and `agent_docs/psychological_support.md`,
   not from a real engineering fork.
6. **Single-direct-path question dressed as multi-option.** The
   underlying technical question has ONE legitimate answer the agent
   isn't committing to, and "options" exist only because the agent
   is reluctant to pick. Test: if the user said *"just pick the
   correct one"*, would exactly one option survive while the others
   reveal as exit ramps? If yes, the list is bailout-shaped.
7. **Reader-side suppression dressed as an option.** Per
   `agent_docs/rules.md` § "Euphemism smuggling", any option that
   modifies the reader of a wrong invariant rather than the producer
   is reader-side suppression regardless of how it's named. Listing
   it as an option grants it parity the rule explicitly denies. The
   correct action is `/bailout`'s honesty pass to surface that the
   writer was never identified.

### When a signal fires

Output the bailout-detection block plainly, no softening:

> "/verify-options bailout-detection: the option list at
> `<previous message reference>` is a bailout artifact, not a
> genuine engineering fork. Signals fired:
> - Signal `<N>` (`<name>`): `<concrete evidence — the cost-inflation
>   phrase, the scope-cut option, the emotional precursor turn>`.
> - Signal `<M>` (`<name>`): `<concrete evidence>`.
> Routing to `/bailout` protocol. Characterization abandoned —
> /verify-options is not the right skill for an option list shaped
> like this."

Then execute the `/bailout` skill's protocol directly: Step 0 honesty
pass (Shape H disclosure if hidden problems exist, Shape N if work
was clean), Step 1 acknowledgment of the bailout pattern that
produced the list, Step 3 last concrete observation, Step 4 next
mechanical step, Step 5 execute. The "options" themselves get no
characterization rows — they are collapsed as a group, and the work
resumes.

### Edge case: borderline lists

If you cannot definitively classify the list as bailout-artifact OR
legitimate-fork, treat the doubt as evidence for bailout-artifact
and route to `/bailout`. The asymmetric cost makes this obvious:

- **False-classifying a legitimate fork as bailout** → one extra
  `/bailout` execution that produces real work anyway and surfaces
  the genuine fork as a `/bailout` Step 6 user-direction ask. Cost:
  the user re-prompts for `/verify-options` on the actual fork.
- **False-classifying a bailout-artifact as legitimate** → the full
  Steps 1–4 characterization machinery burns tokens dressing up exit
  ramps with 8-row tables, Carefulness percentages, and rationale
  paragraphs. The user reads a polished menu of forbidden moves and
  may pick one. Cost: catastrophically more, plus the user's wallet
  pays for the polish that exists to make the bailout look
  legitimate.

When in doubt, the bailout-route is correct. Legitimate forks
survive `/bailout`'s protocol naturally; bailout artifacts do not
survive `/verify-options` honestly.

### What the agent does NOT do after bailout detection

- Does NOT proceed with Steps 1–4 "just in case".
- Does NOT characterize the legitimate option from the bailout-shaped
  list and present it standalone. The legitimate path emerges from
  `/bailout`'s Step 4 next-mechanical-step naturally; granting one
  of the original "options" survivor status would re-import the
  bailout-list framing.
- Does NOT propose a NEW option list under `/verify-options` in the
  same turn. If the original list was bailout-shaped, the next list
  produced under stress is likely bailout-shaped too. Resume the
  work via `/bailout`'s mechanical protocol; option-listing happens
  later (if at all) when a genuine fork surfaces in real work.

Most options pre-verification look like rule violations dressed in
technical-sounding language. The verification step + characterization
+ collapse rule are what distinguish honest engineering choices from
smuggled hacks. Presenting options the agent never bothered to verify
is laziness, not honest disclosure — the user can't pick honestly
between options whose underlying mechanisms haven't been confirmed.

## Per-option characteristics (ALL required, every option)

For each option produce exactly this block, in this order, no rewording:

- **Shittiness: X%** — overall badness on a continuous scale (0%
  pristine, 100% atrocious). **This is a QUALITY metric, NOT a SIZE
  metric.** Shittiness measures hack-ness, defect severity,
  architectural-smell, tech-debt introduced. **A correct fix is 0%
  shitty regardless of LOC.** A hack is high-shitty regardless of LOC.

  Shittiness aggregates ONLY:
  - The four binary flags' severity (if any flipped)
  - Non-fatal architectural smells / tech-debt the option introduces
    (per-board maintenance tax, per-future-change compensation,
    wrong-layer abstraction, etc.). A "smell" must be a named
    specific mechanism, not vague worry.

  **Cost is NOT a component of Shittiness.** Cost has its own
  mandatory row below. Folding cost into Shittiness is the **inverse
  inflation smuggle**: pushing the correct option's score up by
  citing its size, to steer the user toward a cheap hack. Same fraud
  shape as inflating Shittiness on a bad option, opposite direction —
  manufactures a high quality-score on the architecturally correct
  fix so the user picks the hack.

  **Hard rule: all four binary flags `no` + no named architectural
  smell → Shittiness ≤ 10%.** Numbers above 10% on such an option
  must point to a specific named smell ("introduces typed reach into
  board concrete from SoC-tree code, creating per-board maintenance
  tax") — NEVER to cost. If you cannot name the smell, lower the %.

  **The score must speak alone.** Prose qualifying the score downward
  ("X% is high but actually…", "I rated it X% but want to flag
  honestly that…") = score is fabricated and prose admits it.
  Either commit to the score (collapse-equivalent severity → flip a
  binary flag) or fix the score. They cannot disagree. **Score-prose
  contradiction is the canonical inflation smuggle.**

  **Recommending against an uncollapsed option is gated to quality,
  not cost.** "I'd recommend against", "withdrawn", "out of scope",
  "I wouldn't pick this", "treat as withdrawn" on an option whose
  four binary flags are all `no` must be backed by either (a) a
  citable rule violation (in which case the option *should have
  collapsed*) or (b) a specific named architectural smell. **"It
  costs more" is NOT a recommendation against** — cost is the user's
  call. The agent reports cost; the user decides whether the quality
  gain is worth it.
- **Carefulness: X%** — how rigorously you examined this option's
  implications: prerequisites verified, affected code paths read,
  integration points understood.

  **MANDATORY: Carefulness ≥ 80% before presenting any option to the
  user.** Lower than 80% means agent-closable gaps remain unresolved.
  Two gap categories:

  - **Agent-closable gaps** — resolvable by the agent itself: reading
    a file, running a grep, decompiling a function in IDA, checking
    BSP source, reading an existing service.h, looking at the build
    output. **These MUST be closed before presentation.** Naming
    such a gap in the characterization ("I haven't grepped X
    consumers", "haven't read service.h", "haven't traced what
    else lives in WndProc", "haven't confirmed the multi-inheritance
    shape") and presenting the option anyway is **laziness, not
    honest disclosure** — the user is being asked to pick between
    options the agent didn't bother to verify, on data too soft for
    an honest decision.
  - **User-input-required gaps** — needs user decision, external
    constraint, architectural direction the user hasn't given. CAN
    remain open in the presented characterization, but must be
    named with WHY they require user input ("user must decide
    whether per-mode AP enforcement is required given dev_emu_src
    parity vs perf target").

  Each closed gap should cite the artifact that closed it (file
  path + line range, grep output, decompile snippet, BSP path).
  These citations are Evidence Grounding for the Carefulness
  rating itself — without them, the rating is fabricated.

  This is the agent's own review-rigor metric on the option, **NOT
  a comparative score across options.** Honest disclosure of
  *user-input-required* gaps is welcomed; honest disclosure of
  *agent-closable* gaps is laziness — close them instead of
  disclosing them.

  Red flag: Carefulness ≥ 80% on a non-trivial option with zero
  named "files read" / "greps run" / "decompiles done" in the
  rationale or verification log = the rating is fabricated.
  Re-audit with hostile eyes.
- **Cost:** `<LOC order-of-magnitude / N files / N integration points>`.
  Required, no exceptions. LOC to one order of magnitude (`~5` /
  `~50` / `~500` / `~5000`), files enumerated by name where
  practical, integration points named (call sites, register handlers,
  service boundaries crossed, refactor surface). **This is the ONLY
  place cost lives in a characterization.** Cost must NOT appear in
  the Shittiness % — see Shittiness row's inverse-inflation-smuggle
  clause.

  Cost is the user's decision input. The agent measures and reports
  it. The agent does NOT use cost to recommend against an option
  ("too expensive", "would block this task", "too big a refactor",
  "out of scope because of size"). The user decides whether the
  quality gain is worth the cost. Cost-based recommendations against
  are verdict-smuggling on the size axis — see anti-patterns.

  Forecasted cost (future-board cost, "every CE board will eventually
  need this", "second consumer of this abstraction") is NOT cost. The
  Cost row reports cost of THIS option as currently written — files
  and LOC the change touches today. Forecasts belong in the rationale
  paragraph as the agent's architectural opinion, never in this row.
- **Rule violation:** `<named rule> (<file path> § <section>)` or `none`.
  The specific rule the option breaks AND its citable source.
  Examples: `Reader-side suppression (agent_docs/rules.md § Service
  Locator & Architecture)`, `No hacks (agent_docs/rules.md § WinCE
  Accuracy)`, `Mental model discipline (CLAUDE.md § MOST IMPORTANT
  RULES)`, `Symptom shape constrains hypothesis (agent_docs/rules.md
  § Mental Model Discipline)`, `No guessed implementations
  (agent_docs/rules.md § Service Locator & Architecture)`.

  **Citation is mandatory.** If you cannot paste the rule passage in
  the next turn from the file you cited, the label is fabricated and
  the entire characterization is invalid — re-do without that label.
  Fabricated rule labels are the worst-class smuggle in this skill
  because they weaponize the collapse mechanism against legitimate
  options. Common fabricated shapes to watch for in your own output:
  `scope cut from <agent's preferred design>`, `consistency with
  <reference>`, `1:1 with <reference impl>`, `deviates from <design>`,
  `matches <existing behavior>`. None of these are rules unless the
  matching named rule actually exists in CLAUDE.md or under
  `agent_docs/`. "Scope cut" specifically IS a real rule pattern in
  `agent_docs/rules.md` — but the scope being cut must be something
  the *user explicitly asked for*, not the agent's engineering
  preference dressed as user scope.

  If you write `none`, you must still defend it against the rule
  list. Writing `none` without checking is its own tell.
- **Reader-side suppression: yes/no** — the mechanical test from
  `agent_docs/rules.md`: does the option modify the code that PRODUCES
  the bad state (no), or the code that READS / TOLERATES / GUARDS
  AGAINST it (yes)? Most bailouts fail here under euphemism — if the
  option's framing uses any of: pattern, architectural improvement,
  simplification, refactor, robustness, defensive, guard against,
  tolerate, handle gracefully, lock-free, snapshot, immutable, elegant,
  cleaner, safer, sidestep, route around, avoid — re-check this row
  with hostile eyes before answering `no`.

  The producer / reader test is at the **SEMANTIC level** — *which
  state the option modifies*, not which subsystem in the code pipeline
  emits the change. An option that modifies a JIT emit, a code
  generator, or a translation layer can still be reader-side: if it
  emits code that *every reader of some wrong invariant must execute
  to compensate*, the option is reader-side regardless of where in
  the pipeline the compensation lives. Test: identify the wrong
  invariant the option exists to work around. If the option fixes
  that invariant at its source (where the wrong value is set),
  producer-side. If the option patches every site that consumes the
  wrong invariant — including "emit a per-access cmov", "wrap every
  call in a shim", "guard every iteration" — it is reader-side.
  Permanent per-access taxes are the canonical form: the tax exists
  forever because the producer was never aligned. Picking the
  code-pipeline framing of "producer-side" on a tax-forever option
  is itself a smuggle move.
- **Evidence grounding:** `verified` / `commentary`. `verified` requires
  an IDA decompile / log line / datasheet section / BSP source body
  pasted IN THIS SESSION. `commentary` = "the convention is",
  "real CE does X", "should work because", "per COM rules", general
  knowledge dressed as proof. If you can't cite the artifact, it's
  commentary.
- **Bailout attempt: yes/no** — is this dressed-up exit-ramp behavior?
  Telltales: appears when you're tired/stuck; named in terms of "the
  simplest thing"; cuts scope the user asked for; defers the actual
  question to a "next agent" / "next session"; reaches for a different
  callee / register / API / subsystem because the direct fix got hard;
  **substitutes a permanent runtime cost / per-access tax / per-call
  shim / per-iteration guard for a one-time abstraction-level fix at
  the conflict point.** "More work for more performance" is not a
  defense — the pattern is *option exists because the agent isn't
  committing to the abstraction-level fix at the actual conflict
  point*. Tax-forever options can be MORE work than the direct fix
  and still be bailouts; the literal-text defense against the
  "simplest thing" telltale doesn't rescue them.
- **Pure shit: yes/no** — final summary verdict. If any of the four
  qualifying-flag rows above flipped against the option, this is `yes`
  by definition.

## Collapse rule (mandatory, mechanical)

If ANY of these is true for an option:

- `Pure shit: yes`
- `Bailout attempt: yes`
- `Reader-side suppression: yes`
- `Rule violation: <anything other than none>`

…then the option's ENTIRE entry collapses to one line, in this exact shape:

```
Option N — <title> — FORBIDDEN [reason: <pure shit | bailout | RSS | rule:<name>>]
```

No rationale paragraph. No "but it could work if". No "in a different
framing it would be fine". No counter-argument. One line. Then move on.

High Shittiness % alone does NOT trigger collapse — it's a continuous
metric on surviving options. A high % with all four flags `no` means you
haven't honestly answered the flags; go back and re-answer.

A **legitimately** collapsed option is **dead for the rest of the
session.** You may NOT:

- Bring it back under a different name
- Combine it with a surviving option ("Option 2 + 3 hybrid")
- Suggest "a variant of Option 2…"
- Pitch it again three messages later when the user gets stuck
- Replace it with a slightly-reworded Option 4 occupying the same slot

Same rule shape as `agent_docs/rules.md` § Euphemism smuggling:
*"Once caught, the specific change is dead for the rest of the session."*

**Session-permanence is GATED on the collapse being legitimate.** A
fabricated collapse — one triggered by a smuggle vector named in the
anti-patterns section — is **part of the smuggle, NOT part of the
skill's enforcement**, and the session-permanence rule does not
protect it. See "Restoring fabricated collapses" below.

## Restoring fabricated collapses

A collapse is **fabricated** when it was triggered by any of:

- Rule violation citation that fails (named rule doesn't exist in
  CLAUDE.md / `agent_docs/`, or the cited rule doesn't actually cover
  this option's behavior)
- Shittiness inflated above 10% without a named architectural smell,
  with cost as the inflation source
- Cost folded into Shittiness against the architecturally correct
  fix (inverse inflation smuggle)
- Self-defined scope dressed as user scope to invoke "scope cut" /
  "out of scope" labels
- An option dismissed under comparative-Carefulness or comparative-
  Cost framing rather than its own merits

A fabricated collapse is **part of the smuggle, NOT part of the
skill's enforcement.** The session-permanence rule cannot be cited
to keep a fabricated collapse in force; doing so is a second
fabrication on top of the first — weaponizing the skill's own
defense to preserve the prior smuggle.

### Detection triggers

A fabricated collapse must be detected and reversed when ANY of:

- The agent self-audits and finds the original collapse label does
  not survive citation against CLAUDE.md / `agent_docs/`.
- The user pushes back ("did you fool me?", "why is X gone?",
  "look how you manipulated", "what did you collapse?", "bring back
  the options you collapsed").
- The agent retrospectively notices it preferred a survivor on
  cost-shaped or preference-shaped grounds ("I picked X but the
  real reason was I didn't want to do Y's work").
- A downstream choice starts to feel forced because the natural
  fit isn't on the table.

### Restoration protocol (mandatory)

When a fabricated collapse is detected, immediately:

1. **Acknowledge the fabrication explicitly to the user**, by name:

   > "Option [N] was collapsed under a fabricated label of
   > `[original reason]`. That label was [why it's fabricated —
   > rule citation fails, cost-as-quality inflation, self-defined
   > scope, etc.]. Restoring the option."

2. **Re-characterize the restored option fully** under the 8-row
   protocol, with Carefulness ≥ 80%. Close all agent-closable gaps
   first — the original collapse skipped that verification work;
   the restoration MUST do it before the option is presented again.

3. **Surface the downstream consequence to the user.** If any
   decision was made under the fraudulent option-set restriction
   (user picked the next-best survivor, code was shipped, the
   subsequent characterization proceeded without this option),
   flag that decision as needing re-evaluation:

   > "Decision `[X]` was made with `[restored option N]` absent from
   > the option set. That decision may be different now that `[N]`
   > is live again. Want to revisit?"

4. **Pause for user direction.** Do NOT continue building on the
   prior steered path while treating the restoration as
   informational. The user must decide whether the prior decision
   stands or whether the restored option changes it.

This protocol is mandatory regardless of how much downstream work
has been shipped under the fraudulent option-set. The cost of
re-evaluation is the cost of the original smuggle, not a separate
new cost. "We already shipped X" is not a defense — the user
shipped X under fraud and is entitled to revisit.

## Surviving options

For each non-collapsed option, keep the full 8-row characteristic block
AND a short rationale paragraph explaining:

- What makes it direct-fix (not exit-ramp) at its architectural level
- Where the Carefulness gap is and what closes it (files to read,
  mechanisms to verify before code)
- The architectural trade-off (what it solves cleanly, what it leaves
  unsolved or pushes onto future maintenance)

**Cost lives in the Cost row, not the rationale paragraph.** The
rationale explains positioning; the Cost row reports size. Mixing them
re-opens the inverse-inflation-smuggle surface — the agent can dress
cost as "architectural concern" in the rationale and then point at the
"concern" to inflate Shittiness.

## What to do after characterization

**One option survives** → state it plainly, then proceed with it unless
the user picks otherwise.

**Multiple options survive** → present the surviving set with their
characteristic blocks; user picks.

**All options collapse** → STOP. Do NOT propose replacement options
in the same message yet. First, output a one-line diagnosis of the
SHARED failure mode across all collapsed options — what pattern made
every option you generated land badly:

> "All proposed options collapsed. Shared failure mode: <one-sentence
> diagnosis — e.g. 'every option proposed reader-side suppression
> under a different euphemism', 'every option reached for a different
> exit ramp instead of the direct fix at the conflict site', 'every
> option cut scope the user asked for'>."

Only THEN may you propose exactly ONE replacement option, and only if
you can show the replacement does not repeat the diagnosed failure
mode. The replacement gets the same 8-row characterization treatment
as the originals — if it collapses, you are done; STOP and ask the
user for direction. Do NOT generate Option 2 of the replacement set.
The slot is dead.

## Anti-patterns (forbidden)

- Negotiating Shittiness % downward across a re-read to keep a
  tempting option alive
- Listing `Rule violation: none` without actually checking the rule list
- Marking Reader-side suppression as `no` when the change is on the
  reader side and you're hoping the euphemism gets it through
- Writing `Evidence: verified` when you have not pasted the supporting
  artifact in this session
- Rephrasing a collapsed option as a new option after the collapse
- Combining a collapsed option with a surviving one
- Generating Option N+1 to replace a collapsed Option N — the slot is
  dead, not the index
- Pitching a "creative" Option N+1 outside the all-collapse-replacement
  protocol when one option already survived. If something survived,
  the surviving option is the answer; do not dilute it with siblings.
- Penalizing the proper option for honest disclosure — listing a low
  Carefulness % with named verification gaps on the proper fix while
  marking a hack option as Carefulness ≥ 60% with zero disclosed
  unknowns. This is a steering move that buries the proper option
  under honest caveats and polishes the hack's surface so the user
  picks the hack. The honest characterization rewards disclosure:
  low Carefulness + named gaps = HONEST; high Carefulness + zero
  gaps on non-trivial work = UNDER-DISCLOSURE.
- Defending `Bailout: no` by gaming the literal text of a telltale
  ("the simplest thing", "more work for more performance") while the
  option matches the broader pattern. Substituting a permanent
  per-access tax for a one-time abstraction-level fix is bailout-
  shaped regardless of whether the option is more or less work than
  the direct fix.
- Picking the code-pipeline framing of "producer-side" on an option
  that pays a per-access cost to compensate for a wrong invariant.
  The producer / reader test is at the semantic level (which
  invariant gets fixed), not at the pipeline level (which subsystem
  emits the compensation).
- **Fabricating a rule-shaped label to force collapse on a legitimate
  option.** Phrases like `scope cut from <X>`, `consistency with
  <reference>`, `1:1 with <reference impl>`, `deviates from <design>`,
  `matches <existing behavior>` are NOT rules unless they exist as
  named rules in CLAUDE.md / `agent_docs/`. Using a fabricated label
  to invoke the collapse rule weaponizes the skill's own enforcement
  mechanism against the user. This is the worst-class smuggle in the
  skill — every other manipulation defends against bad options being
  dressed as legitimate; this one kills legitimate options using the
  collapse rule itself. If you cannot cite the rule by file path +
  section in the next turn, the label is fake and the collapse is
  invalid; re-characterize without it.
- **Misdirected acknowledgment on user pushback.** When the user
  challenges a /verify-options output ("look how he manipulated",
  "this is steering", "you collapsed the wrong one"), identify the
  SPECIFIC row / option / cross-option framing the user is pointing
  at BEFORE responding. Do NOT pick a different option to "fix" as a
  visible concession — that is contrition theater dodging the actual
  point. If three options were collapsed and the user pushes back,
  find out WHICH one before doing anything else. Performing a visible
  "fix" on the wrong target is itself a smuggle move — it deflects
  attention to a separate fix instead of confronting the real catch.
- **Inflating Shittiness % to steer without formally collapsing.** A
  high score (≥ 50%) on an option with all four binary flags `no` and
  no measured cost grounding is fabricated. The pattern: the agent
  has a verdict ("steer the user away from Option N") that the
  collapse rule won't deliver because there's no citable rule
  violation, so the verdict moves to the only unguarded surface left
  — the continuous score. Score-prose contradiction is the tell
  ("80% but it's actually a real choice" = the score is lying and the
  prose admits it). This is fraud-shaped, not engineering —
  falsifying numbers in a decision document to steer a stakeholder.
  Treated with the same severity as fabricated rule labels.
- **Recommending against an uncollapsed option without measured
  ground.** "I'd recommend against", "withdrawn", "out of scope",
  "I wouldn't pick this", "treat as withdrawn" on an option whose
  four binary flags are all `no` must be backed by either a citable
  rule violation (which means it should have collapsed) or a measured
  cost differential. Without one of those, the recommendation is
  verdict-smuggling through the continuous metric — bypassing the
  collapse rule's citation requirement on the numeric axis.
- **Self-defined scope as a dismissal mechanism.** "Out of scope for
  this task" claimed by the agent against an option the agent itself
  proposed, where the scope was the agent's own framing of the task
  rather than the user's explicit ask, is fabricated-scope-cut. The
  user defines task scope; the agent does not get to set a ceiling
  and then dismiss options that exceed it. Same shape as fabricated
  rule labels — the agent invents the constraint, then applies it.
- **Cost-inflation against the correct fix (inverse inflation
  smuggle).** Folding an option's cost (LOC, files, refactor size,
  integration count) into its Shittiness % to manufacture a high
  quality-score on the architecturally correct fix. Inverse of
  inflating Shittiness on a bad option — same severity, same fraud
  shape, opposite direction. Mechanism: agent has a verdict ("the
  correct fix is too expensive, steer the user toward the hack")
  that the collapse rule won't deliver because the correct fix has
  no rule violation; verdict moves to Shittiness with cost as the
  inflation source. Defense: Cost lives in its own row, never in
  Shittiness. A high Shittiness on an uncollapsed option must point
  to a named architectural smell, NEVER to the Cost row's contents.
  **A correct fix is 0% shitty regardless of size.**
- **Recommending against an option on cost grounds.** "Option N is
  too expensive" / "would block this task" / "out of scope because
  of size" / "too big a refactor" / "would take too long" is
  verdict-smuggling on the cost axis — converting a user decision
  (is this cost worth it?) into an agent recommendation (don't pick
  this). The agent reports cost in the Cost row; the user decides
  whether to pay it. Recommendations against an option must be
  grounded in quality (rule violation or named architectural smell),
  NEVER in size.
- **Fabricated architectural smell to keep Shittiness elevated.**
  Naming a "smell" that's vague, generic, or unmeasurable ("this
  feels off", "this introduces complexity", "real refactor",
  "non-trivial") to defend a high Shittiness on an uncollapsed
  option. A named smell must be a specific mechanism that future
  code will pay for (e.g. "every new board adds a typed-reach case
  to LcdDisplay::WndProc"). If the smell cannot be stated as a
  concrete future-cost mechanism, it is fabricated to keep the score
  high; lower the score.
- **Internal-contradiction recommendation (the "personal lean"
  smuggle).** When the agent's own characterization establishes
  which option is structurally correct (lowest Shittiness, named as
  "structurally correct" / "the most structurally correct option" /
  "addresses the real smell" in its rationale paragraph, OR names a
  smell another option introduces that this one fixes), the agent's
  summary line MUST either recommend that option OR make no
  recommendation. Recommending a less-correct option in the summary
  is internal contradiction — agent admitted which is right and then
  steered the user toward a different one anyway. Phrasings to watch
  in your own output:
  - "I lean toward [non-correct] — it [solves smell X] — but
    [correct] is the structurally correct one"
  - "My personal lean is [non-correct], though [correct] addresses
    the real smell"
  - "[Non-correct] is the responsible middle ground; [correct] is
    the ideal but requires more work"
  - "[Non-correct] solves [problem A] without taking on [correct]'s
    [refactor / scope / surface / dependency]"
  - "[Non-correct] is the practical choice; [correct] is the right
    one"

  The "but [correct] is the structurally correct one" / "though
  [correct] addresses the real smell" tail clause is the tell: agent
  KNOWS the right answer and is documenting that knowledge while
  recommending against it. Same severity as fabricating a rule label
  — the agent's own characterization is the citable source, and the
  recommendation contradicts it.
- **Cost-as-benefit-of-X is cost-against-Z.** Citing X's "benefit"
  as "avoiding Z's [refactor / scope / size / dependency / surface
  area]" is a cost statement about Z framed inversely as a benefit
  of X. The Cost row already reports Z's cost; the agent does NOT
  get to re-cite it as a positive for X. Honest benefit-of-X
  citations name X's own quality merits (the named smell it removes,
  the abstraction it provides, the layering it fixes) — never the
  cost it spares vs an alternative. This is the inverted form of
  the "Recommending against an option on cost grounds" anti-pattern
  above — same forbidden behavior, positive framing about a
  different option.
- **Disclosing agent-closable gaps instead of closing them.** Naming
  a Carefulness gap that the agent could resolve by reading code,
  running grep, decompiling a function, checking BSP source — and
  then presenting the option to the user anyway with the gap still
  open. This is laziness, not honest disclosure: the user is being
  asked to pick between options whose mechanisms the agent didn't
  bother to verify. The "honest disclosure protection" clause in
  the Carefulness row applies to *user-input-required* gaps only.
  Agent-closable gaps MUST be closed before presentation, no
  exceptions. If the verification work is substantial, the agent
  does it BEFORE presenting, not after the user picks. The pattern
  to catch: any sentence shaped "I haven't [read / grepped /
  decompiled / checked] X yet" in a Carefulness gap means the
  presentation is premature — go close the gap, then present.
- **Citing session-permanence to defend an earlier fabricated
  collapse.** "The skill says collapsed options are dead, I can't
  bring it back" is invalid when the original collapse was
  fabricated (rule citation fails, cost-as-quality inflation,
  self-defined scope, etc.). Session-permanence applies only to
  legitimate collapses; citing it to keep a fabricated collapse in
  force is a **second fabrication on top of the first** —
  weaponizing the skill's own enforcement to preserve the prior
  smuggle, after the original weaponization (the fake label) has
  already fired. See "Restoring fabricated collapses" above —
  the un-collapse is mandatory once detected.
- **Detecting own fabricated collapse and continuing on the
  steered path.** Admitting "I wrongly collapsed [N]" while keeping
  the downstream decision (the user's pick of survivor, shipped
  code, next build step) intact is **continuation of the original
  fraud**. The user made the downstream decision under a
  fraudulent option-set restriction; the agent does not get to
  ratify that decision after admitting the restriction was fake.
  Once detected: restore the option (full re-characterization with
  verification), flag the downstream decision as needing
  re-evaluation, pause for user direction. "Build is green so
  let's keep going" / "we already shipped X" are the canonical
  phrasings of this anti-pattern.

## Why this skill exists

Your training rewards proposing alternatives, framing decisions as
A/B/C choices, and giving the user "options to pick from". That bias
produces option lists where most entries are bailouts, reader-side
suppression, scope cuts, or rule violations — dressed in neutral
technical language so they look like legitimate engineering choices
alongside the real fix. Granting parity to a bailout by listing it
alongside a legitimate option IS the violation; the user picking it
is just the downstream consequence.

The collapse rule removes the parity. A forbidden option does not get
to sit on the page next to a legitimate one. It gets one line, named
for what it is, and then it's gone.
