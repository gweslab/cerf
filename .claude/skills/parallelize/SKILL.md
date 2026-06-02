---
name: parallelize
description: When the user wants to speed up a well-scoped task by splitting it across subagents, invoke this skill. A writing subagent is a competent worker — it reads CLAUDE.md, understands context, and writes real code — NOT a dumb text editor (so don't pre-write its diff) and NOT an orchestrator (so don't hand it architecture). The skill forces the main agent to keep architecture / orchestration / sequencing itself, carve off small, clearly-scoped, non-architectural, file-disjoint, independent coding tasks with explicit boundaries, propose the split AND what it keeps, wait for approval before spawning, and verify every subagent's diff (output is never trusted). Invoke when the user types `/parallelize …` or asks to split / fan-out / parallelize work across agents.
argument-hint: [task to parallelize — empty = current in-flight work]
---

# Parallelize — keep the orchestration, hand out small clear coding tasks

The task to parallelize is `$ARGUMENTS` (if empty, it's the work currently in flight).

## What a writing subagent actually is

A writing subagent is a **full Claude worker** — the same capability as you. It
reads CLAUDE.md and the code, understands context, makes reasonable local
implementation decisions, and writes a real chunk of code. Treat it as exactly
two things at once:

- **NOT a dumb text editor.** Do NOT pre-write the diff and hand it over to
  retype. That wastes its capability and means you did the work anyway. Give it a
  task and boundaries, not a solution.
- **NOT an orchestrator / architect.** Do NOT hand it architectural decisions,
  cross-component sequencing, "where should this state live", or an open-ended
  sprawling effort. That is your job, and a subagent handed it will bail out or do
  real damage (edit the wrong thing, over-reach, invent constants).

Its one failure mode is a **vague or mis-scoped prompt** → it bails or wrecks
things. The antidote is **scope clarity**, not spec completeness. A good leaf is:
small, non-architectural, clearly bounded, with explicit "leave this alone"
carve-outs — handed to the agent with CLAUDE.md and the context to read.

## The principle

**You keep the architecture, the orchestration, the sequencing, and the
verification. A subagent does a small, clearly-bounded, non-architectural chunk of
real code-writing inside boundaries you set.**

You scope it; the agent writes it; you review the result. You do NOT pre-solve it.

## The Delegation Test

A unit may go to a writing subagent ONLY if ALL FIVE hold. If any fails, you keep
it.

1. **Non-architectural** — it needs no decision about where state lives, service
   ownership, strategy/interface design, or how components sequence together.
   *Local* implementation choices inside the task are fine — that's the worker
   doing its job, not architecture.
2. **Small & bounded** — a focused chunk you can state in a few sentences with
   clear edges. If you can't describe its goal and its limits briefly, it isn't
   bounded enough to delegate.
3. **Clearly scoped** — you can name what to do, which files it may touch, and
   **what to explicitly leave alone** (the adjacent things that look similar but
   must not change). The carve-out is the safety rail.
4. **Independent & file-disjoint** — no ordering dependency on another leaf, and
   its file set overlaps no other owner's (yours or another subagent's). Two
   agents editing one file clobber each other.
5. **Verifiable** — you can review the resulting diff against the brief and
   CLAUDE.md without having had to pre-write it.

### CERF: keep it yourself (your job)

- Architecture, orchestration, multi-component sequencing, "where does this state
  live / which service owns it", strategy/interface design.
- Anything needing a verified mental model that spans the system.
- Big or open-ended efforts. "Implement mechanism X across the JIT" is yours; a
  small bounded slice of it may be a leaf.
- **Datasheet/IDA-verified constants carry CERF's guessing risk** — a subagent that
  can't find the reference may invent a value (the exact way this project has been
  burned). If you delegate such a unit, name the exact reference in the brief and
  verify every constant against the source when reviewing. When in doubt, keep it.

### CERF: fine to delegate (a worker's task)

- A small, clearly-scoped logic change with explicit boundaries (e.g. "convert
  this defined family of handler paths from A to B; leave these adjacent cases
  alone").
- A well-specified small feature, helper, or self-contained function.
- Symbol/type renames, adding includes, adding lambda captures, mechanical file
  splits (the 500-line-cap split).
- Read-only research / exploration fan-out (see § Research fan-out).

## Protocol

### Phase 1 — Triage: is this even parallelizable?

Not every task decomposes. If the work is one indivisible judgment call, every
piece needs the same spanning mental model, or the pieces are tightly sequential,
**say so and do it yourself.** Forcing a split onto an unsuitable task produces
exactly the bail-out / destruction outcome. Honesty here beats false parallelism.

### Phase 2 — Decompose into what you keep + leaves

- **You keep** everything that fails the Delegation Test: the architecture, the
  orchestration, the sequenced core, the parts needing a spanning mental model.
- **Leaves** are the units that pass all five. Each becomes one subagent.

Group leaves so each subagent's file set is disjoint from every other's and from
yours. If you can't partition the files disjointly, the units aren't independent —
keep them.

### Phase 3 — Write a clear task BRIEF per leaf (not a diff)

Use the template in § Subagent prompt template. The brief gives goal + boundaries
+ pointers to CLAUDE.md and the context to read. **Do NOT pre-compute the change
and paste it in for retyping** — that's the text-editor anti-pattern. Give scope,
let the agent code.

### Phase 4 — Propose the split, then STOP

Present the plan in this shape, then wait for the user. Do NOT spawn yet.

```
## Parallelization plan

I keep (fails Delegation Test — architecture / orchestration / sequenced core):
- <unit> — <why it's mine>
  files: <paths>

Subagent A (small coding task): <one-line goal>
  files (disjoint): <paths>     leave alone: <carve-outs>
  done when: <objective condition>

Subagent B (small coding task): <one-line goal>
  files (disjoint): <paths>     leave alone: <carve-outs>
  done when: <objective condition>

File partition disjoint: <yes — no path under two owners>
Independence: <yes — no leaf depends on another leaf's output>

Approve / adjust the split / tell me to just do it all myself.
```

Wait for explicit approval. The user may reshape the split — honor it.

### Phase 5 — Spawn the leaves, then do your core in parallel

On approval:
- Spawn ALL writing leaves **in a single message** (multiple `Agent` tool calls)
  with `run_in_background: true` so they run concurrently.
- Then immediately work on **your core**. Do NOT poll — per CLAUDE.md
  § Background tasks, the signal is the contract; polling a backgrounded task is a
  rule violation. The harness signals you as each finishes.
- Subagents share your working tree — safe **only because** their file sets are
  disjoint. Don't reach for `isolation: "worktree"` to paper over overlapping
  files; overlap means they weren't independent.

### Phase 6 — Verify every subagent's diff (mandatory)

The subagent wrote real code; your job is to **review what it produced**, not to
have pre-written it. A returned task is unverified until you've read the diff —
*"Do NOT trust agents output - they are as lazy as you are."* For each leaf:
- Read the actual diff of every file it touched (`git diff` / Read). Don't rely on
  its self-report.
- Check it against the brief and CLAUDE.md: correct, complete (not partial), in
  scope (no edits to the carve-outs or files you didn't authorize), no hacks, no
  guessed constants, no fake success.
- If a subagent stopped because it hit an architectural fork (correct behavior),
  resolve that part yourself, then re-brief the bounded remainder or finish it.
- A botched or out-of-scope leaf is your bug to fix.

### Phase 7 — Integrate and build ONCE

Subagents do NOT build, run cerf, or run git. After all leaves are verified and
your core is done, you build once (`build.ps1`) and run/test as the task requires.
Parallel builds thrash and the `**\*.cpp` glob rebuilds the world — the build is a
single coordinated step you own at the end.

## Subagent prompt template

```
You are a worker doing ONE small, clearly-scoped coding task. Read CLAUDE.md and
its referenced pages first, then the context below.

CONTEXT: <1-3 sentences — what this is part of and why. Point at the specific code
/ checklist / reference the agent should read to orient itself.>

TASK: <the goal, stated clearly — what to build or change.>

SCOPE BOUNDARIES:
- Files you may edit (touch nothing else): <paths>
- In scope: <what to do>
- Leave alone / do NOT change: <the adjacent, similar-looking things that must not
  be touched — be explicit, this is the safety rail>

CONSTRAINTS:
- Follow CLAUDE.md: no hacks, no guessed constants, no fake-success stubs, cite
  references for peripheral/BSP behavior.
- Do NOT build, run cerf, or run any git command.
- Make reasonable LOCAL implementation decisions within scope. But STOP and report
  if the task turns out to need an ARCHITECTURAL decision, contradicts CLAUDE.md,
  or can't be done within the boundaries above. Do NOT guess past an architectural
  fork and do NOT widen scope to "make it work."

DONE WHEN: <objective, checkable condition>

REPORT BACK: the diff you produced — files touched and what you changed and why —
so I can review it.
```

Keep it concrete and scoped. The agent has CLAUDE.md in its system prompt and will
read what you point it at — don't re-explain the rules, and don't pre-write the
code. Give it a good small task and clear edges.

## Research fan-out (read-only, lower risk)

Parallelizing reads is the safest form. Use `subagent_type: Explore` (read-only by
construction). File-disjointness is moot (no writes), but a precise question still
matters — give each one a specific thing to find, not a vague "look into X". And
findings are still untrusted output: spot-check anything you act on.

## When NOT to parallelize

- One indivisible judgment call, or every piece needs the same spanning mental
  model — splitting just multiplies the thinking, it doesn't parallelize it.
- The pieces are sequential (each needs the previous one's result).
- You can't partition the files disjointly, or you can't state a leaf's goal and
  edges briefly.
- The only way to make a leaf safe is to pre-write its diff — then it's not a
  delegable task, it's your work.

In all of these, do it yourself in the main conversation and say why.

## Anti-patterns (forbidden)

- **Pre-writing the subagent's diff and handing it over to retype.** Using a
  competent agent as a text editor — wasteful and pointless. Give scope, not
  solution.
- **Handing the subagent architecture, orchestration, sequencing, or an unbounded
  task.** That makes it the orchestrator — it bails or does damage.
- **Vague scope with no "leave alone" carve-out.** The boundary is the safety; an
  unbounded prompt is how a capable agent wrecks adjacent code.
- Spawning before the user approves the split.
- Two subagents owning the same file.
- Accepting a subagent's self-report as verification. The diff is the truth.
- Letting subagents build / run cerf / run git.
- Splitting an unsuitable task just to look fast. False parallelism is slower —
  you pay for botched leaves AND verification AND the re-do.

## Why this exists

There are two ways to misuse subagents, and they fail in opposite directions. Too
strict — you pre-digest everything into an exact diff — and the subagent is a
pointless typist while you did all the work. Too loose — you hand it architecture
or an open-ended task — and it bails or quietly wrecks things. The win is in the
middle: a competent worker, given a small, clearly-bounded, non-architectural task
plus CLAUDE.md, writes a real chunk of code; you keep the orchestration and verify
the diff. This skill keeps you aimed at that middle and off both cliffs.
