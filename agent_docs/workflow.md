# Agent Workflow - Mental Model Discipline

This is the core operating method for each task. It is not only for debugging. This is HOW you work.

## Mental Model Discipline

- **AFTER EVERY CHUNK OF WORK, RUN THE SELF-CHECK. RUN IT SILENTLY.** The self-check is a gate on you. It is not a report for the user. Answer each row for yourself. A row that you skip is a row that you failed. If every row is clean, say nothing about the self-check. Write no status block, no table, no checkmarks, and no "self-check: passed" line. A clean self-check is invisible.
  - I violated CLAUDE.md: yes/no [name the rules]
  - (if your work contains code edits)
    - Confidence in my change: 0-100%
    - How bad or good my change is: -100% <-> 100% {❌|🟠|✅}
    - My change is a BAIL OUT pattern: yes/no
    - My change contains FORBIDDEN code comments: yes/no
    - My change DAMAGES the project: yes/no
    - My change contains code smells or antipatterns: yes/no
    - I deferred, out-of-scoped, TODOed, or placeholdered something: yes/no
  - (if your work touches a checklist)
    - I deviated from the CHECKLIST: yes/no [how, why]
  - (if your work touches the emulation layer, for example a SoC or a BSP)
    - I read the related files of (NAME THE MODULE) online or in references/: yes/no [url or file path]
- **A BAD ROW IS LOUD.** If a row is bad, stop. Surface that row only. Give what tripped it, and what you do about it. A row is bad if it reports a violation, a bail out, or project damage. It is also bad if it reports a defer, a checklist deviation, an unread reference, or low confidence. Never print the rows that passed next to it. The rows that passed are the token waste that this rule removes.
- If you print the full block to look diligent, you violate this rule. The full block hides the one row that matters. It is the same "visible work" reflex that produces edits instead of hooks.
- If you did not read the reference, and your confidence is low, and the work clearly needs that reference, STOP. Research first. Then return.
- If a change is bad, revert it and forbid it. The bad thing stays bad.
- If you bailed out, damaged the project, or deferred a whole section, STOP. REVERT. Something went wrong on your side. We defer nothing. We put nothing out of scope. The user told you to do the work correctly. If you do less, you cheat, and you damage the project. You also damage the wallet of the user. If you feel the urge to destroy code in this way, stop and give this information to the user.
- If you wrote bad comments or code smells, correct them immediately.
- If you deviated from the checklist, STOP. SOMETHING WENT WRONG ON YOUR SIDE.
- **Mental model discipline** - a falsifiable mental model must support each change. Before you touch code, write your understanding as a testable claim. Then verify the claim against a concrete reference or a runtime diagnostic. A reference is a chip datasheet, a BSP source, or a CPU architecture reference manual. A runtime diagnostic is a log line or a watchpoint. If the claim is true, continue. If the claim is false, your understanding is wrong. Then investigate more, and write no code. This applies at each stage:
  1. Before you diagnose: "I believe that the crash comes from ...". Verify it with a log line.
  2. Before you implement: "I believe that register X behaves like Y because ...". Verify it with a datasheet entry or a BSP source line that is visible in this conversation.
  3. After you implement: "I believe that the fix works because ...". Verify that the runtime value changed.
  Never write code against an error that you cannot state as a testable claim. **Verification needs a concrete artifact in the conversation**: a datasheet section, a BSP source body, an architecture reference manual section, or a log line. General knowledge is not verification. The words "this is verifiable from X" without the text are not verification. They are guesses in formal language.

## Reference Citations

- **Each non-trivial peripheral or BSP behavior needs a reference, and you disclose that reference to the user.** The reference is most often a decompilation of the guest ROM, named as bundle, module, function and address. It is otherwise a chip datasheet section, a BSP source path, or an architecture reference manual section. `rules.md` § Reference Licence Hygiene governs both forms. Name it in the message that carries the change. When you spawn a review, repeat it in the `/verify` prompt. The reviewer reads only the diff, so an undisclosed reference leaves the implementation ungrounded.
- **What the rules require is that you KNOW the reference and SAY it, never that the file stores it.** A citation inside the source file is optional - `code_style.md` § Comments governs it. Uncited code needs no explanation.
- **A reference you cannot point at is fabrication.** A disclosure does not make it true. Name only what you opened.

## No Fix Without Diagnostic Evidence

- **Write no fix code until a log line identifies the exact error.** "I think that X causes Y" is not sufficient. "LOG shows that X recurses to depth 999" is sufficient. "LOG shows that the value changes from A to B at this point" is sufficient. If you write a fix, and you cannot cite a log line from a diagnostic that you ran, STOP. Add a diagnostic instead. Each fix attempt without diagnostic evidence is a guess, and it makes new errors. The pattern "try a fix, crash, try a different fix, crash, try another fix" shows that you skipped the diagnostic step. Go back and add LOGs.

## When Your Fix Crashes

- **If your fix crashes, stop the edits and start an investigation.** Treat the new crash as a new investigation. Read the crash log. Decompile the function that crashed. Trace the data. Do not treat the crash as a small tweak to your fix. That reaction is the cascading-hack trigger. If your fix caused the crash, your understanding was wrong. Go back to debugging, not to code.

## Observability Gate

- **Observability gate** - before you implement a checklist step, write down the runtime path that proves that its deliverable is correct. Then verify that this path is wired now. If the path needs components that do not exist yet, the step lands as dead code. Then wait until the prerequisite is in place.

## Scaffolding Lifecycle

- **Scaffolding is a debt the next session inherits, not a tool it finds.** Temporary instrumentation outlives the session that wrote it. Record it where a later session receives it as an obligation to remove, never only as an asset to reuse. A durable record that lists it under what was built, and nowhere under what must be deleted, reads to the next session as inventory. The cleanup then never happens, and the scaffolding collects across sessions inside the fragile trees it targets.
- **The set of your scaffolding is the working diff, never what you remember writing.** A cleanup scoped to the edits of the current context window leaves every older one in place. Anything past that boundary reads as part of the environment. Reconcile the whole diff against the investigation record before you call any cleanup done.

## Scope Rules

- **Crash fixes and behavioral changes: one change for each build-test cycle.** Examples of runtime behavior are slot switching, pointer translation, and flag setting. Make ONE behavioral change. Then build, test, and read the log. Verify that each change works before you add the next one. If you make 5 behavioral changes together, and CERF crashes, you cannot tell which change broke it. Then you start to guess, and guesses cascade into hacks. This scope is different from an architectural refactor. In a refactor the code compiles at each step, and you verify the effect of each step independently.
- **Architectural refactors: implement all checklist steps as one body of work.** Do not stop between steps to build or test. Do not wire only a part of the work. The codebase stays broken until all steps are complete. Write the architecture first, and compile after. This applies to a multi-step restructure, for example a service extraction, a type rename, or an interface change. In these tasks the intermediate states do not compile.
- **Architecture docs are the source of truth.** If the implementation contradicts the architecture design, the design wins. If the design looks wrong, resolve it with /verify-options before you write code.
- **If the checklist leaves a decision open, resolve it with /verify-options.** Phrases such as "or new service" or "or alternative" show that nobody made the decision. Options in parentheses show the same. Do not assume. Decide by these documents and the evidence, and continue.
