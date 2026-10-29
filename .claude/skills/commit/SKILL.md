---
name: commit
description: Create a git commit with a short message that describes the diff.
---

# Commit - short, leak-free git commit

Someone reads this message years from now, with no knowledge of this conversation. They want one thing: what changed. Every other sentence is noise you are asking that reader to skip.

Fewer words is better. A one-line title is the target, not a minimum.

## Procedure

1. Run `git status`, then `git diff` (staged and unstaged). Read what actually changed.
2. If `git status` lists a core library submodule as changed, follow § Submodules.
3. Stage only the paths this work touched.
4. Commit with a message written under the rules below.

## The message

- **Describe the diff, not the discussion.** The message covers what the change does to the project. It never covers the conversation that produced it.
- **A body is banned. Write the one-line title, then stop.** If you judge a body "substantive", "justified", or "short enough", that judgment IS the slop. Delete it. Ship the title.
- **The title is `<scope>: <change>`.** `<change>` is in the imperative. `<scope>` is one of these values:
  - `tools`, `ce_apps`, `ci`, `frontend`, `cerfman`, `claude`, `assets`, `installers`, `uninstaller`, `website`, `ga`, `db`, `chore`
  - `libCerfCore`, `libCerfEngine`, `libservicelocator`
  - the short name of a SoC, for example `s3c2410` or `vr4121`
  - the short name of a board, for example `jornada820`
  - the name of a CPU architecture, for example `arm` or `mips`

  When no one scope covers the change, join the scopes with `, `, for example `sa1111, jornada720: ...`.
- **Title a commit that only bumps a submodule pointer `<submodule>: bump submodule`, and nothing more.** `<submodule>` is the name of the submodule whose pointer moves, for example `libCerfCore: bump submodule`. A commit that also changes other files takes a title that describes its whole change.
- **End with the `Co-Authored-By:` trailer for the model that runs this session.** Claude Code supplies it.

## Example

One diff, two messages:

> **Slop:** `fix: resolve the LCD issue`
>
> As you asked, this commit fixes the display bug we found. I first tried
> changing the palette, but you were right that the real problem was
> elsewhere. This took several attempts to get correct.

> **Clean:** `s3c2410: latch LCD palette at frame start`

The clean message tells the reader what changed. The slop message tells them about a Tuesday afternoon.

## Forbidden

- **A body that restates the diff** - a summary of the mechanism, a list of the parts touched, an expansion of the title. It is accurate, which is why it feels safe to write. The title already said what changed, and the diff says the rest.

Each of these describes the session instead of the diff:

- **Conversation echoes** - "as you asked", "per your feedback", "you were right", "reverted per discussion".
- **Narration** - "this commit", "in this change we", an essay about a one-line edit, "renamed the section", the name of a section you deleted.
- **Incident history** - "this broke 3 times", "after the regression".
- **Alternatives** - "we chose X over Y", "originally tried Z".
- **Agent or session references** - "the previous agent", "a prior session". The trailer is the only sanctioned model mention.
- **Private design leaks** - section numbers (`§3.1`), phase names, `docs/ai_checklists/` paths, any vocabulary from a checklist. Those files are confidential and never enter git history.
- **Personal data leak** - "John Smith told to do this".

The test for a line: a developer at a fresh clone, who never saw this session, understands it. If a line makes sense only to someone who watched the conversation, delete it.

## Submodules

A change to a core library gets a commit in that library and a commit in each repository that holds the library. A library commit is not complete without the commit that records its pointer.

1. Commit inside each changed library first, in the repository of that library, with this skill.
2. Commit the repository that holds the library last. Stage the path of each changed library together with the changes of that repository. The staged library paths record the new library commits. If the other changes stay uncommitted, stage only the library paths.

Push a library before the repository that holds its pointer. Push the root last. Before you push a repository, make sure that the remote of each library holds the commit that the pointer names. A pointer to a commit that is only local breaks every CI checkout.

## GitHub issues

An issue reference is diff metadata, so it is welcome. When the commit fully resolves the issue, put `Fixes #123` on its own line above the trailer. When the commit is related but does not resolve it, use `Refs #123`. Reference an issue only when the diff corresponds to it. The issue thread is still conversation, so do not summarize it into the body.

## CI keywords

**The default is no keyword.** A commit carries a keyword only when the user asks for that CI action.

These keywords in the commit message start a CI action. CI reads the full message. Put the keyword at the end of the title line.

- `[skip build]` - CI does not build this commit.
- `[rc]` - CI announces the artifact on the QA Discord channel as a release candidate. Every member of the channel receives a notification.
- `[release cerf]` - CI publishes the artifact as a release on all platforms. The release is public, and users download it.

When the user asks for one of these actions directly, write its keyword. The request "/commit a release build" names the release action, so write `[release cerf]`. When the user asks for no action, write no keyword.

When you write a keyword, tell the user in bold immediately after the commit. Name the action that CI will do.

> **This commit has `[release cerf]`. CI will publish a release on all platforms.**

If your reading of the request is incorrect, the user sees that line and stops you.

## Hard stops

- **Never run git unless the user asked.** `/commit` is that ask. It covers this one commit, the library commits of the same change, and the commits that record their pointers. Do not `git push`, which needs separate approval.
- **Never force past `.gitignore`** with `git add -f`. The ignore is a STOP signal.
- **Stage only what this session changed.** Other agents and the user work in this tree at the same time, so `git status` often lists edits that are not yours. If you did not make a change, leave it unstaged and say it is there.
