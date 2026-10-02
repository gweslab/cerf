---
name: cerf
description: List the project skills and offer the environment doctor.
---

# /cerf - project skill index

Print the index of the project skills. Then offer the environment doctor. Do
not run the doctor unless the user agrees.

## Step 1 - print the skill index

Open with a short welcome line for the CERF Claude development environment. Use
one or two lines. Do not write a paragraph.

1. List the immediate subdirectories of `.claude/skills/` in the repo root. Each
   subdirectory is one skill.
2. Read the `name` and the `description` from the `SKILL.md` of each skill.
3. Condense each description to one short line. The descriptions in the
   frontmatter are long. Write one clause that gives the purpose of the skill.
4. Print one line for each skill:

   ```
   /<name> - <one-line explanation>
   ```

Order: print `/start-board-implementation` first. It is the entry point for the
core work of the project, which is board bring-up. Print the other skills after
it, in alphabetical order by name. If `/start-board-implementation` is absent,
print all the skills in alphabetical order.

## Step 2 - offer the environment doctor

After the index, write one short line that offers the doctor. For example: "I
can run the environment doctor (`setup.ps1 -Check`) for a health report on this
clone."

Then stop. Do not run the doctor. Do not ask more questions.

Note: git does not clone `.git/hooks/`. `core.hooksPath` lives in the local
`.git/config`, which git also does not clone. A fresh clone runs no git hooks
until `setup.cmd` writes this configuration.

## Step 3 - run the doctor

Run this step only when the user agrees.

From the repo root, run this command:

```
powershell -NoProfile -ExecutionPolicy Bypass -File setup.ps1 -Check
```

The doctor changes nothing. It prints one line for each check, with a tab
between the fields: `STATUS<TAB>key<TAB>detail`. STATUS is `OK`, `WARN`, or
`FAIL`. The exit code is 1 when one check or more failed.

`setup.ps1` owns the list of checks. Read the output of `setup.ps1`. Do not test
any of these conditions directly in this skill.

A FAIL has these consequences:

| key | consequence |
| --- | --- |
| `git-repo` | This directory is not a git repo. No other check has a meaning. |
| `git-hooks` | `core.hooksPath` is not `.githooks`, so `.githooks/pre-commit` never runs. |
| `submodules` | A declared submodule is empty, so the build fails. |
| `python` | `py -3` does not run, so every `.claude/hooks/*.py` hook is a silent no-op. |
| `claude-hooks` | `.claude/settings.json` is absent or does not parse, or a hook script that it names is absent or does not compile. |
| `vcpkg` | Nobody ran `vcpkg integrate install`, so `build.ps1` refuses to build. |

`stale-local-hooks` is a WARN. `core.hooksPath` shadows the leftover files in
`.git/hooks/`, so those files cannot run. But they give wrong information to the
reader. Name this warning in one line. Do not dramatize it.

### Report the result

If every check is OK, print one short line. For example: "Environment: healthy -
the git hooks and the .claude hooks are both active." Do not print the table.
Name each WARN line in one line.

If one check or more failed, give the diagnosis first:

1. Give the consequence of each failure, not the name of the key. Read the
   consequence from the table above. Read `.githooks/pre-commit` for the rules
   that this hook enforces.
2. Print the failing lines.
3. Give the fix. `setup.cmd` corrects `git-hooks` and `submodules`. `python` and
   `vcpkg` are outside the repo. For `python`, install the Python launcher. For
   `vcpkg`, run `vcpkg integrate install` from
   `<VS install>\VC\vcpkg\vcpkg.exe`. `setup.cmd` reports these two conditions,
   but it cannot correct them.
4. If `setup.cmd` corrects the failures, offer to run `setup.cmd`. Ask one time
   in plain chat. If the user agrees, run it.

CAUTION: Do not run `setup.cmd` without agreement from the user. It writes the
git configuration and it can initialize submodules.

## Scope and rules

- Print the project skills only. List the subdirectories of `.claude/skills/` in
  the repo root. Do not list the built-in CLI commands (`/help`, `/clear`). Do
  not list the global skills or the user skills that are outside this directory.
- Read the directory in this run. Never write a fixed list of skills into this
  file. Skills change over time, and a fixed list becomes wrong.
- Write one line for each skill. If a description is a paragraph, give its
  purpose in a few words. Keep the column short.
- If a subdirectory has no `SKILL.md`, or the frontmatter does not parse, print
  the name of the directory with `(no description)`. Do not omit the directory.
- Ask no questions, except the offer in Step 2 and the offer in Step 3.
