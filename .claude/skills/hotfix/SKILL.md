---
name: hotfix
description: Release a patch of a CERF version that is already released, through the release-<major>.<minor> branch of that version (only user triggered, no agent self-invocation).
---

# hotfix - release a patch of a released CERF version

The user invoked `/hotfix`. A patch fixes a defect of a released version, and the same defect also occurs in the development tree. So the fix goes into the development tree first. Then you port the fix to the release branch of that version, and the commit there starts the release in CI.

Only the user triggers this skill by typing `/hotfix`. An agent never invokes it on its own initiative. A fix of a defect that a release also has does not give you permission to release a patch.

## Names

- The patched version `<major>.<minor>` is the released version that gets the patch. The user names it. If the user does not, it is the version of the latest release: `gh release view --json tagName -q .tagName`. A release tag has the form `<major>.<minor>.<patch>.<build>`.
- The release commit is the commit that CI released as `<major>.<minor>`. The tag `<major>.<minor>.0.<build>` points to it.
- The release branch `release-<major>.<minor>` starts at the release commit. It holds the patches of that version and nothing else.
- The worktree `tmp/release-<major>.<minor>` holds the release branch. Do not switch the branch of the main tree, because other agents and the user work in that tree at the same time. A branch switch changes their files.

## Git operations that `/hotfix` allows

`/hotfix` is the request of the user for these git operations, and for no others:

- Fetch the tags and branches of `origin`, in the root and in each library that the fix touches.
- Add the worktree, and create the release branch in the root and in each library that the fix touches.
- Remove a worktree record whose folder is gone (`git worktree prune`).
- Commit on the release branches with `/commit`.

Do not push, because the user pushes. Do not commit on the development branch unless the user asks for it.

## Procedure

### 1. Fix the development tree

Write the fix in the development tree and test it there. The fix is done when a run shows that the defect is gone. Step 4 ports this fix, not a new one. Then invoke `/changelog` and follow its § Patch line in the development tree.

### 2. Open the release branch

1. Run `git fetch origin --tags`.
2. Run `git worktree list`. If a worktree already holds `release-<major>.<minor>`, use that worktree. If the list marks it `prunable`, its folder is gone. Run `git worktree prune`, then continue with the next item.
3. If the branch exists, add a worktree for it:
   - The branch is local: `git worktree add tmp/release-<major>.<minor> release-<major>.<minor>`
   - The branch is only on `origin`: `git worktree add -b release-<major>.<minor> tmp/release-<major>.<minor> origin/release-<major>.<minor>`
4. If the branch does not exist, create it at the release commit: `git worktree add -b release-<major>.<minor> tmp/release-<major>.<minor> <release commit>`.

A local branch can hold patch commits that the user has not pushed yet. Keep them, and put the new patch on top of them.

### 3. Make sure that CI releases from the branch

Read `.github/workflows/build.yml` in the worktree. CI builds a push to the branch only when `on.push.branches` lists `release-*` or the name of the branch. If it lists neither, the release commit is older than the support for release branches in CI. Port that support from the development branch before the fix, in a commit of its own. To find it, run `git log --oneline -S"release-*" -- .github/workflows/build.yml` on the development branch. Port only its parts for `build.yml` and for the release tools that `build.yml` runs.

The support also keeps an older version from replacing the latest release. Without it, a patch of an older version becomes the version that the updater and the installers download.

### 4. Port the fix

- In the root repository: if the user committed the fix alone on the development branch, run `git -C tmp/release-<major>.<minor> cherry-pick -x <commit>`. If not, write the diff of the fix paths to a file under `tmp/` with `git diff HEAD -- <paths>`. Then apply it in the worktree with `git -C tmp/release-<major>.<minor> apply --3way <file>`.
- In a library: the root diff shows only the new library pointer. Run `git -C tmp/release-<major>.<minor> submodule update --init <library>`. In that library, use its branch `release-<major>.<minor>` when `origin` has it. If not, create the branch at the commit that the worktree pins. Port the library part of the fix there.
- In the changelog: do not port `docs/changelog.yml` with the diff, because the development changelog has entries that the branch does not have. Write the same patch line into the entry of the patched version on the branch.

If the fix does not apply as it is, change it so that it fits the old code. Then build and test the worktree before the commit, as in step 1. If the fix applied with no change, the CI build is enough. CI builds every platform before it releases, and a failed build releases nothing.

### 5. Raise the patch number on the branch

Run `python tmp/release-<major>.<minor>/tools/bump_version.py patch`. If the branch is older than that script, add 1 to `CERF_VERSION_PATCH` in `tmp/release-<major>.<minor>/cerf-qt/version.h` by hand. The new number is the `N` of the patch line. If it is not, stop and tell the user.

### 6. Commit on the branch

Invoke `/commit` for the worktree. The commit has the port of the fix, the patch line and `cerf-qt/version.h`. Its title ends with `[release cerf]`, because `/hotfix` is the request of the user for that release.

### 7. Hand over

Tell the user which branches to push, in this order:

1. The branch `release-<major>.<minor>` of each library that got a commit.
2. The branch `release-<major>.<minor>` of the root.

The push of the root branch starts the release. Also tell the user that the development tree still has the fix and the patch line, for the normal commit of the user. The worktree stays in `tmp/release-<major>.<minor>` for the next patch of that version.
