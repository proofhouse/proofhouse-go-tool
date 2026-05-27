#!/usr/bin/env bash
# Strip git's commit-message helper text and any verbose-diff
# scissors block from the COMMIT_EDITMSG buffer before passing it to
# vale. The commit-msg hook fires before git's own cleanup pass, so
# the buffer still contains:
#
#   - Lines beginning with the comment character (`#` by default).
#     git adds these on `git commit --amend` or `git commit` without
#     `-F`/`-m` to remind the author what changed and what gets
#     ignored. The text reads like English prose, so vale flags it
#     for headings, "will", passive voice, and so on.
#
#   - Everything from the scissors line
#     `# ------------------------ >8 ------------------------` to
#     EOF when `commit.verbose=true` is set, which is the project
#     default for any reviewer who wants the diff visible while
#     editing. The diff itself contains `--git` (em-dash trigger)
#     and other tokens vale would otherwise treat as prose.
#
# The hook receives the path to `.git/COMMIT_EDITMSG` as `$1`. The
# strip pipeline writes a cleaned copy to a temp file, runs vale
# with `--ext=.md` (the same flag the project's commit-msg-stage
# scope expects), and propagates vale's exit code through `exec`.
set -euo pipefail

msg_file=$1
# vale's file processor selects rules by file extension. mktemp's
# default template has no suffix, so vale falls through to the
# default scope and skips the file entirely. The `.md` suffix lands
# the temp file in the `[*.md]` scope from `.vale.ini`, which is the
# scope this hook needs to enforce on the commit message.
tmp=$(mktemp --suffix=.md 2>/dev/null || mktemp -t vale-commit-msg.XXXXXX.md)
trap 'rm -f "$tmp"' EXIT

# sed cuts from the scissors marker through EOF. The pattern matches
# the scissors text loosely (any number of dashes, optional spacing
# around the `>8`) and accepts the configurable `core.commentChar`
# via the `[#;]` character class. `git stripspace --strip-comments`
# then drops the remaining comment lines using git's own
# commentChar rules.
sed -E '/^[#;] *-+ *>8 *-+ *$/,$d' "$msg_file" \
  | git stripspace --strip-comments \
  > "$tmp"

exec vale --ext=.md "$tmp"
