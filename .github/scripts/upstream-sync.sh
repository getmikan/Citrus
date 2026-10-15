#!/usr/bin/env bash
# Merges MetaCubeX/mihomo Alpha into dev on a branch and opens a PR for it,
# or opens an issue when the merge conflicts. Run by
# .github/workflows/upstream-sync.yml; see the header there.
#
# Environment:
#   BASE_BRANCH      branch the sync targets (default: dev)
#   UPSTREAM_URL     upstream repository (default: https://github.com/MetaCubeX/mihomo)
#   UPSTREAM_BRANCH  upstream branch (default: Alpha)
#   ORIGIN_REMOTE    remote of this repository (default: origin)
#   UPSTREAM_REMOTE  remote name for upstream, added if missing (default: upstream)
#   DRY_RUN=1        do everything locally, but do not push and do not call gh
#   GH_TOKEN         token for gh (not needed with DRY_RUN=1)
set -euo pipefail
export LC_ALL=C

BASE_BRANCH="${BASE_BRANCH:-dev}"
UPSTREAM_URL="${UPSTREAM_URL:-https://github.com/MetaCubeX/mihomo}"
UPSTREAM_BRANCH="${UPSTREAM_BRANCH:-Alpha}"
ORIGIN_REMOTE="${ORIGIN_REMOTE:-origin}"
UPSTREAM_REMOTE="${UPSTREAM_REMOTE:-upstream}"
DRY_RUN="${DRY_RUN:-0}"
UPSTREAM_WEB="${UPSTREAM_URL%.git}"
MAX_LISTED=200

DATE="$(date -u +%Y%m%d)"
SYNC_BRANCH="chore/upstream-sync-${DATE}"
ISSUE_PREFIX="Upstream sync conflicts"
ISSUE_TITLE="${ISSUE_PREFIX} $(date -u +%Y-%m-%d)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

note() { echo "upstream-sync: $*" >&2; }

run_gh() {
	if [ "$DRY_RUN" = "1" ]; then
		note "DRY_RUN: gh $*"
		return 0
	fi
	gh "$@"
}

# --- fetch ---------------------------------------------------------------
if ! git remote get-url "$UPSTREAM_REMOTE" >/dev/null 2>&1; then
	git remote add "$UPSTREAM_REMOTE" "$UPSTREAM_URL"
fi
git fetch --no-tags "$ORIGIN_REMOTE" "+refs/heads/${BASE_BRANCH}:refs/remotes/${ORIGIN_REMOTE}/${BASE_BRANCH}"
git fetch --no-tags "$UPSTREAM_REMOTE" "+refs/heads/${UPSTREAM_BRANCH}:refs/remotes/${UPSTREAM_REMOTE}/${UPSTREAM_BRANCH}"

BASE_REF="${ORIGIN_REMOTE}/${BASE_BRANCH}"
UP_REF="${UPSTREAM_REMOTE}/${UPSTREAM_BRANCH}"
UP_SHA="$(git rev-parse "$UP_REF")"
UP_SHORT="$(git rev-parse --short=8 "$UP_REF")"

if git merge-base --is-ancestor "$UP_REF" "$BASE_REF"; then
	note "${UP_REF} (${UP_SHORT}) is already in ${BASE_BRANCH}; nothing to do."
	if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
		echo "Upstream \`${UPSTREAM_BRANCH}\` (${UP_SHORT}) is already in \`${BASE_BRANCH}\`. Nothing to sync." >>"$GITHUB_STEP_SUMMARY"
	fi
	exit 0
fi

MB="$(git merge-base "$UP_REF" "$BASE_REF")"
MB_SHORT="$(git rev-parse --short=8 "$MB")"
COUNT="$(git rev-list --count "${MB}..${UP_REF}")"
COMPARE_URL="${UPSTREAM_WEB}/compare/${MB}...${UP_SHA}"
note "${COUNT} upstream commits to merge: ${MB_SHORT}..${UP_SHORT}"

# A sync branch that already has this upstream commit is waiting for review:
# do not open another one. Earlier open ones are listed in the new PR.
OLD_SYNC=()
while read -r _ ref; do
	b="${ref#refs/heads/}"
	git fetch -q --no-tags "$ORIGIN_REMOTE" "+${ref}:refs/remotes/${ORIGIN_REMOTE}/${b}"
	if git merge-base --is-ancestor "$UP_REF" "${ORIGIN_REMOTE}/${b}"; then
		note "${b} already contains ${UP_SHORT}; nothing to do."
		exit 0
	fi
	# Today's branch is rewritten below; one already merged into the base
	# branch is just left over.
	[ "$b" = "$SYNC_BRANCH" ] && continue
	git merge-base --is-ancestor "${ORIGIN_REMOTE}/${b}" "$BASE_REF" || OLD_SYNC+=("$b")
done < <(git ls-remote "$ORIGIN_REMOTE" 'refs/heads/chore/upstream-sync-*')

# Upstream commit list: plain text for the merge commit, Markdown for PR/issue.
git log --no-merges --format='%h %s' "${MB}..${UP_REF}" >"$WORK/shortlog.txt"
{
	git log --no-merges --format="- [\`%h\`](${UPSTREAM_WEB}/commit/%H) %s (%an, %as)" "${MB}..${UP_REF}" | head -n "$MAX_LISTED"
	NOMERGE="$(wc -l <"$WORK/shortlog.txt" | tr -d ' ')"
	if [ "$NOMERGE" -gt "$MAX_LISTED" ]; then
		echo "- ... and $((NOMERGE - MAX_LISTED)) more, see the compare link."
	fi
} >"$WORK/commits.md"

# --- merge ---------------------------------------------------------------
git config user.name >/dev/null 2>&1 || git config user.name "github-actions[bot]"
git config user.email >/dev/null 2>&1 || git config user.email "41898282+github-actions[bot]@users.noreply.github.com"

git checkout -q -B "$SYNC_BRANCH" "$BASE_REF"

{
	echo "Merge upstream ${UPSTREAM_BRANCH} ${UP_SHORT} into ${BASE_BRANCH}"
	echo
	echo "Upstream range ${MB_SHORT}..${UP_SHORT} (${COUNT} commits):"
	echo
	cat "$WORK/shortlog.txt"
} >"$WORK/merge-msg.txt"

if ! git merge --no-ff --no-edit -F "$WORK/merge-msg.txt" "$UP_REF" >"$WORK/merge.log" 2>&1; then
	cat "$WORK/merge.log" >&2
	git diff --name-only --diff-filter=U >"$WORK/conflicts.txt" || true
	git merge --abort || git reset -q --hard "$BASE_REF"
	note "merge conflicts in $(wc -l <"$WORK/conflicts.txt" | tr -d ' ') files; opening an issue."

	{
		echo "The weekly upstream sync could not merge \`${UPSTREAM_BRANCH}\` of [MetaCubeX/mihomo](${UPSTREAM_WEB}) into \`${BASE_BRANCH}\`: the merge conflicts. Nothing was pushed."
		echo
		echo "- Upstream range: \`${MB_SHORT}..${UP_SHORT}\` (${COUNT} commits), [compare](${COMPARE_URL})"
		echo "- Base: \`${BASE_BRANCH}\` at \`$(git rev-parse --short=8 "$BASE_REF")\`"
		if [ -n "${GITHUB_RUN_ID:-}" ]; then
			echo "- Run: ${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}"
		fi
		echo
		echo "### Conflicting files"
		echo
		sed 's/^/- `/; s/$/`/' "$WORK/conflicts.txt"
		echo
		echo "### Resolve by hand"
		echo
		echo '```sh'
		echo "git remote add upstream ${UPSTREAM_URL}   # once"
		echo "git fetch origin ${BASE_BRANCH}"
		echo "git fetch upstream ${UPSTREAM_BRANCH}"
		echo "git switch -c ${SYNC_BRANCH} origin/${BASE_BRANCH}"
		echo "git merge --no-ff upstream/${UPSTREAM_BRANCH} -m \"Merge upstream ${UPSTREAM_BRANCH} ${UP_SHORT} into ${BASE_BRANCH}\""
		echo "# resolve, then: go build ./... && go mod tidy && (cd test && go mod tidy)"
		echo "git push -u origin ${SYNC_BRANCH}   # and open a PR to ${BASE_BRANCH}"
		echo '```'
		echo
		echo "Keep the Citrus side: removed protocols stay removed (SSR, Hysteria v1, TUIC v4, shadowstream, v2ray-plugin), the \`replace\` directives in \`go.mod\`, the branding in \`constant/\`, and the security, REALITY and xhttp changes."
		echo
		echo "### Upstream commits"
		echo
		cat "$WORK/commits.md"
	} >"$WORK/issue.md"

	if [ "$DRY_RUN" = "1" ]; then
		note "DRY_RUN: would open or update issue \"${ISSUE_TITLE}\":"
		cat "$WORK/issue.md"
		exit 0
	fi
	# One open conflict issue at a time: update the existing one if there is one.
	EXISTING="$(gh issue list --state open --search "\"${ISSUE_PREFIX}\" in:title" --json number,title \
		--jq "map(select(.title | startswith(\"${ISSUE_PREFIX}\"))) | .[0].number // empty")"
	if [ -n "$EXISTING" ]; then
		gh issue edit "$EXISTING" --title "$ISSUE_TITLE" --body-file "$WORK/issue.md"
		note "updated issue #${EXISTING}"
	else
		gh issue create --title "$ISSUE_TITLE" --body-file "$WORK/issue.md"
	fi
	exit 0
fi
cat "$WORK/merge.log" >&2

# --- checks --------------------------------------------------------------
WARNINGS="$WORK/warnings.md"
: >"$WARNINGS"

for dir in . test; do
	if ! (cd "$dir" && go mod tidy) >"$WORK/tidy.log" 2>&1; then
		cat "$WORK/tidy.log" >&2
		echo "- \`go mod tidy\` fails in \`${dir}\`: \`$(head -n 1 "$WORK/tidy.log")\`" >>"$WARNINGS"
	fi
done
if ! git diff --quiet -- go.mod go.sum test/go.mod test/go.sum; then
	git add go.mod go.sum test/go.mod test/go.sum
	git commit -q -m "chore(deps): go mod tidy after the upstream sync"
	echo "- \`go mod tidy\` changed the module files; that is committed separately." >>"$WARNINGS"
fi

BUILD_OK=1
if ! go build ./... >"$WORK/build.log" 2>&1; then
	BUILD_OK=0
	cat "$WORK/build.log" >&2
	{
		echo "- **\`go build ./...\` fails after the merge**, the PR is a draft until it is fixed:"
		echo
		echo '  ```'
		head -n 40 "$WORK/build.log" | sed 's/^/  /'
		echo '  ```'
	} >>"$WARNINGS"
fi

# Citrus replace directives must survive the merge.
grep -E '^replace|=>' <(git show "${BASE_REF}:go.mod") | sort >"$WORK/replace.base" || true
grep -E '^replace|=>' go.mod | sort >"$WORK/replace.new" || true
if ! diff -q "$WORK/replace.base" "$WORK/replace.new" >/dev/null; then
	{
		echo "- The \`replace\` directives in \`go.mod\` differ from \`${BASE_BRANCH}\`:"
		echo
		echo '  ```diff'
		diff -u "$WORK/replace.base" "$WORK/replace.new" | tail -n +3 | sed 's/^/  /' || true
		echo '  ```'
	} >>"$WARNINGS"
fi

# Branding.
grep -q 'const Name = "citrus"' constant/path.go ||
	echo "- \`constant/path.go\` no longer has \`Name = \"citrus\"\`." >>"$WARNINGS"
grep -q 'MihomoName = "citrus"' constant/version.go ||
	echo "- \`constant/version.go\` no longer has \`MihomoName = \"citrus\"\`." >>"$WARNINGS"

# Files Citrus deleted (present at the merge base, gone from the base branch)
# must not come back, and upstream must not add new files next to them.
git diff --name-only --diff-filter=D "$MB" "$BASE_REF" | sort >"$WORK/removed.txt"
git diff --name-only --diff-filter=A "$BASE_REF" HEAD | sort >"$WORK/added.txt"
comm -12 "$WORK/removed.txt" "$WORK/added.txt" >"$WORK/revived.txt"
sed 's|/[^/]*$||' "$WORK/removed.txt" | sort -u >"$WORK/removed-dirs.txt"
while IFS= read -r f; do
	d="${f%/*}"
	[ "$d" = "$f" ] && continue
	if grep -qxF "$d" "$WORK/removed-dirs.txt" && ! git cat-file -e "${BASE_REF}:${d}" 2>/dev/null; then
		echo "$f"
	fi
done <"$WORK/added.txt" >>"$WORK/revived.txt"
sort -u -o "$WORK/revived.txt" "$WORK/revived.txt"
if [ -s "$WORK/revived.txt" ]; then
	{
		echo "- Upstream brings back files of code Citrus removed. Delete them in this PR if they belong to a removed protocol:"
		sed 's/^/  - `/; s/$/`/' "$WORK/revived.txt"
	} >>"$WARNINGS"
fi

# --- PR body -------------------------------------------------------------
{
	echo "Merges \`${UPSTREAM_BRANCH}\` of [MetaCubeX/mihomo](${UPSTREAM_WEB}) into \`${BASE_BRANCH}\`."
	echo
	echo "- Upstream range: \`${MB_SHORT}..${UP_SHORT}\` (${COUNT} commits), [compare](${COMPARE_URL})"
	if [ -n "${GITHUB_RUN_ID:-}" ]; then
		echo "- Opened by ${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}"
	fi
	echo "- \`go build ./...\`: $([ "$BUILD_OK" = 1 ] && echo ok || echo '**failed**')"
	echo
	if [ -s "$WARNINGS" ]; then
		echo "### Needs attention"
		echo
		cat "$WARNINGS"
		echo
	fi
	if [ "${#OLD_SYNC[@]}" -gt 0 ]; then
		echo "Earlier sync branches still exist (\`${OLD_SYNC[*]}\`); this one has everything they merged from upstream. Close their PRs once this lands, after moving over any fixes pushed to them."
		echo
	fi
	echo "### Before merging"
	echo
	echo "- [ ] CI ran. A PR opened with \`GITHUB_TOKEN\` does not start other workflows: push an empty commit to this branch, close and reopen the PR, or run Test by hand."
	echo "- [ ] \`go.mod\` keeps the Citrus \`replace\` directives and the module path \`github.com/metacubex/mihomo\`."
	echo "- [ ] Branding is intact (\`constant/path.go\`, \`constant/version.go\`)."
	echo "- [ ] Removed protocols stay removed (SSR, Hysteria v1, TUIC v4, shadowstream, v2ray-plugin) and upstream changes to them are dropped."
	echo "- [ ] Upstream changes do not undo Citrus security fixes, PQ REALITY or xhttp."
	echo "- [ ] Merge with a merge commit, not squash, so the next sync starts from here."
	echo
	echo "### Upstream commits"
	echo
	cat "$WORK/commits.md"
} >"$WORK/pr.md"

PR_TITLE="chore: sync upstream ${UPSTREAM_BRANCH} ${UP_SHORT}"

if [ "$DRY_RUN" = "1" ]; then
	note "DRY_RUN: would push ${SYNC_BRANCH} and open \"${PR_TITLE}\":"
	cat "$WORK/pr.md"
	exit 0
fi

# --- push and PR ---------------------------------------------------------
git push --force "$ORIGIN_REMOTE" "HEAD:refs/heads/${SYNC_BRANCH}"

PR_NUMBER="$(gh pr list --state open --head "$SYNC_BRANCH" --json number --jq '.[0].number // empty')"
if [ -n "$PR_NUMBER" ]; then
	gh pr edit "$PR_NUMBER" --title "$PR_TITLE" --body-file "$WORK/pr.md"
	note "updated PR #${PR_NUMBER}"
else
	DRAFT=()
	[ "$BUILD_OK" = 1 ] || DRAFT=(--draft)
	gh pr create --base "$BASE_BRANCH" --head "$SYNC_BRANCH" --title "$PR_TITLE" --body-file "$WORK/pr.md" "${DRAFT[@]}"
	PR_NUMBER="$(gh pr list --state open --head "$SYNC_BRANCH" --json number --jq '.[0].number // empty')"
fi

# A conflict issue from an earlier run is resolved by this PR.
gh issue list --state open --search "\"${ISSUE_PREFIX}\" in:title" --json number,title \
	--jq ".[] | select(.title | startswith(\"${ISSUE_PREFIX}\")) | .number" |
	while read -r num; do
		gh issue close "$num" --comment "Upstream merges cleanly now, see #${PR_NUMBER}."
	done
