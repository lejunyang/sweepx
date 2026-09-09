# Git-ignored project artifacts

Status: design recommendation backed by a local read-only measurement on 2026-09-10. No deletion
authority is proposed here.

## Product question

Git ignore rules are a useful signal for locating disk growth that a normal source-tree view hides.
They are not a statement that data is disposable. A developer may ignore rebuildable outputs such
as Cargo `target/` or Node `node_modules/`, but may also ignore credentials, local configuration,
databases, models, test evidence, downloaded toolchains, or an entire workspace. SweepX therefore
must keep two decisions separate:

1. **Discovery:** is this path currently ignored by the repository's effective Git rules?
2. **Classification:** is there independent evidence that this exact object is rebuildable or safe
   to review as junk?

Ignore membership can strengthen discovery and ranking. It cannot, by itself, lower risk or grant
Trash, plan, approval, or execution authority.

## Local corpus measurement

The requested root `/home/lejunyang/Projects/lejunyang` resolves to
`/data00/home/lejunyang/Projects/lejunyang`. Ten top-level Git worktrees were enumerated with
`git ls-files --others --ignored --exclude-standard --directory -z`; byte totals were then measured
independently with `du --block-size=1`. Nested repositories were measured separately and were not
added to the top-level total. This is one host on 2026-09-10, not a general benchmark.

| Observation | Count | Allocated bytes | GiB |
|---|---:|---:|---:|
| Top-level ignored entries | 52 | 135,808,147,456 | 126.48 |
| Existing SweepX known-name classes | 36 directories | 123,239,514,112 | 114.78 |
| Other ignored entries | 12 directories + 4 files | 12,568,633,344 | 11.71 |

The largest entries were:

| Repository/path | Allocated bytes | GiB | Interpretation |
|---|---:|---:|---|
| `sweepx/target` | 65,539,059,712 | 61.04 | Known Cargo build output |
| `one-sdk/target` | 55,745,253,376 | 51.92 | Known Cargo build output |
| `dev-flow/artifacts` | 8,131,059,712 | 7.57 | Large ignored data, but the generic name is not enough to call it disposable |
| `ogen/workspace` | 4,341,620,736 | 4.04 | Hard blocker: it contains the nested `tools/ComfyUI/.git` repository and tool/runtime assets |
| `agent-knowledge/node_modules` | 851,902,464 | 0.79 | Known installed dependency tree |
| `learn-english/node_modules` | 265,940,992 | 0.25 | Known installed dependency tree |

During the same review, the current name-and-marker `sweepx junk` pass reported 20 candidates
totaling 132,218,947,701 logical bytes. These values are a dated observation of an active build
tree, not an invariant: running the project's own verification grew `sweepx/target`, so the final
independent allocated-byte measurement above is intentionally larger. Git-aware evidence would add
explanation and find generic large ignored paths, but the `ogen/workspace` counterexample proves
that it must not turn all ignored bytes into reclaimable bytes. A present ignored `.env.local` was
only 224 bytes; size is useful for ranking, but neither small nor ignored means unimportant.

## Recommended first vertical slice

Add report-only Git evidence to `sweepx junk ROOT` while preserving the existing scanner as the
filesystem authority. Use the system `git` executable initially: it already implements repository
discovery, nested `.gitignore` precedence, `.git/info/exclude`, global excludes, negation, escaped
names, and platform matching semantics. Reimplementing those rules in the first slice would create a
second Git with subtly different answers. The invocation must be non-interactive and bounded, with
NUL-delimited input/output and fixed arguments; no shell is involved.

Suggested flow:

1. Discover repository roots from scanned `.git` directories or files, with explicit caps on
   repositories, queried paths, input/output bytes, wall time, and child processes.
2. Feed eligible scanned paths relative to each repository to `git check-ignore --stdin -z -v`; do
   not use `--no-index`, because a tracked path must remain distinguishable from an ignored path.
3. Join results back to scanner entry IDs/native locators. Display paths are never authority. Store
   only a bounded source kind, rule line/pattern, and repository-relative name in report output; do
   not persist global-exclude paths or environment values by default.
4. Apply hard blockers before ranking: nested `.git`, gitfile/submodule/worktree boundary, any
   tracked descendant, symlink/reparse/mount boundary, incomplete aggregate, Git timeout/error, or
   an arbitrary ignored file.
5. Classify rather than guess:

   - `known_generated_ignored`: an existing evidence-backed rule such as `rust.target`,
     `node.modules`, Python caches, or selected build outputs also matches Git ignore evidence. This
     is a high-confidence report-only candidate.
   - `large_ignored_review`: an otherwise unknown ignored directory above a configurable reporting
     threshold. It is ranked for human inspection, remains R3/report-only, and carries blockers.
   - `ignored_local_state`: ignored files and sensitive/config/data-shaped names such as `.env*`,
     credentials, keys, databases, models, uploads, and workspace roots. These are never junk by
     ignore evidence alone and should be omitted by default or shown only in an explicit diagnostic
     view.

The output should add stable fields rather than overloading `ruleId`: for example
`git.status=ignored`, `git.repositoryId`, `git.sourceKind`, `git.pattern`,
`classification=known_generated_ignored|large_ignored_review`, `confidence`, and `blockers[]`.
Existing field names and enum values remain unchanged.

## Tests and acceptance boundary

The first slice is complete when fixtures cover nested `.gitignore`, negation, global excludes,
non-UTF-8 names on Unix, spaces/newlines through NUL framing, tracked-but-pattern-matching files,
gitfile worktrees/submodules, nested repositories, time/output caps, missing Git, concurrent file
changes, and incomplete scanner evidence. Cross-platform tests must assert the host's Git semantics
rather than hardcode case sensitivity.

No candidate discovered only by Git ignore status may be passed to `trash`, a plan builder, or an
executor. A later slice can use independently qualified cleaner evidence and live identity
revalidation to offer an explicit Trash workflow.
