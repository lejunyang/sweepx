# Git-ignored project artifacts

Status: the first report-only enrichment slice is implemented; broader ignored-directory discovery
remains a design recommendation. The local evidence is a read-only measurement from 2026-09-10.
No deletion authority is proposed here.

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

## Delivered first vertical slice

`sweepx junk ROOT` now adds report-only Git evidence to candidates already selected by the existing
project rules while preserving the scanner as the filesystem authority. It invokes the system
`git` executable with fixed arguments and native path arguments, without a shell, because Git already
implements nested `.gitignore` precedence, `.git/info/exclude`, global excludes, negation, escaped
names, and platform matching semantics. Queries are non-interactive and bounded to 256 subprocesses
and a five-second total deadline.

The delivered flow:

1. Discover repository roots only from `.git` directory/file entries in the retained scan and only
   when the repository row itself has complete, non-truncated detail coverage.
2. Rebuild query paths from validated native locators, then compare the live repository and
   candidate identities with the scan capture before asking Git; display paths are never
   classification authority.
3. Reject gitfile/worktree boundaries, nested repositories, incomplete/details-lost aggregates, and
   tracked descendants before checking ignore status. A failed or timed-out Git query leaves the
   candidate at its original confidence and adds a blocker.
4. A known rule candidate that is untracked and ignored is labeled
   `known_generated_ignored` / `high`. Other known candidates remain `known_generated` / `medium`.
5. JSON adds stable `git`, `classification`, `confidence`, and `blockers` fields. The human report
   makes a successful Git promotion or blocker visible. No path gains mutation authority.

## Recommended next slice

Broader discovery should classify rather than guess:

   - `large_ignored_review`: an otherwise unknown ignored directory above a configurable reporting
     threshold. It is ranked for human inspection, remains R3/report-only, and carries blockers.
   - `ignored_local_state`: ignored files and sensitive/config/data-shaped names such as `.env*`,
     credentials, keys, databases, models, uploads, and workspace roots. These are never junk by
     ignore evidence alone and should be omitted by default or shown only in an explicit diagnostic
     view.

Before enabling `large_ignored_review`, add a dedicated bounded repository-boundary enumeration that
cannot lose nested `.git` evidence when the main scan reaches its detail-retention cap. It should
also batch Git queries with NUL-delimited input/output and record bounded ignore-source metadata.
The existing per-candidate process budget is adequate for the narrow enrichment slice, not for
arbitrary ignored-path discovery.

## Tests and acceptance boundary

The first slice covers normal ignored candidates, tracked descendants, nested repositories, and
the fallback when no repository is present. Before broad discovery, fixtures must additionally cover
nested `.gitignore`, negation, global excludes, non-UTF-8 names on Unix, spaces/newlines through
batched NUL framing, gitfile worktrees/submodules, time/output caps, missing Git, concurrent file
changes, and incomplete scanner evidence. Cross-platform tests must assert the host's Git semantics
rather than hardcode case sensitivity.

No candidate discovered only by Git ignore status may be passed to `trash`, a plan builder, or an
executor. A later slice can use independently qualified cleaner evidence and live identity
revalidation to offer an explicit Trash workflow.
