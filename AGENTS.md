# SweepX contributor guidance

## Product-focused delivery

- Prefer one user-visible vertical slice over many narrow internal milestones.
- During implementation, run focused crate tests. Run broad matrices once at the delivery boundary.
- Do not use sub-agents unless the user explicitly requests delegation.

## Comments and documentation

- Add rustdoc to every new public type, function, trait, enum, and non-obvious field.
- Add short comments around concurrency, unsafe code, filesystem authority, resource bounds,
  cancellation, cache validity, and destructive-operation guards.
- Comments should explain invariants, trade-offs, failure behavior, and why a tempting shortcut is
  unsafe. Do not merely restate the next line of code.
- Keep CLI help, README, and both `site/` language variants aligned with behavior changes.
- Preserve stable machine field names and enum values across locales.

## Filesystem safety

- Display paths are never execution authority. Revalidate native identity immediately before a
  Trash operation.
- Trash failure, denial, cancellation, or ambiguity must never fall back to permanent deletion.
- Preserve explicit incomplete/lower-bound evidence; never render it as exact.
