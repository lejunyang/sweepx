# pnpm v11 record fixture

`pnpm-v11-record.msgpack` contains public package-index metadata for get-tsconfig 4.14.3,
read from the installed pnpm v11 store `package_index` table on 2026-10-07. It contains
manifest fields and file digests/modes/lengths, with no package payload or private project data.
The tests pin independently observed labels, lengths, record decoding and the six unique
content keys represented by seven file paths. Controlled CAS bytes test current native
accounting and selection guards; they do not verify the published package's content hash.
