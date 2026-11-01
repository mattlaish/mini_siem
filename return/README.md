# Recovered Dashboard return artifacts

`mini-siem-return-package.zip` and `mini-siem/` are the recovered **October 22,
2026 historical delivery**, restored byte-for-byte from the owner-supplied ZIP.
They are not a new package of the October 28 active application.

Archive SHA-256:
`b54d5041d30ba646b188a7a917d502aa6f674b4e25540007d1d456c84ae25c34`

The active application remains `C:/Users/mattlai/Projects/mini_siem`. Its recovered
connector, schemas and token tool have been selectively integrated with the newer
browser authentication, outbound protections and workflow improvements. Do not
deploy the historical `mini-siem/source/` snapshot over the active application.

The historical identity, fixtures, logs, catalog statuses and source hashes are
kept unchanged. They describe that delivery only. Its validator normally compares
identity against the surrounding repository; this updated repository deliberately
differs. Historical revalidation must compare against the included historical
`source/`, not relabel its identity as the current application. Do not edit its
old test logs or mark live transport qualification PASS.

The seven `mini-siem/tools/*.py` files are restored reproducibility tools. Preparing
a new source payload would replace the historical mirror and invalidate its old
checksums/identity; do that only as a separate, explicitly versioned delivery with
fresh fixtures, identity, acceptance evidence and ZIP. No new ZIP was generated
by this recovery. The Dashboard consumer itself was not changed or registered.

See `../RECOVERY_2026-10-28.md` for current-source validation, deployment needs and
the remaining documented R3/G1 operational gaps.
