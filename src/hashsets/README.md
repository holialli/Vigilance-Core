# Hash sets

Drop hash lists here to enable hash-set matching during a carve:

- `known_bad.txt` — hashes that should raise an alert (malware, contraband)
- `known_good.txt` — hashes to suppress as known-OS/application noise (e.g. NSRL)

Any 32/40/64-character hex token on a line is read as a hash, so plain hash
lists and CSV exports (including NSRL) both work. Lines starting with `#` are
ignored.

Hashing is skipped entirely when neither file exists, because it reads every
candidate file out of the image and dominates carve time.

Override the paths with the `HASHSET_BAD` / `HASHSET_GOOD` environment variables.
