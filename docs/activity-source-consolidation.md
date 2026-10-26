<!-- Written by Richard Christopher, Copyright 2026 NeoTec, LLC -->
# Activity and workspace native source consolidation

The Activity persistence implementation and the existing workspace engine now
share this maintained source checkout. The common ancestor was `2c97d206d0c82caa1029816f80e62a8d01e8727c`.
The Activity development clone included checkpoints `042dc61` and `f7326f5` plus
its later domain, enrollment, personal-source and Manifest persistence work.
The import inventory in `activity-source-import.jsonl` records the resulting
source bytes. Private stores, credentials and generated binaries were not copied.

The integration retains all 71 workspace-only source files, its dependency lock,
feed/preferences, asset-index and message-operation routes. It adds 169
Activity-only source files and reconciles shared storage/lifetime fields. Neither
an older workspace tree nor the private clone was substituted wholesale.

Consolidation verification: 1,005 Go test cases passed, nine skipped, no failures;
14 tested packages passed and two packages had no tests. Three exposed fixture
defects were corrected without relaxing runtime checks:

- Populate the new optional personal-binding ledger in the exhaustive codec test.
- Recreate/reconnect in-memory transports after a Raft process restart.
- Use an owner-only enrollment fixture directory, matching the existing recovery
  witness requirement (0700 directory, 0600 file), rather than weakening it.

`make activity-shared` builds ABI2 with `-buildvcs=false -ldflags=-buildid=`;
the build ID otherwise includes location-dependent action hashes even when the
compiled content hash matches. The release records source and artifact hashes.
`make ffi` builds the workspace archive. Source commit and artifact hash remain
separate release pins. This integration alone does not unify browser auth, approve
customer migration, or certify deployment/provider readiness.
