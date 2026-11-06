# Replication foundation

Injected native library; it does not start an ambient server. `Open` requires an
explicit transport, three-voter initial bootstrap, admission gate, 32-byte storage
key and bounded timeout. Existing-state bootstrap is refused. State-directory
ownership uses a Linux advisory lock. Production peer authentication/encryption
must be provided by the transport adapter; no insecure TCP default is supplied.

`Apply` performs the trusted leader admission gate, then atomically replicates
record mutation and receipt. The FSM never consults network, wall time or external
authority. It checks replicated monotonic actor/session fences deterministically.
`Fence` is a trusted authority-only port, not an authenticated public endpoint.
Receipts retain definitive revision/fence refusals; changed command digests never
replace the original receipt. Admission proof bytes are excluded from digest;
remaining command fields and normalized JSON payload bind replay identity.

`Read` and `Receipt` require a leader barrier. Timeout is `ErrUnknown`, not a
recorded failure: resolve the original stable command ID by a leader receipt read.
Never retry automatically with another command ID. Results do not contain payloads.

LogStore, StableStore and snapshots use AES-256-GCM plus restrictive modes, atomic
rename and file/directory fsync. Content remains opaque: storage keys are NOT client
content keys. Whole-state encrypted rewrites and retained snapshots are deliberately
simple foundation adapters; bounded production storage/compaction and authenticated
transport are outstanding integration/efficiency work.

Status: implemented, not wired to runtime, not verified. Three-voter replay,
fencing, minority refusal and snapshot/restart fixture tests exist. No tests or
builds were run during this development phase per user instruction. Final QA must
verify Raft races, timeout ambiguity, persistence fault behavior and all integration.
