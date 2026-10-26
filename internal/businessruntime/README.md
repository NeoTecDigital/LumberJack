# Native business SDK foundation (not production certified)

`Open(Config)` owns a new injected Raft node, replacing its gate with the composed
signed-admission gate. Config requires `Replication`, `Verifier`, `Authority` and
`Now`. It supplies no network transport, default authority, keys or public routes.
**Production business activation remains closed.** A caller-injected transport is
not evidence of authenticated peers: concrete mTLS/authenticated transport policy,
node identity verification and actual connection verification remain integration
work. This SDK alone does not certify a production service.

API:
- `Commit(ctx,Request,proof,payload) (replication.Result,error)`
- `Read(ctx,Access) (replication.Record,bool,error)`
- `Receipt(ctx,Access) (replication.Result,bool,error)`
- `Fence(ctx,FenceRequest) error`; `Close() error`

Request contains adapter-authenticated Actor, requested Scope, ResourceID,
RecordID, CommandID, Operation, ExpectedRevision. These requests never establish
access. `CurrentAuthority.Resolve` must freshly resolve real verified Activation
actor/session/grant and current native ACL/resource expectations into Claims and
ciphertext Context; it MUST NOT echo decoded proof/body fields as authority.
`AuthorizeRead` must validate current actor/session/scope/resource access and, for
Receipt, the actual CommandID-to-resource/actor ownership binding. A granted
resource plus an arbitrary foreign CommandID is not authorization. There is no
unauthenticated raw record API. Actor is trusted adapter input, not browser JSON.

The SDK accepts only native-validated ciphertext envelopes at exact contextual
resource/record/next revision and exact signed byte digest. Content keys never
enter this package. Structural resource/record hashing namespaces storage keys;
original resource/record identifiers remain in trusted context, not invented IDs.
Admission proof is excluded by replication's replay digest. Renewed proofs still
require fresh authority verification and identical bound command fields.

Native generation registry is real Raft control state, not an in-memory mock.
`Fence` first quorum-commits the monotonic actor fence, then prepares and confirms
its stable OperationID/version control record. Gate requires the confirmed version
EXACTLY equal the current native fence. Thus old confirmations refuse immediately
after fencing, even before prepare persists. Control writes also carry the target
actor/version so the deterministic FSM refuses a lower concurrent confirmation.
Unknown states stay blocked; resume the same operation ID. Activation must only
finalize revocation after all affected native authorities acknowledge. Registry
stores control generations only, never accounts or grants.

Reserved control namespace cannot be submitted/read by ordinary product commands.
Read and Receipt current-authorize before leader barriers. The trusted Fence port
requires `AuthorizeFence`, never caller-provided privilege flags.

Not implemented: legacy forest replicated mutation driver, actual Activation
current-authority adapter, transport certification, route wiring, native encrypted
key-envelope ACL model, consented migration. No automatic data migration or
legacy plaintext acceptance. No feature-complete/deployment claim.

Tests written: three-voter composed admission/ciphertext commit, current-read and
receipt denial, exact payload digest mismatch, concurrent fencing and stale proof.
No tests/builds run during development; all behavior is unverified until final QA.
