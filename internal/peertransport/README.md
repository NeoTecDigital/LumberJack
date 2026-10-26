# Explicit authenticated Raft transport (S1-T prerequisite)

Public API: `Peer{Address raft.ServerAddress, DNSName string}`;
`Config{LocalID raft.ServerID, ListenAddress string, Peers map[raft.ServerID]Peer,
Certificate tls.Certificate, Roots *x509.CertPool, Timeout time.Duration,
MaxPool int}`; `Open(Config) (*Transport,error)`;
`(*Transport).Raft() raft.Transport`; `(*Transport).Close() error`.
`ErrConfig` and `ErrPeer` are sanitized errors, not certificate/key dumps.

The owner explicitly supplies every peer, including the local ID, its advertised
host:port and unique lowercase nonwildcard DNS SAN identity. Advertised addresses
must have concrete host and nonzero numeric port; listening is separate and may
use a disposable `127.0.0.1:0` port. There is no environment discovery, persistence,
bootstrap, default CA, product route, or ambient cluster startup. `Open` starts
only the explicitly requested listener and Raft NetworkTransport accept loop.
Inject `transport.Raft()` into existing `replication.Config.Transport`. Shutdown
the node and close the transport; both its direct Close and Raft WithClose are
idempotent. Close shuts down listener, pooled, accepted and handshaking tracked
connections. A dial already in progress remains bounded by configured timeout.

Certificates require a matching marshalable private key, a current trusted chain,
both client/server EKUs, exactly one DNS SAN, and no alternative IP/URI/email SANs.
The local SAN must match the local configured identity. Roots, peer map and key/
certificate material are copied at Open; hardware-backed nonexportable keys are
not supported by this API. Caller must not mutate inputs concurrently with Open.
TLS uses version 1.3 only, standard CA/expiry/EKU/hostname verification (no bypass),
mandatory client certificates, and a second configured-identity check. Incoming
clients must be recognized nonlocal peer identities. Outgoing servers must match
the DNS identity of the exact configured destination. Unknown IDs, mismatched
ID/address pairs and self destinations are rejected *before pooled reuse* by the
returned guarded Transport. There is no Raft address-provider fallback.

Timeout must be positive and <=1 minute; MaxPool must be 1..64. Dial plus handshake
shares one timeout budget. Inbound handshakes are serial and deadline-bounded;
failed handshakes never enter the Raft consumer. The pool cap is per destination,
not a global active-connection/rate limit. Raft owns RPC deadlines (including its
snapshot-size scaling), RPC framing and pipelining. This package does not claim
hostile-network DoS resistance or enforce Raft message size limits. Deployment
needs external connection/rate limits and operational controls. Identity policy
and certificate validity are checked at handshake; existing connections do not
perform continuous revocation/expiry checks. Reopen with new policy/certificates
and close old transport to revoke its existing connections. No CRL/OCSP discovery.

## Threat boundary

This authenticates configured peer machines; it is not signed business actor,
resource/scope authorization, admission, or certification of claimed IDs inside
Raft message payloads. Raft assumes trusted, non-Byzantine voters. Caller-provided
membership must agree with this configuration; CA issuance and DNS identity
uniqueness across deployed private keys are operator responsibilities. A trusted
CA can issue another key for an identity; this is CA-based trust, not key pinning.
Native admission, ciphertext/key lifecycle, current authority and generation/
revocation adapters remain separate requirements. Success is neither product
activation nor production-cluster certification. No live cluster is configured.

Disposable ECDSA CA/leaf loopback fixtures cover three configured peers and real
RequestVote RPC, cached-destination ID/address refusal, missing/unknown/untrusted/
expired/wildcard/ambiguous/self client identities, wrong server SAN, plaintext,
stalled-handshake/listener cleanup, configuration rejection and input copying.
Ephemeral port reservation has the ordinary bind race; no production ports/keys.
Tests/builds are intentionally not run during development: coordinator owns the
single stopped-edit phase QA gate, including race/security/efficiency review.
