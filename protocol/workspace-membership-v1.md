# Workspace Membership v1

Status: provisional ADR-005 protocol. The authoritative schema is
`proto/membership/v1/membership.proto`.

This protocol makes one Ed25519 workspace authority the source of device
membership, roles, identity-key bindings, and revocation. It does not encrypt
notification content and does not replace per-recipient Auth HPKE.

## Algorithms and identifiers

- authority signing: Ed25519;
- device identity and proof recipient key: uncompressed 65-byte P-256 point;
- identity key ID: SHA-256 over the exact 65-byte identity public key;
- workspace and device IDs: non-zero 16-byte opaque values;
- digests and certificate IDs: full 32-byte SHA-256 values;
- timestamps: positive Unix milliseconds no greater than `2^63-1`;
- membership and roster epochs: `1..2^63-1`.

The following ASCII domain strings include the terminating zero byte shown as
`\0`:

```text
SyncNotifications-membership-possession-hpke-info-v1\0
SyncNotifications-membership-possession-challenge-digest-v1\0
SyncNotifications-membership-device-certificate-id-v1\0
SyncNotifications-membership-device-certificate-signature-v1\0
SyncNotifications-membership-workspace-roster-digest-v1\0
SyncNotifications-membership-workspace-roster-signature-v1\0
SyncNotifications-membership-authority-transition-digest-v1\0
SyncNotifications-membership-authority-transition-old-signature-v1\0
SyncNotifications-membership-authority-transition-new-signature-v1\0
```

A domain-separated digest is `SHA-256(domain || canonical_bytes)`. An authority
signature is Ed25519 over `domain || canonical_bytes`, not over a hexadecimal or
JSON representation.

## Canonical protobuf

Each top-level message is deterministic protobuf and is limited to 1 MiB.
Receivers MUST reject:

1. parse failure or an empty/oversized message;
2. unknown fields at any nested level;
3. an unsupported `protocol_version`;
4. any semantic constraint violation in this document; or
5. bytes that differ from deterministic re-encoding.

The final rule rejects duplicate fields and alternate field order. Repeated
roles, active certificates, and revocations also have semantic sort rules below.
A future field requires a new explicitly supported protocol version; silently
retaining unknown fields is forbidden.

## Pending registration and identity possession

A registration code authorizes only creation of a pending device. It does not
make the device a member and does not authorize business relay traffic.

After validating and consuming the registration code, the server allocates the
workspace-bound device ID and creates an `IdentityPossessionChallenge`:

- `challenge_secret` is a fresh non-zero random 32-byte value;
- lifetime is positive and at most 10 minutes;
- workspace, device, and identity key ID bind the pending record.

The server Base-HPKE seals the canonical challenge to the proposed P-256
identity public key with the existing RFC 9180 suite:

```text
KEM  = DHKEM(P-256, HKDF-SHA256) 0x0010
KDF  = HKDF-SHA256               0x0001
AEAD = AES-128-GCM               0x0001
mode = Base                       0x00
info = "SyncNotifications-membership-possession-hpke-info-v1\0"
       || workspace_id || device_id || identity_key_id
AAD  = empty
```

The device decrypts the challenge using the exact proposed identity private key
and returns canonical `PendingIdentityProof`. `challenge_digest` is the
challenge-digest domain hash over the exact canonical challenge. The server
requires constant-time equality for the workspace/device/key binding, digest,
and secret, and separately enforces one-time use and expiry. A proof establishes
only possession of the proposed key; administrator approval is still required.

This HPKE challenge is necessary because existing device P-256 keys are ECDH
keys with derive/decrypt usage and are not portable ECDSA signing keys. The
protocol does not silently add a second device signing identity.

## Device certificate

`DeviceCertificate` binds:

- workspace and device IDs;
- Android or Chrome device type;
- valid non-blank UTF-8 display name of at most 100 bytes;
- one or more unique roles in strictly increasing enum order;
- exact P-256 identity public key and matching key ID;
- issue time, optional expiry (`0` means no expiry), and membership epoch.

Roles are:

1. `SEND_NOTIFICATIONS`;
2. `RECEIVE_NOTIFICATIONS`;
3. `INVOKE_NOTIFICATION_ACTIONS`;
4. `MANAGE_DEVICES`.

Role values are authorization facts, not UI labels. A relay may enforce routing
constraints visible from authenticated metadata; recipients MUST independently
check the authenticated sender and required role against their accepted roster.

For canonical certificate bytes `C`:

```text
certificate_id = SHA-256(certificate-id-domain || C)
authority_signature = Ed25519.Sign(authority_private_key,
                                   certificate-signature-domain || C)
```

`SignedDeviceCertificate` carries `C`, the exact ID, and the 64-byte signature.
Certificate IDs are derived rather than random, preventing two identifiers for
the same canonical authorization statement. The display name is the single
workspace-wide device name; clients do not create a second local alias model.

## Device certificate transition

An approved device display-name change replaces its active certificate in the
next roster. `DeviceCertificateTransition` binds the workspace and device, exact
previous and replacement certificate IDs, activation roster epoch, preceding
roster digest, transition reason, and issue time. Version 1 permits only
`DISPLAY_NAME`.

The replacement certificate MUST preserve the device type, roles, identity
public key and key ID, expiry, workspace, and device ID. Only `display_name`,
`issued_at_unix_ms`, and `membership_epoch` may change; the replacement
membership epoch and issue time equal the transition activation values. The
old and replacement certificates are never simultaneously active. The signed
activation roster authenticates the transition, so no local or relay-controlled
name can override it.

## Signed workspace roster

`WorkspaceRoster` is the complete current active certificate set plus a bounded
revocation record:

- `roster_epoch` is strictly monotonic;
- epoch 1 has an all-zero 32-byte `previous_roster_digest`;
- later epochs have a non-zero digest of the immediately preceding signed
  roster body;
- at most 256 active certificates, strictly sorted by unsigned device-ID bytes;
- at most one active certificate per device;
- at most 256 certificate transitions, strictly sorted by unsigned device-ID
  bytes and absent from epoch 1;
- each transition identifies the exact active replacement certificate, matches
  the roster workspace, epoch and previous digest, and uses a supported reason;
- at most 4096 revocations, strictly sorted by certificate-ID bytes;
- a certificate ID cannot be both active and revoked;
- every active certificate matches the roster workspace and has
  `membership_epoch <= roster_epoch`.

A revoked device is absent from the active set. A revocation identifies the
exact certificate and device and records the server time. A replacement
identity receives a new certificate; old and new certificates are never active
for the same device in one roster.

For canonical roster body bytes `R`:

```text
roster_digest = SHA-256(roster-digest-domain || R)
authority_signature = Ed25519.Sign(authority_private_key,
                                   roster-signature-domain || R)
```

The signature covers the complete active set, certificate transitions,
revocations, epoch, and previous digest. The relay cannot edit names or roles,
replace a certificate, or remove a member without invalidating it.
The accepted trust boundary still permits the authority itself to authorize a
malicious future recipient.

## Signed authority key transition

An authority rotation is a forward-only transition jointly authenticated by the
previous and new Ed25519 authorities. The canonical transition body binds the
workspace, transition epoch, previous transition digest, exact previous and new
public keys, activation roster epoch, preceding roster digest, and issue time.
The keys must differ. Epoch 2 has an all-zero previous transition digest; later
epochs require the exact non-zero digest of the preceding transition.

For canonical transition body bytes `T`:

```text
transition_digest = SHA-256(transition-digest-domain || T)
previous_authority_signature = Ed25519.Sign(previous_private_key,
                                             old-signature-domain || T)
new_authority_signature = Ed25519.Sign(new_private_key,
                                       new-signature-domain || T)
```

Both signatures are mandatory. The old signature establishes continuity and the
new signature proves possession before activation. The activation roster is the
next roster, extends the bound previous roster digest, reissues every active
device certificate under the new authority, and is signed by the new authority.
The transition, replacement certificates, activation roster, and current
authority pointer must be committed atomically.

Clients may replace a pin only by validating the next transition and activation
roster against their durable transition and roster rollback floors. Stale or
gapped epochs, digest forks, key reuse, activation mismatches, and unsigned pin
replacement fail closed.

## Client acceptance and rollback protection

A previously enrolled client durably stores the highest accepted roster epoch,
digest, and canonical signed bytes. It accepts:

- the same epoch only when digest and canonical signed bytes are exact matches;
- the next epoch only when `previous_roster_digest` equals the stored digest;
- a local certificate replacement only when the same next roster carries an
  exact transition from the stored certificate, and semantic comparison proves
  that only the display name and transition-bound issue/membership fields
  changed;
- no lower epoch and no gap without fetching and validating each missing roster.

A newly approved client may bootstrap from a currently signed roster without
replaying workspace history only when that roster contains its exact newly
issued certificate and has `roster_epoch >= membership_epoch`. It then persists
that roster as its rollback floor before business traffic begins.

Before sending or accepting a business envelope, a client checks that the exact
device ID and identity key are active and possess the required role. Transport
authentication, envelope replay, notification revision, snapshot reconciliation,
and operation idempotency remain separate checks.

## Revocation behavior

One administrator transaction must mark the device revoked, issue the next
signed roster, deny new transport authentication, and make active-session
closure observable to the authorization monitor. Other clients stop encrypting
to the revoked certificate after accepting the roster and reject subsequent
business envelopes from it.

Revocation is prospective: it cannot erase plaintext already delivered or
ciphertext already decrypted. Offline staleness duration and roster-fetch
transport remain pending implementation decisions; clients must not resume
business traffic indefinitely from an unrefreshed roster.

## Fixed vector

`test-vectors/workspace-membership-v1.json` contains public test-only authority
seed, device identity scalar, deterministic Base-HPKE challenge ciphertext,
challenge/proof, signed Chrome certificate, initial roster, next-epoch
display-name certificate transition, and independent next-epoch revoked roster.
It fixes HPKE info/encapsulation/ciphertext, all canonical bytes, digests,
certificate IDs, signatures, and previous-roster linkage. None of its
keys or secrets may be used outside tests.
