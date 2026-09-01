# Chrome release GitHub Actions review

Status: **internal identity and permission review; not independent approval**

The release workflow adds two official GitHub Actions. Both are pinned to
immutable commits that GitHub reports as valid verified signatures.

## `actions/attest`

- Commit: `1e69f48acb82d1966a394da916b4c1698aa569d6`
- Release: `v4.2.2`
- Inputs: only the generated ZIP, release manifest and checksum file
- Purpose: subject hashing, GitHub OIDC/Sigstore signing and GitHub attestation
  publication
- Permissions: `contents: read`, `id-token: write`, `attestations: write`,
  `artifact-metadata: write`
- Long-lived signing secret: none

The job does not receive extension publisher credentials, transport credentials,
HPKE identity state, notification data or a browser profile.

## `actions/upload-artifact`

- Commit: `b7c566a772e6b6bfb58ed0dc250532a479d7789f`
- Release: `v6.0.0`
- Input: the already verified and attested three-file release set
- Missing-file behavior: fail closed
- Retention: 30 days

The uploaded artifact name includes the full source commit, but neither that name
nor GitHub's generated download ZIP is a release identity. Consumers verify the
three inner subjects and canonical release manifest.

## Remaining review

This review does not recursively approve every Action dependency, GitHub's
hosted runner, Sigstore availability, durable artifact hosting or Chrome Web
Store processing. Both pinned commits, permissions and published source must be
rechecked at the production release baseline. Publisher account controls and
store upload tooling require a separate review before credentials are introduced.
