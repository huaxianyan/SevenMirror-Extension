# Chrome Extension release provenance and rollback

Status: **release-channel engineering baseline; independent review and Chrome Web Store publication evidence remain required**

## Deterministic submission package

The checked-in release builder packages the production `dist/` tree as a
canonical ZIP. Entries are sorted, use `/` separators, have a fixed 1980 ZIP
timestamp, regular-file mode `0644`, no directory records and deterministic
DEFLATE level 9 compression. Symlinks, non-regular files and unsafe paths are
rejected.

The release artifact set contains exactly:

- `sevenmirror-extension-<manifest-version>.zip`;
- `release-manifest.json`;
- `SHA256SUMS`.

The manifest binds the source repository and exact 40-character revision, npm
package version, Chrome manifest version, Manifest V3, ZIP name/size/SHA-256 and
every packaged file's sorted path/size/SHA-256. It intentionally contains no
build timestamp, runner path, branch name or extension signing key.

After downloading an artifact set, verify it offline against the approved source
revision:

```sh
python3 scripts/build_release_package.py \
  --output ./sevenmirror-extension-release \
  --revision <40-character-commit> \
  --verify-only
```

The verifier rejects missing or extra output files, symlinks, duplicate or
unordered ZIP entries, path traversal, encrypted entries, noncanonical metadata,
manifest/version mismatch and every size or digest mismatch.

## GitHub provenance

`.github/workflows/release-artifacts.yml` rebuilds from `package-lock.json`, runs
the protocol/fixture checks, typecheck and tests, then creates the deterministic
submission package. The official `actions/attest` action is pinned to
`1e69f48acb82d1966a394da916b4c1698aa569d6` (`v4.2.2`, GitHub-verified commit).
It uses GitHub OIDC and a short-lived Sigstore certificate to publish SLSA
provenance for the ZIP, release manifest and checksum file. No long-lived
repository signing key is configured.

Verify all three downloaded subjects against the repository identity:

```sh
for artifact in sevenmirror-extension-release/*; do
  gh attestation verify "$artifact" \
    --repo huaxianyan/SevenMirror-Extension
done
```

A version-tag run requires the tag to equal `v<public/manifest.json version>` and
requires `package.json` to carry that same non-development version. Manual runs
may produce attested release-candidate evidence while `package.json` still ends
in `-dev`; that output is not a published release.

The workflow uploads the exact set under a name containing the full source
commit with 30-day retention. Durable release retention is still undecided.

## Chrome Web Store boundary

The ZIP is the source submission package. GitHub provenance does **not** prove
which account uploaded it, what Chrome Web Store processing occurred, which
extension ID received it, or which CRX Google signed and served. The unpacked
extension ID observed in local Cent Browser profiles is not a release identity.

Before publication, release evidence must additionally record without exposing
credentials:

1. the verified ZIP SHA-256 and approved source revision;
2. the Chrome Web Store item/extension ID and publisher account control policy;
3. upload and review result associated with that ZIP;
4. the published version and publication time;
5. the store-served CRX/update-manifest identity and verification method;
6. publisher-account MFA, recovery, least privilege and audit-log retention.

Chrome Web Store credentials or refresh tokens must not enter the repository,
workflow artifacts, build logs or support bundles.

## Rollback rule

Chrome versions are monotonic. A published bad version normally cannot be
replaced by uploading the old ZIP under its old version. Rollback therefore means
building a **new, higher manifest version** from an explicitly approved prior
source state plus only the compatibility/version changes needed for publication.

A rollback candidate is acceptable only when its new ZIP and manifest pass the
same offline and GitHub attestation checks, the prior source revision is named in
the incident decision, storage/protocol compatibility has been reviewed, and the
new store publication evidence is captured. Do not select rollback source by a
mutable tag, filename, local unpacked profile, workflow status or “last known
good” label alone.

GitHub/Sigstore provenance is not Chrome Web Store signing and is not an
independent security review. Store publication, served-package verification,
publisher-account recovery and long-term retention remain release blockers.
