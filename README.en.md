<div align="center">
  <img src="docs/images/icon.png" width="120" alt="SevenMirror icon">

  # SevenMirror Chrome Extension

[Project hub](https://github.com/huaxianyan/SevenMirror-Project) · [Server](https://github.com/huaxianyan/SevenMirror-Server) · Chrome extension · [Android app](https://github.com/huaxianyan/SevenMirror-Android)

[English](README.en.md) | [简体中文](README.md)
</div>

Receive your phone's notifications on your computer. This extension is the receiving end: every notification your phone sends pops up as a system notification, and you can act on it, reply to it or clear it right there.

> Status: usable for everyday use, and listed on the Chrome Web Store. Receiving and presenting notifications, remote actions and replies, shortcut rules, cross-browser rule sync and the standalone interaction window are all implemented. Being listed on the store is not the same as a completed independent security review; the two are recorded separately.

<p align="center">
  <a href="https://chromewebstore.google.com/detail/fibpoeijlejjkokmngpcoahdhbjigcma"><img src="docs/images/chrome-web-store-badge.png" height="56" alt="Get SevenMirror on the Chrome Web Store"></a>
</p>

## What it does

- **Receives phone notifications**: notifications from the apps your phone selected pop up on your computer, just like local ones.
- **Acts on them from the computer**: mark as done, send a reply, or clear the notification.
- **Click the body to open a small window**: read the details and reply in a standalone window, without a browser tab and without interrupting what you were doing.
- **The badge counts only what you actually opened**: the toolbar badge counts notifications whose details you have not opened. Peeking at the popup does not clear it.
- **Source filter**: narrow the list down to one source device.
- **Its own sound**: a short chime when a notification arrives live, with a silent mode and a preview button in the settings.
- **Shortcut rules**: per-application priority rules and quick actions, so you do not have to open the detail every time.
- **Rules sync across browsers**: one passphrase keeps the rules the same in every browser of your workspace. Rules are stored as ciphertext; the relay cannot read them.
- **Failed clears explain themselves**: when the phone refuses a remote clear, the extension tells you why instead of leaving you waiting.

## Using it

SevenMirror is self-hosted, so you need a server running the relay first. You can host it yourself; see the server repository for how.

1. Install the extension. The [Chrome Web Store](https://chromewebstore.google.com/detail/fibpoeijlejjkokmngpcoahdhbjigcma) listing is the one-click path; you can also download the packaged build from this repository's Releases, or build it yourself and load it.
2. Put the relay address into the settings, then register with a one-time join code issued by the operator.
3. Approve the phone the first time it connects, and compare the verification code shown on both ends.
4. Configure how notifications are presented and set up shortcut rules in the settings.

The extension never asks to read the notifications on your computer. The phone decides what to share, and every piece of content is already encrypted when it arrives; only this extension holds the key.

## Requirements

- The Node.js LTS version named in `.nvmrc`, when building yourself
- A current stable Chrome
- A SevenMirror relay that is already running

## Building from source

```sh
npm install
npm test
npm run build
```

Then load the `dist/` directory in `chrome://extensions` with "Load unpacked". The settings page shows the running version, which is how you confirm the reload took effect.

## Releasing

Pushing a tag like `v0.1.21` triggers a release. The tag must equal the version in `public/manifest.json`, and `package.json` must match it.

The release artefact is a deterministically packed ZIP, and it is the same file submitted to the Chrome Web Store. The ZIP and the store listing are still two separate things: a store version goes through review on its own, and the identity of store-distributed artefacts and the publisher account evidence stay independent. The listing is at [Chrome Web Store](https://chromewebstore.google.com/detail/fibpoeijlejjkokmngpcoahdhbjigcma). Full rules are in [Release provenance](docs/release-provenance.md).

## Documentation

Development and operational detail lives in separate documents rather than here.

| Topic | Document |
| --- | --- |
| Unread, history and search rules | [Notification history and search](docs/notification-history.md) |
| Release artefacts, offline verification and the store boundary | [Release provenance](docs/release-provenance.md) |
| Actions and permissions used by the release workflow | [Release actions](docs/release-actions.md) |
| Local sensitive-data inventory and audit | [Sensitive data](docs/SENSITIVE_DATA.md) |
| Dependency vulnerability evidence and query rules | [Vulnerability evidence](docs/vulnerability-evidence.md) |
| Where the notification sound comes from and how to switch it | [Notification sound](docs/notification-sound.md) |
| Protocol assets, versions and verification | [Protocol assets](protocol/README.md) |

## License

This revision is licensed under [`GPL-3.0-only`](LICENSE). Commercial use is allowed, and distribution must follow GPLv3. Previously released MIT versions are unaffected retroactively; the exact MIT-to-GPL boundary is in [`LICENSE-TRANSITION.md`](LICENSE-TRANSITION.md), and that boundary revision and its ancestors remain available under MIT.
