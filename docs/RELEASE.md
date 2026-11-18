# Release process

> **Status: no release has been made; nothing is signed.** The pipeline exists
> (`.github/workflows/release.yml`) and its non-signing parts ran on GitHub runners (see `PACKAGING.md`).

Checklist a first release must satisfy, with the state of each item:
1. All CI jobs green on Linux, macOS **and** Windows runners (cross-compiled-only ≠ tested). *State: see the
   CI badge/runs; macOS runners were queued for hours and a macOS test job hung once — `TESTING.md`.*
2. `cargo deny check` clean; no ignored advisory without a written justification. *Done: three
   AccessKit-only "unmaintained" advisories are ignored in `deny.toml` with a reason and a review date
   (2027-03-01).*
3. Fuzzers (`fuzz/`) ran for a documented duration (hours, with seed corpora), findings fixed. *Not done:
   one real bug found and fixed; 8 targets × 5 minutes on GitHub plus short local runs, ≈112 M executions in
   total, no persisted corpora (`TESTING.md`).*
4. Every `uses:` in `.github/workflows` pinned to a full commit SHA. *Done (2026-11-18).*
5. Artefacts + `SHA256SUMS` + CycloneDX SBOM. *Built by the workflow.* Signatures only where real credentials
   exist — **none do**: no Apple Developer ID, no Windows code-signing certificate, no release GPG/minisign key.
   The signing and notarisation steps are written, run only when these repository secrets exist
   (`APPLE_CERT_P12_BASE64`, `APPLE_CERT_PASSWORD`, `APPLE_SIGNING_IDENTITY`, `APPLE_ID`, `APPLE_TEAM_ID`,
   `APPLE_APP_PASSWORD`, `WINDOWS_CERT_PFX_BASE64`, `WINDOWS_CERT_PASSWORD`) and have **never been executed**.
   Until then the Windows installer triggers SmartScreen and the macOS app is ad-hoc signed (Gatekeeper warns).
6. Threat model and `SECURITY.md` re-read against what was actually built; independent review
   scheduled/recorded before any "production" wording. *Not done.*

How to cut a release candidate: bump `version` in the workspace `Cargo.toml`, commit, `git tag vX.Y.Z`,
`git push --tags`. The workflow refuses a tag that does not match the crate version, builds and verifies
everything, and leaves a **draft** pre-release for a human to inspect and publish.
