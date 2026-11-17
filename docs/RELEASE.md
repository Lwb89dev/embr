# Release process — plan

> **Status: not started (Milestone 7).** No release has been made; nothing is signed.

Checklist a first release must satisfy:
1. All CI jobs green on Linux, macOS **and** Windows runners (cross-compiled-only ≠ tested).
2. `cargo deny check` clean; no ignored advisory without a written justification.
3. Fuzzers (`fuzz/`) ran for a documented duration (hours, with seed corpora), findings fixed.
4. Every `uses:` in `.github/workflows` pinned to a full commit SHA.
5. Artefacts + `SHA256SUMS` + CycloneDX SBOM; signatures only where real credentials exist
   (release GPG/minisign key; Apple Developer ID; Windows code-signing cert) — missing credentials are
   documented, never faked.
6. Threat model and `SECURITY.md` re-read against what was actually built; independent review
   scheduled/recorded before any "production" wording.
