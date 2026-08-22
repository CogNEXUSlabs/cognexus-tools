# Changelog

## 0.5.0

The licence CLI and the rotation-aware verifier. Both were written before
0.4.0 was cut and neither reached PyPI, so 0.4.0 users have a verifier that
cannot read a key handover and no `artzain licence` command at all.

### Added

- **`artzain licence`** — the client half of the offline licence flow:
  `request`, `install`, `attest`, `anchor`, `anchors`, `verify`. Everything
  works on files, with no network at any point. That is a requirement rather
  than an optimisation: a sovereign or air-gapped install exports an
  attestation, a person carries it out on whatever medium they already use,
  and it is verified on the other side.
- **`artzain.licence`** — the module behind it. CSRs, anchor records, Sealed
  Usage Attestations, and three-verdict verification matching the audit
  verifier (`VERIFIED, ATTESTED` / `VERIFIED, SELF-ATTESTED` / `FAILED`).
- **Signing-key handovers in `audit verify`.** A bundle that spans a key
  rotation now carries `key-rotations.json`: countersigned records binding a
  retiring key to its successor. The verifier checks both signatures against
  the public keys carried *inside each record*, not through `keys.json`, so an
  edited bundle cannot choose which of its own claims get inspected.
- `audit verify --json` reports `rotations_checked` and `unexplained_key_ids`.

### Changed

- A bundle whose signed manifest commits `key_ids` now fails if `keys.json` is
  missing one of them. Deleting a key was previously invisible, and it silently
  skipped whatever check would have resolved that key.
- `verify_bundle` reports, without failing, a key that signed records in the
  bundle when no sound handover names it. Reported rather than fatal because a
  second process legitimately signs with its own key — but it is also the shape
  a substitution takes, so the reader gets to decide.

### Compatibility

Bundles exported before any of this still verify exactly as they did. A
handover the bundle cannot check — a key absent from `keys.json`, or
`cryptography` not installed — is reported, never fatal: a supplementary
custody claim must not collapse the verdict for an otherwise intact chain.

## 0.4.0 and earlier

Not recorded here. See the git history on
[CogNEXUSlabs/cognexus-tools](https://github.com/CogNEXUSlabs/cognexus-tools).
