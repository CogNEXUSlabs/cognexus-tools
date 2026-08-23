# Security policy

## Reporting a vulnerability

Email **security@cognexuslabs.ai**. Please do not open a public issue,
discussion or pull request for an unfixed defect, and please do not send
reports to any other address.

There is no PGP key yet. If a report needs encryption in transit, say so in a
first plain email with no details and we will agree a channel before you send
them.

### Scope

- the packages published from this repository: `artzain` on PyPI and
  `@cognexuslabs/artzain` on npm;
- the hosted service at <https://app.cognexuslabs.ai>;
- the decision engine behind it (Decision API, audit chain, policy bundles),
  which is a separate private codebase that carries this same policy.

### What to include

- the package and version, or "the hosted service" with the date and time
  you observed the behaviour;
- steps to reproduce, with the input that triggers it -- a proof-of-concept
  is welcome, a weaponised exploit is not needed;
- the impact as you understand it;
- whether, and how, you would like to be credited.

### What happens next

- **Acknowledgement within 3 business days** of receipt.
- We confirm or refute the report and agree a fix and disclosure plan with
  you. The target is a fix and **coordinated disclosure within 90 days** of
  the report; if a fix needs longer we will say so, and why, before the
  deadline rather than after it.
- SDK fixes are released through the tag-gated, Trusted-Publisher workflows
  in this repository and announced as a GitHub Security Advisory here.

### What we do not offer

- **No bug bounty.** We credit reporters in the advisory if they want it; we
  do not pay for reports.
- **No PGP key yet**, as above.

## Safe harbour

Security research conducted in good faith under this policy is authorised,
and we will not pursue or support legal action against you for it, provided
you avoid customer data (if you can reach another tenant's data, stop and
report it without reading, copying or retaining it), do not degrade the
hosted service (no denial of service, load testing or automated scanning that
amounts to either), do not violate anyone's privacy or social-engineer staff
or customers, use only accounts and API keys you own, and give us the time
above to fix the issue before any public disclosure.

## Verifying a release

Every release is published by a tag-gated workflow through a Trusted
Publisher (PyPI and npm), so each artifact carries provenance naming the
commit and workflow run that built it: a PEP 740 attestation on PyPI, and
npm provenance you can check with `npm audit signatures`.
