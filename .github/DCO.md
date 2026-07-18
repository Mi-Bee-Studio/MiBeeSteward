# Developer Certificate of Origin (DCO)

In addition to signing the [Contributor License Agreement (CLA)](../CLA.md),
every commit in a pull request must be **signed off** using the
Developer Certificate of Origin (DCO).

## What is the DCO?

The DCO is a lightweight assertion that you wrote the code you are submitting
(or otherwise have the right to pass it on). It is the same mechanism used by
the Linux kernel, Git, and many other open-source projects.

## How to sign off

Add a `Signed-off-by` line to each commit. The easiest way is to pass
`-s` when committing:

```bash
git commit -s -m "feat(scanner): add new probe"
```

This produces a trailer in the commit message:

```
Signed-off-by: Jane Doe <jane@example.com>
```

The name and email **must match** your Git configuration and (for the CLA)
the GitHub username / email we have on file.

## Automating sign-off

To never forget, configure Git to sign off every commit on this clone:

```bash
git config alias.scommit 'commit -s'
# then use: git scommit -m "..."
```

Or set it globally for the project's repo only:

```bash
cd mibee-steward
git config commit.gpgsign false   # DCO uses trailers, not GPG — but this is unrelated
```

## The DCO text

```
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.

Everyone is permitted to copy and distribute verbatim copies of this
license document, but changing it is not allowed.


Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```

## Enforcement

The [`dco.yml`](workflows/dco.yml) workflow runs on every pull request and
**blocks merge** if any commit lacks a valid `Signed-off-by` trailer. To fix a
forgotten sign-off on existing commits:

```bash
git rebase --signoff HEAD~N    # re-sign the last N commits
git push --force-with-lease
```

## Relationship to the CLA

- **DCO** (per-commit, automated): certifies *origin* — "I wrote this / have
  the right to submit it."
- **CLA** (per-contributor, one-time): grants *relicensing rights* — "Mi-Bee
  Studio may release my contribution under both AGPLv3 and the commercial
  license."

Both are required. The DCO is the daily-mechanism; the CLA is the one-time
agreement that makes dual licensing legally possible.
