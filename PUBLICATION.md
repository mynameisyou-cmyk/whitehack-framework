# Publication gate

Whitehack separates an **open method** from the **private operational state** of a
security review. Open source does not mean every active investigation belongs in
an open repository.

## Classification

| Class | Examples | Public by default? |
|-------|----------|--------------------|
| Framework | Integrity Case schema/tooling, blank templates, doctrine, generic checklists | Yes, after review |
| Sanitized learning | Synthetic examples, primary-source case studies, owner-approved remediated findings | Case by case |
| Operational state | Real asset maps, review queues, hunt logs, unresolved findings, proof-of-concept code | No |
| Restricted data | Credentials, personal data, private authorization records, internal access details | Never |

If a repository contains operational or restricted material, it is not a public
release artifact as a whole. Publish from a reviewed allowlist into a clean
repository or release branch; do not rely on a denylist or `.gitignore` to remove
tracked history.

## Minimal reusable release slice

The exact first-release manifest is [`PUBLIC-ALLOWLIST.txt`](PUBLIC-ALLOWLIST.txt).
At a directory level, the smallest self-contained public slice is:

```text
LICENSE
SECURITY.md
CONTRIBUTING.md
PUBLICATION.md
PUBLIC-ALLOWLIST.txt
integrity/
site/
```

In a standalone public repository, promote `site/README.md` to the repository-root
`README.md`. Keep the original operational repository history out of that release.

Add doctrine, patterns, and public-source case studies only after reviewing their
content, source rights, links, and history. Never include `findings/drafts/`,
`findings/open/`, real `assets/<name>/` workspaces, `reviews/`, `hunt-log.md`,
`poc/`, credentials, or target-specific traces by default.

## Release checklist

1. **Name the release source.** Record the exact commit and the maintainer who
   approved publication.
2. **Build from an allowlist.** Start a clean tree and copy only reviewed public
   classes. Do not clone an operational repository's history into the public one.
3. **Scan the tree and history.** Check for key/token signatures, personal data,
   internal addresses, absolute user paths, unresolved finding IDs, and large or
   binary evidence files. Automated secret scans are necessary but not sufficient.
4. **Validate every Integrity Case.** Render its dashboard and manually inspect all
   implementation and evidence references for disclosure safety.
5. **Review rights.** Confirm the project can redistribute every document, image,
   dataset, and quoted excerpt under the declared license.
6. **Dry-run as a stranger.** Follow the public README in a fresh environment with
   no internal credentials, symlinks, or private dependencies.
7. **Publish deliberately.** Verify repository visibility, issue privacy limits,
   default branch protection, and the private security contact after publication.

## If sensitive material was committed

Stop publication. Rotate any credential first, even if you plan to rewrite Git
history. Preserve evidence according to the owner's incident process, identify
where the data was fetched or mirrored, and coordinate history removal with every
maintainer and hosting provider. A follow-up deletion commit is not remediation.
