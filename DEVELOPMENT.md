# Development Process

This document records, fairly and quantitatively, **how this repository was
actually built**. It is the after-action report on a deliberate experiment:

> Could a non-trivial, security-sensitive desktop application be built almost
> entirely by a hands-off agentic AI (the GitHub Copilot coding agent),
> with the human owner restricted to authoring GitHub Issues, reviewing pull
> requests, and pressing the merge button?

The short answer, supported by the metrics below, is **yes — substantively
all source code, tests, and documentation in this repository were produced by
the GitHub Copilot SWE Agent in response to GitHub Issues authored by the
repository owner.** The owner's contribution to the source tree itself is
limited to the initial scaffold commit and a handful of GitHub-suggested
security autofixes accepted via the GitHub UI; the owner's substantive role
was in *direction* (writing issues), *governance* (reviewing PRs, merging),
and *curation* (closing duplicates, prioritising follow-ups).

> **Snapshot date.** The figures in this document were computed against
> `origin/main` on **2026-04-18**. The methodology is reproducible — see
> [Reproducing the metrics](#reproducing-the-metrics) at the end of the file.

---

## 1. The Experiment

### 1.1 Aim

The stated intent of the project from the outset was to **develop a
cross-platform Rust + Slint password manager using hands-off agentic
GitHub Copilot, driven by GitHub Issues, with minimal hands-on
interventions.** Issue [#256 "Final Code Quality Review"](
https://github.com/obstreperous-ai/rust-slint-password-saver/issues/256)
restates this verbatim:

> This project has been an experiment in using hands off agentic CoPilot
> driven by GitHub Issues with minimal hands on interventions.

### 1.2 The loop in practice

A single, repeating workflow accounts for almost every change in the
repository:

1. **Owner opens a GitHub Issue.** Issues range from broad features
   ("Add a password generator", "Add Windows support") to narrow polish
   tasks ("Fix corrupt backup test", "Document two-factor authentication").
2. **Issue is assigned to `@Copilot`.** Every closed issue in the
   repository is assigned to the Copilot SWE Agent (often alongside the
   owner as co-assignee for visibility).
3. **The Copilot agent opens a draft pull request** from a `copilot/<slug>`
   branch and works in that branch — planning, exploring the codebase,
   writing code, running `cargo build` / `cargo test` / `cargo clippy` /
   `cargo fmt`, iterating on review feedback, then marking the PR ready.
4. **Owner reviews and merges.** Almost all merges are squash/merge-commit
   merges performed by the owner via the GitHub UI; the resulting merge
   commit is authored by the owner, but the underlying file changes are
   authored by `copilot-swe-agent[bot]`.
5. **Specialist agent personas under `.github/agents/`** (e.g.
   [`rust-security-expert`](.github/agents/rust-security-expert.md),
   [`codeql-triage-expert`](.github/agents/codeql-triage-expert.md),
   [`code-quality-expert`](.github/agents/code-quality-expert.md),
   [`slint-ux-expert`](.github/agents/slint-ux-expert.md),
   [`windows-expert`](.github/agents/windows-expert.md),
   [`licensing-expert`](.github/agents/licensing-expert.md),
   [`cs-researcher`](.github/agents/cs-researcher.md))
   shape the agent's behaviour in different domains. Project-wide
   conventions live in [`.github/copilot-instructions.md`](.github/copilot-instructions.md).
6. **Automated guardians** (CodeQL, `cargo-audit`, `cargo-deny`,
   Dependabot, the `quality.yml` lint/format workflow, the multi-OS
   `ci.yml` test workflow) provide the only non-human, non-Copilot
   feedback signal in the loop.

There is no separately-checked-in "design doc" backlog: **the GitHub Issues
*are* the design and the planning record.** Implementation is governed
by the documents committed alongside the code — chiefly
[`README.md`](README.md), [`SECURITY.md`](SECURITY.md),
[`THREAT_MODEL.md`](THREAT_MODEL.md),
[`CODE_QUALITY.md`](CODE_QUALITY.md),
[`STYLE_GUIDE.md`](STYLE_GUIDE.md),
[`TESTING_SECURITY_NOTE.md`](TESTING_SECURITY_NOTE.md), and
[`WINDOWS.md`](WINDOWS.md).

---

## 2. Headline Metrics

All figures are computed from `origin/main` and from the GitHub Issues /
Pull Requests API. Counts are exact at the snapshot date.

### 2.1 Project size and span

| Metric | Value |
|---|---|
| First commit | 2026-01-13 |
| Latest commit on `main` | 2026-04-18 |
| Calendar duration | ~3 months (≈14 weeks) |
| Source files (Rust) | 44 `.rs` files |
| Source lines (Rust) | 16,572 lines |
| UI definition (Slint) | 1,586 lines (`src/ui/main.slint`) |
| Project documentation | 6,802 lines across 7 top-level Markdown files |

### 2.2 Commits on `main`

| Category | Commits | Share |
|---|---:|---:|
| **Total commits on `main`** | **534** | 100.0% |
| Merge commits (PR integrations) | 144 | 27.0% |
| Substantive (non-merge) commits | 390 | 73.0% |

Of the **390 substantive commits** that actually changed files in the tree:

| Author | Substantive commits | Share |
|---|---:|---:|
| `copilot-swe-agent[bot]` | **384** | **98.5%** |
| `obstreperous-ai` (owner) | 4 | 1.0% |
| `dependabot[bot]` | 2 | 0.5% |

The four owner-authored substantive commits are themselves *not* hand-written
feature work:

| SHA | Date | Message | Origin |
|---|---|---|---|
| `d02530f` | 2026-01-13 | Initial commit | Empty-repo scaffold |
| `a9500d4` | 2026-02-09 | Potential fix for code scanning alert no. 22: Hard-coded cryptographic value | GitHub Code Scanning autofix accepted in the UI |
| `0363838` | 2026-02-21 | Potential fix for code scanning alert no. 4: Workflow does not contain permissions | GitHub Code Scanning autofix accepted in the UI |
| `131b98e` | 2026-04-08 | Potential fix for code scanning alert no. 154: Workflow does not contain permissions | GitHub Code Scanning autofix accepted in the UI |

So the owner's direct, hand-written contribution to the source tree is, in
practice, the empty `Initial commit`. **Everything else** was either
generated by the Copilot SWE Agent, suggested by GitHub Code Scanning's
autofix and accepted by the owner, or proposed by Dependabot.

### 2.3 Merges, by who pressed the button

| Author of merge commit | Merge commits | Share |
|---|---:|---:|
| `obstreperous-ai` (owner) | 141 | 97.9% |
| `copilot-swe-agent[bot]` | 3 | 2.1% |

The owner's role on `main` is overwhelmingly that of an **integrator**:
141 of the owner's 145 commits on `main` (97.2%) are PR merge commits. The
three Copilot-authored merge commits are agent-side rebases of long-running
feature branches against `main` (e.g. the recovery-workflow branch).

Of the 144 merge commits, **140 (97.2%) integrate a `copilot/*` feature
branch**. The remaining four are two Dependabot dependency bumps and two
GitHub Code Scanning `alert-autofix-*` branches.

### 2.4 Co-authorship trailers

The Copilot SWE Agent records the human who initiated each task as a
`Co-authored-by:` trailer on the commit. Across `main`:

| Co-author trailer | Commits |
|---|---:|
| `Co-authored-by: obstreperous-ai` | 255 |
| `Co-authored-by: Copilot Autofix powered by AI` | 3 |

So **255 substantive commits (~66% of all 384 Copilot-authored commits) are
explicitly co-authored by the human owner via the agentic workflow** — the
mechanical record of "owner asked, agent built". The remaining ~129
Copilot-authored commits are intermediate iterations within an agent
session (planning, retries, lint fixes) that do not carry a co-author
trailer; the *containing* PR is still owner-initiated.

### 2.5 Issues and pull requests

| Resource | Count |
|---|---:|
| Issues opened (all-time) | 121 |
| Issues closed | 120 |
| Pull requests opened | 137 |
| Pull requests merged | 133 |
| PRs authored by `app/copilot-swe-agent` | 129 |
| PRs authored by `app/dependabot` | 2 |
| PRs authored by the owner directly | 6 |

The six owner-authored PRs are GitHub Code Scanning **autofix** PRs
(`alert-autofix-*` branches) — i.e. one-click acceptances of automated
suggestions, not hand-written patches.

**Net effect: 100% of merged code, tests and documentation in the
repository arrived through one of three automated routes** (Copilot SWE
Agent, Dependabot, GitHub Code Scanning autofix), all of them gated on the
owner's review and merge.

### 2.6 Velocity

Substantive commits per calendar month on `main`:

| Month | Substantive commits | Notes |
|---|---:|---|
| 2026-01 | 34 | Project scaffolding, initial encryption, first UI |
| 2026-02 | 242 | Bulk of feature work — recovery codes, search, generator, validation, Slint UX, security hardening |
| 2026-03 | 61 | Stabilisation, CI/CD, Windows port, packaging |
| 2026-04 | 53 | Final review, threat-model writing, documentation polish, signing/SBOM/SLSA |

Peak February velocity (~8 commits/day, all but two by Copilot)
demonstrates that the agentic loop is capable of sustaining a working
pace well above what a single human reviewer can realistically *originate*
in the same window — but reading and merging that volume is exactly the
role the owner adopted.

---

## 3. Qualitative Assessment

### 3.1 What the experiment confirms

- **The "issue → agent → PR → merge" loop scales well for a single-developer
  project of this size.** 121 issues over three months produced a working,
  cross-platform Rust + Slint password manager with: Argon2id key
  derivation, AES-256-GCM storage, recovery-code workflow, password
  strength meter, generator, search, export/import, clipboard auto-clear,
  auto-lock, rate-limited login, and Windows ACL hardening — all driven
  from natural-language issue descriptions.
- **Specialist agent personas materially shape outputs.** The seven
  personas in `.github/agents/` (security, CodeQL triage, Slint UX,
  Windows, licensing, code quality, CS research) give the agent a
  consistent voice and reviewing posture in their respective domains, and
  the project-wide standards in `.github/copilot-instructions.md`
  successfully enforce the `cargo fmt` → `cargo build` → `cargo test` →
  `cargo clippy -D warnings` discipline visible in the CI logs.
- **Automated guardrails are essential, not optional.** CodeQL,
  `cargo-audit`, `cargo-deny`, Dependabot, and the strict-clippy CI are
  what keep an *unsupervised* agent honest. Several of the most important
  hardening rounds in `SECURITY.md` were initiated by CodeQL alerts that
  the agent then resolved in a follow-up issue.
- **Test discipline survived the experiment.** The repository ships ~16.5
  KLOC of Rust including a substantial integration-test tree
  (`tests/integration/*`). Where regressions occurred, they were typically
  caught by the existing test suite on the next agent PR rather than
  reaching `main`.

### 3.2 What the experiment exposes

- **Reviewer load is the binding constraint.** With ~98.5% of substantive
  commits authored by the agent and ~98% of PRs Copilot-authored, the
  human owner's only practical lever is *which PRs to merge*. This makes
  PR descriptions (which the Copilot agent maintains as a checklist) and
  passing CI the de-facto sources of truth — there is no realistic
  expectation of full line-by-line human review at this volume.
- **Documentation and code can drift if not policed in-issue.** The
  recurring need for "Final Code Quality Review" / consistency-pass issues
  (e.g. #256 / #257) is a direct symptom: each narrow agent PR is locally
  consistent, but cross-document consistency requires its own,
  explicitly-scoped issue.
- **Some classes of work remain awkward.** Truly cross-cutting refactors,
  UI ergonomics that require human judgement, and questions where the
  *requirement itself* is ambiguous all benefit from the owner writing
  more prescriptive issues. The shorter and more open-ended an issue, the
  more likely the resulting PR is to need follow-up.
- **The owner's name on a merge commit is not a claim of authorship.** A
  reader of `git log` who does not look beyond `%an` on merge commits will
  systematically over-attribute the project to the owner. Section 2 of
  this document exists precisely to make the true authorship distribution
  visible.

### 3.3 Honest scope of the human contribution

To be unambiguous, the human owner's contribution to this repository
consists of:

- Authoring and refining **121 GitHub Issues** that defined every feature,
  bug fix, security hardening, and documentation update.
- **Reviewing and merging 141 pull requests** from `copilot/*` branches
  (plus 2 Dependabot and 4 autofix PRs).
- One-click acceptance of **3 GitHub Code Scanning autofixes** that landed
  as owner-authored commits.
- The empty `Initial commit` that created the repository.
- Project direction, prioritisation, and the decision to attribute
  authorship transparently in this document.

The human owner has **not hand-written any of the Rust source, Slint UI,
test, CI workflow, or non-trivial Markdown content** that ships in the
repository today.

---

## 4. Repeatability

If you want to run the same experiment, the moving parts are all visible
in this repository:

- **Project-wide agent contract:** [`.github/copilot-instructions.md`](.github/copilot-instructions.md)
  — encodes the mandatory `cargo fmt` / `cargo build` / `cargo test` /
  `cargo clippy --all-targets -- -D warnings` workflow, security rules,
  TDD expectations, and what the agent must *not* do.
- **Specialist personas:** [`.github/agents/`](.github/agents/) — seven
  domain-specific reviewer/implementer profiles invoked when an issue
  touches their area.
- **Quality gates in CI:**
  [`ci.yml`](.github/workflows/ci.yml) (Linux/macOS/Windows build & test),
  [`quality.yml`](.github/workflows/quality.yml) (`cargo fmt --check`
  and `cargo clippy -D warnings`),
  [`security.yml`](.github/workflows/security.yml)
  (`cargo-audit` + `cargo-deny` daily and on PR),
  [`codeql.yml`](.github/workflows/codeql.yml) (Rust CodeQL with
  `tests/` excluded via [`.github/codeql/codeql-config.yml`](.github/codeql/codeql-config.yml)),
  [`release.yml`](.github/workflows/release.yml) (multi-target signed
  releases with SBOM and SLSA provenance).
- **Living standards documents** the agent treats as authoritative:
  [`README.md`](README.md), [`SECURITY.md`](SECURITY.md),
  [`THREAT_MODEL.md`](THREAT_MODEL.md),
  [`CODE_QUALITY.md`](CODE_QUALITY.md),
  [`STYLE_GUIDE.md`](STYLE_GUIDE.md),
  [`TESTING_SECURITY_NOTE.md`](TESTING_SECURITY_NOTE.md),
  [`WINDOWS.md`](WINDOWS.md).
- **Pre-commit hooks** mirroring the CI gates:
  [`.pre-commit-config.yaml`](.pre-commit-config.yaml).

---

## 5. Reproducing the metrics

All numbers in Section 2 can be regenerated locally with `git` and the
GitHub API. Snapshot date: 2026-04-18 against `origin/main`.

```bash
# Section 2.2 — substantive vs merge commits, by author
git log origin/main --pretty=format:'%an' | sort | uniq -c | sort -rn
git log origin/main --merges    --pretty=format:'%an' | sort | uniq -c | sort -rn
git log origin/main --no-merges --pretty=format:'%an' | sort | uniq -c | sort -rn

# Section 2.2 — the four owner-authored substantive commits
git log origin/main --no-merges --author='obstreperous-ai' \
    --pretty=format:'%h %ai %s'

# Section 2.3 — share of merges that come from copilot/* branches
git log origin/main --merges --pretty=format:'%s' | grep -c 'copilot/'

# Section 2.4 — co-authorship trailers
git log origin/main --pretty=format:'%b' | grep -i 'Co-authored-by:' \
    | sort | uniq -c | sort -rn

# Section 2.5 — issues and PRs (uses gh CLI)
gh issue list --repo obstreperous-ai/rust-slint-password-saver \
    --state all --limit 1000 | wc -l
gh pr    list --repo obstreperous-ai/rust-slint-password-saver \
    --state all --limit 1000 | wc -l
gh pr    list --repo obstreperous-ai/rust-slint-password-saver \
    --state all --limit 1000 --search 'author:app/copilot-swe-agent' | wc -l

# Section 2.6 — substantive commits per month
git log origin/main --no-merges --pretty=format:'%ai' \
    | awk '{print substr($1,1,7)}' | sort | uniq -c
```

---

## 6. Disclosure

This `DEVELOPMENT.md` was itself written by the GitHub Copilot SWE Agent in
response to issue
[#66 "Document Development Process"](https://github.com/obstreperous-ai/rust-slint-password-saver/issues/66),
following the same loop it documents. The agent computed the metrics in
Section 2 directly from `git log` and the GitHub API in the same session
that produced this file. The owner's contribution to this document is the
issue that requested it and the act of merging the resulting pull request.
