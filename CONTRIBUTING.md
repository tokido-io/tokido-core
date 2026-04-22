# Contributing to tokido-core

Thank you for your interest in contributing. This document covers everything you need to know to get a change merged.

---

## Table of contents

- [Getting started](#getting-started)
- [How to contribute](#how-to-contribute)
- [Issues](#issues)
- [Pull requests](#pull-requests)
- [Code style](#code-style)
- [Testing requirements](#testing-requirements)
- [CI / GitHub Actions](#ci--github-actions)
- [Adding a new factor provider](#adding-a-new-factor-provider)
- [Commit messages](#commit-messages)
- [Review process](#review-process)
- [Release process](#release-process)

---

## Getting started

```bash
git clone https://github.com/tokido-io/tokido-core.git
cd tokido-core
mvn verify        # compile + test + coverage check
```

**Requirements:** Java 21+, Maven 3.9+.

The build must pass `mvn verify` cleanly — this runs compilation, all tests, and the JaCoCo coverage gate (90% minimum line coverage).

---

## How to contribute

1. Check [open issues](https://github.com/tokido-io/tokido-core/issues) — someone may already be working on your idea.
2. For non-trivial changes, **open an issue first** to discuss the approach before writing code.
3. Fork the repository, create a branch, make your changes, open a PR.
4. A maintainer will review. Address feedback and keep the PR up to date with `main`.

---

## Issues

### Reporting bugs

Use the **Bug report** issue template. Include:

- tokido-core version
- Java version and OS
- Minimal reproduction (code snippet or test case)
- Expected vs actual behavior

### Requesting features

Use the **Feature request** issue template. Describe:

- The problem you are trying to solve (not just the solution)
- Whether you are willing to implement it

### Security vulnerabilities

**Do not open a public issue.** Follow the process in [SECURITY.md](SECURITY.md).

### Issue hygiene

- Search before opening — duplicates will be closed.
- One issue per problem.
- Issues with no activity for 90 days may be closed as stale.

---

## Pull requests

### Before opening a PR

- [ ] There is an open issue for non-trivial changes.
- [ ] `mvn verify` passes locally.
- [ ] New functionality has tests.
- [ ] No new runtime dependencies were added without prior issue discussion.

### PR title

Use [Conventional Commits](https://www.conventionalcommits.org/) format:

```
feat(totp): add algorithm negotiation
fix(engine): remove redundant confirmed update in enroll
docs(spi): document SecretStore callback sequence
test(recovery): add replay protection test
chore: bump jacoco to 0.8.13
```

Types: `feat`, `fix`, `docs`, `test`, `chore`, `refactor`, `perf`.

### PR body

Fill in all sections of the pull request template:
- **What** — what changed
- **Why** — the problem it solves or the issue it closes (`Closes #123`)
- **Testing** — how you verified the change

### PR rules

- **One concern per PR.** Don't bundle unrelated fixes.
- **Keep PRs small.** Large PRs take longer to review and are harder to reason about. If a feature is large, split it into reviewable pieces.
- **No force-pushes** to a PR branch after review has started — it makes diff tracking hard. Use additional commits; squashing happens at merge.
- **All CI checks must be green** before a PR can be merged.
- **All review comments must be resolved** before merging.
- **At least one approval** from `@tokido-io/maintainers-oss` is required.
- Stale reviews are dismissed automatically when new commits are pushed.
- The author of the last push cannot approve their own PR.

### Merging

Maintainers merge using **squash and merge** to keep `main` linear. Your commit messages become the squash body — write them clearly.

---

## Code style

tokido-core has a deliberately minimal style. There is no formatter enforced by CI, but PRs that diverge significantly from these conventions will be asked to align.

### Java conventions

- **Records for value types and results** — `EnrollmentResult`, `StoredSecret`, `FactorStatus` are all records. New value types should be too.
- **No Lombok.** Explicit is better than generated.
- **No framework annotations** in core or SPI modules. tokido-core must remain framework-agnostic.
- **`final` fields everywhere.** Mutable state is a last resort.
- **Immutable collections.** Use `Map.of()`, `List.of()`, `Map.copyOf()` — never return mutable collections from public methods.
- **Package-private by default.** Only expose what is part of the intentional API surface.
- **No `null` in public APIs** unless the contract explicitly documents it (e.g., `SecretStore.load()` returns `null` for not-found by design).
- **Exceptions over error codes.** Throw typed exceptions (`AlreadyEnrolledException`, `NotEnrolledException`) rather than returning status codes.

### Javadoc

- All public types and methods in `tokido-core-api` must have Javadoc.
- `tokido-core-engine` public methods must have Javadoc.
- Implementation classes (`TotpFactorProvider`, etc.) should document non-obvious behavior.
- Use `{@code}` for inline code references, `{@link}` only for types reachable from the current module's classpath.

### Dependencies

- **No new compile-scope dependencies in `tokido-core-api`** or `tokido-core-engine`. These modules must remain dependency-free.
- New runtime dependencies in factor modules (e.g., `zxing`, `jbcrypt`) are acceptable but require prior discussion in an issue.
- Test-scope dependencies are fine without discussion.

---

## Testing requirements

- **90% minimum line coverage** enforced by JaCoCo. The build fails below this threshold.
- Tests live in `src/test/java` in the same module as the code under test.
- Use `InMemorySecretStore` and `CollectingAuditSink` from `tokido-core-test` for unit tests.
- Integration tests that depend on external systems are not part of this repo.
- Test method names describe behavior, not implementation: `enrollStoresAccountName()`, not `testEnroll()`.

---

## CI / GitHub Actions

The workflow runs `mvn verify`, uploads JaCoCo XML to [Codecov](https://codecov.io/gh/tokido-io/tokido-core), and attaches HTML reports as workflow artifacts. The Codecov step uses the `CODECOV_TOKEN` repository secret and fails the job if the upload errors. Connect the GitHub repo in the Codecov UI to enable PR comments and the README coverage badge.

JavaScript actions that run on **Node 24** need a GitHub Actions runner that bundles Node 24 support. **Self-hosted runners** must run [`actions/runner`](https://github.com/actions/runner) **v2.328.0 or newer**; older runners cannot execute those actions. GitHub documents this in the [Node 20 deprecation / Node 24 rollout changelog](https://github.blog/changelog/2025-09-19-deprecation-of-node-20-on-github-actions-runners/).

---

## Adding a new factor provider

1. Create a new module: `tokido-core-yourfactor/`
2. Add `pom.xml` with parent reference and `tokido-core-api` dependency
3. Implement `FactorProvider<YourEnrollmentResult, YourVerificationResult>`
4. Add `YourConfig`, `YourEnrollmentResult`, `YourVerificationResult` following the TOTP module as a reference
5. Write tests using `InMemorySecretStore` and `CollectingAuditSink` — coverage must meet 90%
6. Do **not** set `SecretStore.Metadata.CONFIRMED` in your provider's `store()` call — the engine owns the confirmation lifecycle
7. Use `SecretStore.Metadata` constants for all metadata keys you read or write
8. Add the module to the parent `pom.xml` `<modules>` list
9. Open an issue to discuss the new factor before submitting the PR

---

## Commit messages

Use [Conventional Commits](https://www.conventionalcommits.org/). Each commit should be a single logical change:

```
feat(recovery): support configurable code format (numeric/alphanumeric)

Adds a `codeFormat` option to RecoveryConfig. Defaults to numeric for
backward compatibility.

Closes #42
```

- Subject line: 72 characters max, imperative mood, no period.
- Body: explain *why*, not *what* (the diff shows what).
- Footer: `Closes #N` for issues, `BREAKING CHANGE:` for breaking changes.

---

## Review process

PRs are reviewed by `@tokido-io/maintainers-oss`. Reviews are best-effort — please allow a few business days before pinging.

During review, maintainers may:
- Request changes — address all comments and re-request review.
- Approve and merge — no action needed from you.
- Close without merging — with an explanation. You are welcome to ask questions.

Reviewers follow these principles:
- Comments are about code, not people.
- Blocking comments (must be addressed) are marked as such. Non-blocking suggestions are prefixed with `nit:` or `optional:`.
- Approvals are not given to PRs that break the public contract, lower coverage, or introduce dependencies without prior discussion.

---

## Release process

Releases are cut by maintainers. If you believe a fix or feature is ready for release, comment on the relevant issue or PR.

Releases follow [Semantic Versioning](https://semver.org/):
- **Patch** (`1.0.x`) — bug fixes, documentation, no API changes.
- **Minor** (`1.x.0`) — backward-compatible new features.
- **Major** (`x.0.0`) — breaking changes to public APIs or SecretStore contracts.

Contributors do not need to manage versions or releases.
