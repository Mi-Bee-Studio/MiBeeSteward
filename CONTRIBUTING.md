# Contributing to MiBee Steward

Thank you for your interest in contributing to MiBee Steward!

## Licensing your contribution

MiBee Steward is distributed under a **dual license**: the open-source [GNU AGPLv3](./LICENSE) plus a separate [commercial license](./LICENSE-COMMERCIAL.md). For this dual licensing to remain possible, every contribution must be covered by two things:

1. **A signed [Contributor License Agreement (CLA)](./CLA.md)** — one-time per contributor (ICLA for individuals, CCLA for companies). The CLA grants Mi-Bee Studio the right to release your contribution under both the AGPLv3 and the commercial license. You keep your copyright.
2. **A per-commit `Signed-off-by` (DCO)** — certifies the *origin* of every commit. Pass `-s` to `git commit`, or see [`.github/DCO.md`](./.github/DCO.md). A CI check (`.github/workflows/dco.yml`) blocks any PR with an unsigned commit.

A pull request cannot be merged until both are in place. See the linked docs for signing instructions.

## Development Workflow — TDD

We follow **Test-Driven Development (TDD)**: Red → Green → Refactor.

1. **Red**: Write a failing test first.
   - Backend: place a `_test.go` file beside the source it tests, using `testify/require`.
   - Frontend: place a `*.test.ts` file in `web/src/__tests__/`.
   - Run the test and confirm it FAILS for the right reason.
2. **Green**: Write the minimum code required to make the test pass.
3. **Refactor**: Clean up the implementation while keeping tests green.

A test that mirrors its implementation (mock-call assertions, pinned constants) is not evidence of correctness. Tests must verify real observable behavior.

## Test Commands

```bash
# Backend (Go)
make test                    # = go test ./...

# Frontend (SvelteKit 5)
cd web && npm test           # = vitest run (single-shot)

# Single frontend test file
cd web && npx vitest run src/__tests__/validation.test.ts
```

## CI Gates

All of the following must pass before a PR can merge (enforced by `.github/workflows/ci.yml`):

- Frontend build (`npm ci && npm run build`) — produces the `web/dist/` artifact the `go` job embeds.
- `go vet ./...`
- `golangci-lint run` (v2, config in `.golangci.yml`)
- `go test -race -coverprofile=cover.out -covermode=atomic ./...`
- Frontend tests (`npm ci && npm test`)
- `sqlc compile` (validates queries against the schema; no sqlc Cloud required)

Coverage is **reported** (artifact uploaded), not hard-gated.

## Branch & Pull Request Process

1. Fork the repo and create a feature branch from `main`.
2. Use [Conventional Commits](https://www.conventionalcommits.org/): `feat:`, `fix:`, `docs:`, `chore:`, `ci:`, `refactor:`.
3. Open a PR against `main` and fill in the [PR template](.github/pull_request_template.md) checklist.
4. Ensure all CI checks pass.
5. Request review from a maintainer.

## sqlc Regeneration Rule

The files under `internal/db/` are **generated** — never edit them by hand. If you change `db/schema.sql` or any file under `db/queries/`, you MUST regenerate:

```bash
sqlc generate
```

Then commit the regenerated `internal/db/*.go` files alongside your schema/query changes.

## Anti-Patterns (project-specific gotchas)

- **CGO-free build**: Never introduce CGO dependencies. SQLite uses `modernc.org/sqlite`. The Makefile sets `CGO_ENABLED=0`.
- **Frontend embed**: Use `//go:embed all:dist` (with the `all:` prefix) in `web/embed.go`. Without `all:`, Go skips `_app/` and the SPA 404s its JS/CSS.
- **Svelte 5 runes**: `$state`/`$derived`/`$effect`/`$props` ONLY in `.svelte` files. In `.ts`/`.js`, use `svelte/store` — the Svelte compiler only transforms `.svelte`.
- **sqlc boundary**: Never edit `internal/db/*.go` directly — edit `db/queries/*.sql` then `sqlc generate`.
- **No secrets**: Never commit secrets, private IPs, or credentials. Use `.env` (gitignored).

## Questions?

Open an issue on [GitHub](https://github.com/Mi-Bee-Studio/MiBeeSteward/issues).
