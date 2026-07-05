# Contributing to MiBee Steward

Thank you for your interest in contributing to MiBee Steward! This project is licensed under the [PolyForm Noncommercial License 1.0.0](https://polyformproject.org/licenses/noncommercial/1.0.0). All contributions come back under the same license.

By submitting a pull request, you certify that you have the right to submit the work and you agree to the project's licensing (DCO-lite sign-off).

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

- `go vet ./...`
- `golangci-lint run` (config in `.golangci.yml`)
- `go test -race -coverprofile=cover.out -covermode=atomic ./...`
- `npm ci && npm test && npm run build` (frontend)
- `sqlc verify`

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
