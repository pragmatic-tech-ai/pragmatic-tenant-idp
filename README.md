# pragmatic-tenant-idp

The realm sign-in service: an OpenID Connect provider for one or more realms, with its own Postgres, its sign-in app
(`idp-login/`) and its container image `ghcr.io/pragmatic-tech-ai/pragmatic-tenant-idp` (linux/amd64 + linux/arm64).
Split out of pragmatic-server; see `ARCHITECTURE.md`.

## Configuration

The service reads `PRAGMATIC_IDP_*` (declared in `src/tenant-idp-component.ts`). At start the mounted
`pragmatic-config-pragmatic-tenant-idp` file (the tenant admin console's applied configuration) is laid over the `core`
variables; one the service cannot start with exits 78 with the reason. The per-realm options in the same folder are
read by `RealmConfigurationReader`. A configured admin token is read from `PRAGMATIC_IDP_ADMIN_TOKEN_REF_FILE`.

## Build and test

Packages come from GitHub Packages (`.npmrc`, token in `NODE_AUTH_TOKEN`, `read:packages`).

```
npm ci
npm run build
npm test                       # src/**/*.test.ts and tests/*.test.ts; live Postgres cases with PRAGMATIC_TEST_PG_URL
npm run typecheck
npx pragmatic-closure-check    # closure.json against what the entry reaches
npm --prefix idp-login ci && npm --prefix idp-login test
```

## Image

```
NPMRC_FILE=$HOME/.npmrc docker buildx bake -f docker-bake.hcl --allow=fs.read=$HOME/.npmrc components
NPMRC_FILE=$HOME/.npmrc VERSION=0.1.0 GIT_SHA=$(git rev-parse HEAD) docker buildx bake -f docker-bake.hcl \
  -f .components/docker-bake.components.json --allow=fs.read=$HOME/.npmrc pragmatic-tenant-idp
```

CI (`.github/workflows/ci.yml`) and the image release on a `v<version>` tag (`release.yml`) run pragmatic-shared's
reusable container workflows. The image, its configuration (`PRAGMATIC_IDP_*`) and its component descriptor are
unchanged from pragmatic-server.
