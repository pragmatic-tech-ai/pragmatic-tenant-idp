# pragmatic-tenant-idp — Architecture Index

The realm sign-in service, the OIDC provider of the realms, split out of pragmatic-server: pragmatic-server's
`src/idp/` is this repository's `src/`, its `src/bin/pragmatic-idpd.ts` is `src/bin/`, and its `idp-login/` is
`idp-login/`. One container serves one or more realms on `pragmatic-app-host`; every record lives in its own Postgres;
signing key, master key, TLS and admin tokens are secret files in the data folder.

## Entry point and image

- `src/bin/pragmatic-idpd.ts` -> `IdpMain.Run()` (`src/idp-main.ts`); the image's ENTRYPOINT is
  `node dist/bin/pragmatic-idpd.js` under `/workspace/pragmatic-tenant-idp`, port 7100 (`PRAGMATIC_IDP_PORT`), HTTPS
  health probe on `/healthz` (the certificate is issued for the public host, so the probe does not verify the peer).
- The image (`Dockerfile`, `docker-bake.hcl`, rendered by `pragmatic-container-template` of
  `@pragmatic-tech-ai/pragmatic-release-toolkit`) is multi-arch (linux/amd64 + linux/arm64), installs every package from
  GitHub Packages through the lock, builds `idp-login` and copies its `dist` beside the compiled `dist` (`IdpLoginPage`
  resolves `../idp-login/dist` from its module), keeps esbuild and typescript across the prune (TODL declares both as
  runtime dependencies from 0.66.4 on), installs `openssl` (the CA tooling) and carries its component descriptor at
  `/pragmatic/component.json` with the digest as the label `ai.pragmatic-tech.component.digest`.
- `closure.json` lists what the image copies; `npx pragmatic-closure-check` (package.json `pragmaticClosureCheck`)
  keeps it in step with what the entry reaches.
- The descriptor: `TenantIdpComponent` (`src/tenant-idp-component.ts`), exported for the image build as `Components`
  by `src/release-components.ts`; `tests/descriptor-golden.test.ts` pins its digest to pragmatic-server's golden.
  `dist/release-components.js` is read only by the image's component stages; it rides along in the runtime `dist`
  unused (nothing at runtime imports it; the rendered Dockerfile copies the whole `dist`).

## Composition

`IdpMain.Compose(env)` (`idp-main.ts`) -> `TenantIdpService.Open` (`tenant-idp-service.ts`): `TenantIdpDatabase`
(`PRAGMATIC_IDP_DATABASE_URL_FILE`; `Stores()` opens every store, each running its migrations), the pre-A5 file
importer (`TenantIdpImport.ImportIfPending`, dev data only), `RealmConfigurationReader` (applied files of
`PRAGMATIC_IDP_CONFIGURATION_DIR` + `PRAGMATIC_IDP_BOOTSTRAP_REALM_FILE`), `IdpRealmSet` (catalogue + configured
realms), the route table, `AppHost`. `IdpFormRoutes` registers the token and revocation endpoints as `RouteBody.Form`
routes; in a hive the host serves TLS itself (`AppHostConfig.Tls`, the `IdpTlsIdentity` from the data folder).

- **Paths.** `RealmIssuer` (pragmatic-identity) is the one home: issuer `<base>/realms/<realm>`,
  `.../protocol/openid-connect/{auth,token,certs,revoke,logout}`, `.../.well-known/openid-configuration`, `.../login`
  (JSON, the login page) and `.../login/config`, `.../broker/<source>/{login,callback}`; admin
  `/_admin/realms/<realm>/...`; sign-in app assets `/_login/`.
- **Realms and sources.** `RealmSettings` (`realm-settings.ts`) from a realm's configuration (descriptor
  `TenantIdpComponent`, option names in `TenantIdpOptions`): `TokenPolicy`, `LocalPolicy`, `UpstreamSourceSettings`
  (Google / Entra / generic OIDC / Pragmatic -> `UpstreamOidcSource`; its `Complete` answers an `UpstreamSignIn` or a
  typed `UpstreamRefusal` carrying the authorize request whenever the state was valid, which the broker callback turns
  into a redirect back to the sign-in page with a `LoginNotice` marker, else `SignInFailurePage`) and `IdentityPlatformSourceSettings` (->
  `IdentityPlatformSource`). `IdpRealm` holds the local accounts (SQL identity stores, password hashes in the realm's
  `SqlSecretStore` scope `tenant-idp/<realm>`), profiles and federated links (`SqlIdpFederatedAccounts`).
- **Clients.** `OidcClient` (`clients/oidc-client.ts`) has a `ClientKind` (`confidential` | `public`) and an optional
  resource audience. Registered clients (admin API, `SqlIdpClientStore`) are confidential; `SeededClients`
  (`clients/seeded-clients.ts`) are the service's own, consulted before the store, never stored, reserved in the admin
  API (POST 409, DELETE 405): today `plexus`, the Plexus desktop (public, `none` at the token endpoint, PKCE S256, the
  loopback redirect `http://127.0.0.1/pragmatic-desktop/callback` on any port, audience `pragmatic-tenant-admin`).
- **Sign-in and tokens.** `SignInEndpoints` (`authorize-endpoint.ts`), `SignInCompletion` (SSO session + single-use
  code), `TokenEndpoint` / `RevocationEndpoint` (`token-endpoint.ts`: client authentication by kind, code + PKCE,
  rotating refresh tokens with reuse detection; revocation only of the client's own tokens), `ProtocolEndpoints`
  (discovery, JWKS, RP-initiated logout; token, keys and revocation named on the origin the document was read from, base
  or internal), `RealmTokenIssuer` (ID token claims incl. `roles` / `app_roles` from `RealmRoleResolver` at every issue)
  and `AccessTokenIssuer` (`tokens/access-token-issuer.ts`: an RFC 9068 `at+jwt` for a client with a resource audience,
  `sid` = the refresh family, lifetime `tokens.accessTokenLifetime` 1m-60m; opaque otherwise). Stores:
  `SqlIdpClientStore`, `SqlIdpRealmCatalogue`, `SqlIdpAccountProfiles`, `SqlAuthorizationCodeStore`,
  `SqlSsoSessionStore`, `SqlRefreshTokenStore` (migrations in `tenant-idp-migrations.ts`), app-host throttles
  (`IdpLoginThrottles`) and audit.
- **Admin API.** `IdpAdminEndpoint`: realms, accounts, password reset, clients, role mappings and assignable roles
  (`RoleMappingService`), applications (component descriptors; also fed from `PRAGMATIC_IDP_APPLICATIONS_DIR`), realm
  secrets.
- **Sign-in app.** `idp-login/` (own package.json and lock; see its README for the contract with the service).

## Tests

- `src/tests/` with `TenantIdpTestHost` (pg-mem, dev CA, free port) and `IdpTestFlow`; `realm-sign-in-e2e.test.ts`
  drives the app-host `OidcRelyingParty` through local and (fake) Identity Platform sign-ins. The store suites also run
  against a live Postgres when `PRAGMATIC_TEST_PG_URL` is set. `desktop-endpoint.test.ts` and
  `idp-admin-client.test.ts` hold the tenant plane's clients (`@pragmatic-tech-ai/pragmatic-tenant-plane`) to this
  service. `plexus-client.test.ts`, `discovery-origin.test.ts` and `plexus-native-client-e2e.test.ts` hold the
  native-client contract (E.s S1-S3; Plexus's side is its `realm-desktop-contract.test.ts`). `component-golden.ts` /
  `component-sources.ts` are copies of pragmatic-server's component test support.
- `tests/descriptor-golden.test.ts` (the release descriptor is the golden), `tests/singletons.test.ts` (one installed
  copy of todl-runtime, todl and mural).
- `idp-login`: `npm --prefix idp-login test` (unit), `test:e2e` (Playwright, against a fake service).
