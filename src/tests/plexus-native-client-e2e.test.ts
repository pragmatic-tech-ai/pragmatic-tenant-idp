import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import { createHash, randomBytes } from 'node:crypto';
import { RealmIssuer } from '@pragmatic-tech-ai/pragmatic-identity';
import { CaTrustingHttpClient, RealmTokenVerifier } from '@pragmatic-tech-ai/pragmatic-identity-source-oidc';
import { TenantIdpTestHost } from './tenant-idp-test-host.js';

class NativeFixture
{
    public static readonly Realm = 'acme';
    public static readonly Email = 'ada@acme.example';
    public static readonly Password = 'ada password long enough';
    public static readonly PrincipalId = 'p-ada';
    public static readonly ClientId = 'plexus';
    public static readonly Audience = 'pragmatic-tenant-admin';
    public static readonly Scope = 'openid email profile offline_access';
}

/**
 * Plexus's side of S1-S3 as a native app does it (RFC 8252), over the service in process: discovery, authorize with PKCE
 * through the login API for a local account, the loopback code, the exchange with `none`, the access token verified as
 * the tenant admin console verifies it (`RealmTokenVerifier`: audience the console, authorized party plexus), a
 * refresh, a revocation, and a refresh refused after it.
 */
describe('end to end: plexus as a native client of the realm', () =>
{
    const F = NativeFixture;
    let host: TenantIdpTestHost;
    let verifier: RealmTokenVerifier;

    before(async () =>
    {
        host = await TenantIdpTestHost.Start({ Internal: true });
        await host.Admin('PUT', F.Realm, { displayName: 'Acme' });
        await host.Admin('POST', F.Realm + '/accounts', { email: F.Email, principalId: F.PrincipalId, password: F.Password, displayName: 'Ada' });
        await host.Admin('POST', F.Realm + '/role-mappings', { role: 'admin', member: { kind: 'account', value: F.PrincipalId } });
        verifier = new RealmTokenVerifier({ Issuer: host.Issuer(F.Realm), Audience: [F.Audience], AuthorizedParties: [F.ClientId], Http: new CaTrustingHttpClient(host.Ca) });
    });

    after(async () =>
    {
        await host.Close();
    });

    it('authorizes with PKCE, exchanges with none, verifies the access token, refreshes and revokes', async () =>
    {
        const issuer = host.Issuer(F.Realm);
        const doc = (await host.Http.Send('GET', issuer + RealmIssuer.DiscoveryPath)).Json();
        assert.equal(doc.issuer, issuer);
        assert.ok(doc.token_endpoint_auth_methods_supported.includes('none'));
        assert.equal(new URL(doc.token_endpoint).origin, new URL(issuer).origin, 'a desktop is named the public token endpoint');

        const loopback = 'http://127.0.0.1:61234/pragmatic-desktop/callback';
        const verifierText = randomBytes(32).toString('base64url');
        const state = randomBytes(8).toString('hex');
        const nonce = randomBytes(8).toString('hex');
        const authorize = new URL(doc.authorization_endpoint);
        authorize.search = new URLSearchParams({
            response_type: 'code', client_id: F.ClientId, redirect_uri: loopback, scope: F.Scope, state, nonce,
            code_challenge: createHash('sha256').update(verifierText).digest('base64url'), code_challenge_method: 'S256',
        }).toString();
        assert.equal((await host.Http.Send('GET', authorize.toString())).Status, 200, 'the login page');
        const login = await host.Http.Send('POST', issuer + RealmIssuer.LoginPath, { Json: { request: authorize.search.slice(1), method: 'password', email: F.Email, password: F.Password }, Headers: { origin: host.BaseUrl } });
        assert.equal(login.Status, 200, login.Text);
        const redirect = new URL(login.Json().redirect);
        assert.equal(redirect.origin + redirect.pathname, loopback);
        assert.equal(redirect.searchParams.get('state'), state);

        const exchanged = await host.Http.Send('POST', doc.token_endpoint, { Form: { grant_type: 'authorization_code', code: redirect.searchParams.get('code')!, code_verifier: verifierText, redirect_uri: loopback, client_id: F.ClientId } });
        assert.equal(exchanged.Status, 200, exchanged.Text);
        const tokens = exchanged.Json();
        const principal = await verifier.Verify(tokens.access_token);
        assert.ok(principal !== undefined, 'the console accepts the access token');
        assert.equal(principal.Subject, F.PrincipalId);
        assert.equal(await verifier.Verify(tokens.id_token), undefined, 'an ID token is not a bearer for the console');

        const refreshed = await host.Http.Send('POST', doc.token_endpoint, { Form: { grant_type: 'refresh_token', refresh_token: tokens.refresh_token, client_id: F.ClientId } });
        assert.equal(refreshed.Status, 200, refreshed.Text);
        const renewed = refreshed.Json();
        assert.ok((await verifier.Verify(renewed.access_token)) !== undefined);

        const revoked = await host.Http.Send('POST', doc.revocation_endpoint, { Form: { token: renewed.refresh_token, token_type_hint: 'refresh_token', client_id: F.ClientId } });
        assert.equal(revoked.Status, 200);
        const refused = await host.Http.Send('POST', doc.token_endpoint, { Form: { grant_type: 'refresh_token', refresh_token: renewed.refresh_token, client_id: F.ClientId } });
        assert.equal(refused.Status, 400);
        assert.equal(refused.Json().error, 'invalid_grant');
    });
});
