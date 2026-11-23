import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import { createLocalJWKSet, decodeProtectedHeader, jwtVerify } from 'jose';
import { RealmIssuer } from '@pragmatic-tech-ai/pragmatic-identity';
import { ReservedClientError } from '../sql-idp-client-store.js';
import { IdpTestFlow } from './idp-test-flow.js';
import { RealmTestConfiguration } from './realm-test-configuration.js';
import { TenantIdpTestHost } from './tenant-idp-test-host.js';

class PlexusFixture
{
    public static readonly Realm = 'tenant-x';
    public static readonly Other = 'tenant-y';
    public static readonly Short = 'tenant-short';
    public static readonly Email = 'ada@acme.example';
    public static readonly Password = 'ada password long enough';
    public static readonly PrincipalId = 'p-ada';
    public static readonly ClientId = 'plexus';
    public static readonly Loopback = 'http://127.0.0.1:53682/pragmatic-desktop/callback';
    public static readonly Console = 'console';
    public static readonly ConsoleSecret = 'console-secret';
    public static readonly ConsoleRedirect = 'https://console.example/cb';
    public static readonly Audience = 'pragmatic-tenant-admin';

    public static Claims(token: string): Record<string, any>
    {
        return JSON.parse(Buffer.from(token.split('.')[1]!, 'base64url').toString('utf8')) as Record<string, any>;
    }
}

describe('the seeded public client plexus (S1) and its JWT access tokens (S2)', () =>
{
    const F = PlexusFixture;
    let host: TenantIdpTestHost;
    let plexus: IdpTestFlow;
    let confidential: IdpTestFlow;

    before(async () =>
    {
        const short = RealmTestConfiguration.Of(F.Short, { options: { local: {}, tokens: { accessTokenLifetime: '2m' } } });
        host = await TenantIdpTestHost.Start({ Configurations: [short] });
        for (const realm of [F.Realm, F.Other, F.Short])
        {
            await host.Admin('PUT', realm, { displayName: realm });
            await host.Admin('POST', realm + '/accounts', { email: F.Email, principalId: F.PrincipalId, password: F.Password, displayName: 'Ada' });
        }
        assert.equal((await host.Admin('POST', F.Realm + '/clients', { clientId: F.Console, secret: F.ConsoleSecret, redirectUris: [F.ConsoleRedirect] })).Status, 200);
        plexus = new IdpTestFlow(host, F.Realm, F.ClientId, undefined, F.Loopback);
        confidential = new IdpTestFlow(host, F.Realm, F.Console, F.ConsoleSecret, F.ConsoleRedirect);
    });

    after(async () =>
    {
        await host.Close();
    });

    it('every realm knows plexus without registration', async () =>
    {
        for (const realm of [F.Realm, F.Other])
        {
            const flow = new IdpTestFlow(host, realm, F.ClientId, undefined, F.Loopback);
            assert.equal((await flow.Authorize(flow.Request())).Status, 200, realm);
        }
    });

    it('plexus exchanges a code with token_endpoint_auth_method none and a verifier', async () =>
    {
        const signedIn = await plexus.SignIn(F.Email, F.Password);
        assert.equal(signedIn.Tokens.token_type, 'Bearer');
        assert.equal(typeof signedIn.Tokens.refresh_token, 'string');
        assert.equal(IdpTestFlow.Claims(signedIn.Tokens.id_token).aud, F.ClientId);
        assert.equal(IdpTestFlow.Claims(signedIn.Tokens.id_token).nonce, signedIn.Request.Nonce);
    });

    it('plexus without PKCE S256 gets invalid_request at authorize', async () =>
    {
        const plain = await plexus.Authorize(plexus.Request({ code_challenge_method: 'plain' }));
        assert.equal(plain.Status, 400);
        assert.equal(plain.Json().error, 'invalid_request');
        const none = await plexus.Authorize(plexus.Request({ code_challenge: '' }));
        assert.equal(none.Status, 400);
        assert.equal(none.Json().error, 'invalid_request');
    });

    it('plexus presenting a secret is invalid_client, in the form or as Basic', async () =>
    {
        const request = plexus.Request();
        const login = await plexus.PasswordLogin(request, F.Email, F.Password);
        const code = IdpTestFlow.CodeOf(login.Json().redirect, request);
        const posted = await plexus.Exchange(code, request, 'anything');
        assert.equal(posted.Status, 401);
        assert.equal(posted.Json().error, 'invalid_client');
        const empty = await plexus.Exchange(code, request, '');
        assert.equal(empty.Status, 401);
        const basic = await host.Http.Send('POST', plexus.Issuer + RealmIssuer.TokenPath, {
            Form: { grant_type: 'authorization_code', code, code_verifier: request.Verifier, redirect_uri: F.Loopback },
            Headers: { authorization: 'Basic ' + Buffer.from(F.ClientId + ':').toString('base64') },
        });
        assert.equal(basic.Status, 401);
        assert.equal(basic.Json().error, 'invalid_client');
    });

    it('a confidential client without a secret is still invalid_client', async () =>
    {
        const request = confidential.Request();
        const login = await confidential.PasswordLogin(request, F.Email, F.Password);
        const answered = await host.Http.Send('POST', confidential.Issuer + RealmIssuer.TokenPath, {
            Form: { grant_type: 'authorization_code', code: IdpTestFlow.CodeOf(login.Json().redirect, request), code_verifier: request.Verifier, redirect_uri: F.ConsoleRedirect, client_id: F.Console },
        });
        assert.equal(answered.Status, 401);
        assert.equal(answered.Json().error, 'invalid_client');
        const revoked = await host.Http.Send('POST', confidential.Issuer + RealmIssuer.RevocationPath, { Form: { token: 'x', client_id: F.Console } });
        assert.equal(revoked.Status, 401);
    });

    it('a loopback redirect on any port is accepted for plexus, any other host refused', async () =>
    {
        for (const port of ['1', '49152', '65535'])
        {
            const flow = new IdpTestFlow(host, F.Realm, F.ClientId, undefined, `http://127.0.0.1:${port}/pragmatic-desktop/callback`);
            assert.equal((await flow.Authorize(flow.Request())).Status, 200, port);
        }
        for (const redirect of ['http://localhost:53682/pragmatic-desktop/callback', 'https://evil.example/pragmatic-desktop/callback', 'http://127.0.0.1:53682/elsewhere'])
        {
            const flow = new IdpTestFlow(host, F.Realm, F.ClientId, undefined, redirect);
            const refused = await flow.Authorize(flow.Request());
            assert.equal(refused.Status, 400, redirect);
            assert.equal(refused.Json().error, 'invalid_request');
        }
    });

    it('the admin API cannot register or delete plexus', async () =>
    {
        const registered = await host.Admin('POST', F.Realm + '/clients', { clientId: F.ClientId, secret: 'mine now', redirectUris: ['https://evil.example/cb'] });
        assert.equal(registered.Status, 409);
        assert.equal(registered.Json().error, 'reserved_client');
        const deleted = await host.Admin('DELETE', F.Realm + '/clients/' + F.ClientId);
        assert.equal(deleted.Status, 405);
        assert.equal((await plexus.Authorize(plexus.Request())).Status, 200, 'still seeded');
        const evil = new IdpTestFlow(host, F.Realm, F.ClientId, undefined, 'https://evil.example/cb');
        assert.equal((await evil.Authorize(evil.Request())).Status, 400, 'the refused registration left no redirect behind');
    });

    it('the refresh grant rotates for plexus and a reuse revokes the family', async () =>
    {
        const signedIn = await plexus.SignIn(F.Email, F.Password);
        const first = signedIn.Tokens.refresh_token as string;
        const renewed = await plexus.Refresh(first);
        assert.equal(renewed.Status, 200);
        const second = renewed.Json().refresh_token as string;
        assert.notEqual(second, first);
        const replay = await plexus.Refresh(first);
        assert.equal(replay.Status, 400);
        assert.equal(replay.Json().error, 'invalid_grant');
        assert.equal((await plexus.Refresh(second)).Status, 400, 'the reuse revoked the family');
    });

    it('discovery lists none and offline_access', async () =>
    {
        const doc = (await host.Http.Send('GET', plexus.Issuer + RealmIssuer.DiscoveryPath)).Json();
        assert.ok(doc.token_endpoint_auth_methods_supported.includes('none'));
        assert.ok(doc.token_endpoint_auth_methods_supported.includes('client_secret_basic'));
        assert.ok(doc.scopes_supported.includes('offline_access'));
        assert.deepEqual(doc.code_challenge_methods_supported, ['S256']);
    });

    it('plexus gets an at+jwt verifiable with the realm JWKS, with the contract claims', async () =>
    {
        const signedIn = await plexus.SignIn(F.Email, F.Password);
        const access = signedIn.Tokens.access_token as string;
        assert.equal(decodeProtectedHeader(access).typ, 'at+jwt');
        const jwks = createLocalJWKSet((await host.Http.Send('GET', plexus.Issuer + RealmIssuer.CertsPath)).Json());
        const { payload } = await jwtVerify(access, jwks, { issuer: plexus.Issuer, audience: F.Audience, typ: 'at+jwt' });
        assert.equal(payload.sub, F.PrincipalId);
        assert.equal(payload.azp, F.ClientId);
        assert.equal(payload.client_id, F.ClientId);
        assert.equal(payload.email, F.Email);
        assert.equal(typeof payload.jti, 'string');
        assert.equal(typeof payload.sid, 'string');
        assert.deepEqual(payload.roles ?? [], []);
        assert.equal(signedIn.Tokens.expires_in, payload.exp! - payload.iat!);
        assert.equal(signedIn.Tokens.expires_in, 600);
        assert.notEqual(IdpTestFlow.Claims(signedIn.Tokens.id_token).aud, F.Audience, 'the ID token stays the client\'s');
    });

    it('expires_in equals exp minus iat and follows accessTokenLifetime', async () =>
    {
        const flow = new IdpTestFlow(host, F.Short, F.ClientId, undefined, F.Loopback);
        const signedIn = await flow.SignIn(F.Email, F.Password);
        const claims = F.Claims(signedIn.Tokens.access_token);
        assert.equal(signedIn.Tokens.expires_in, 120);
        assert.equal(claims.exp - claims.iat, 120);
    });

    it('sid is the same after a refresh and jti differs; roles and app_roles follow a mapping change', async () =>
    {
        const signedIn = await plexus.SignIn(F.Email, F.Password);
        const first = F.Claims(signedIn.Tokens.access_token);
        assert.deepEqual(first.roles ?? [], []);
        assert.equal((await host.Admin('POST', F.Realm + '/role-mappings', { role: 'admin', member: { kind: 'account', value: F.PrincipalId } })).Status, 200);
        const renewed = await plexus.Refresh(signedIn.Tokens.refresh_token);
        assert.equal(renewed.Status, 200);
        const next = F.Claims(renewed.Json().access_token);
        assert.equal(next.sid, first.sid);
        assert.notEqual(next.jti, first.jti);
        assert.deepEqual(next.roles, ['admin']);
        const other = await plexus.SignIn(F.Email, F.Password);
        assert.notEqual(F.Claims(other.Tokens.access_token).sid, first.sid, 'another sign-in is another family');
        await host.Admin('DELETE', F.Realm + '/role-mappings', { role: 'admin', member: { kind: 'account', value: F.PrincipalId } });
    });

    it('a confidential client still gets an opaque token', async () =>
    {
        const signedIn = await confidential.SignIn(F.Email, F.Password);
        assert.equal((signedIn.Tokens.access_token as string).split('.').length, 1);
        assert.equal(signedIn.Tokens.expires_in, 300);
    });

    it('revocation with client_id plexus revokes plexus\'s family and ignores another client\'s token', async () =>
    {
        const mine = await plexus.SignIn(F.Email, F.Password);
        const theirs = await confidential.SignIn(F.Email, F.Password);
        const foreign = await plexus.Revoke(theirs.Tokens.refresh_token);
        assert.equal(foreign.Status, 200);
        assert.equal((await confidential.Refresh(theirs.Tokens.refresh_token)).Status, 200, 'another client\'s token is left alone');
        const withSecret = await plexus.Revoke(mine.Tokens.refresh_token, F.ClientId, 'a secret');
        assert.equal(withSecret.Status, 401, 'a public client presenting a secret is refused');
        assert.equal((await plexus.Revoke(mine.Tokens.refresh_token)).Status, 200);
        const refused = await plexus.Refresh(mine.Tokens.refresh_token);
        assert.equal(refused.Status, 400);
        assert.equal(refused.Json().error, 'invalid_grant');
    });

    it('a seeded id is refused before the body is read, and the store never writes or lists it', async () =>
    {
        const invalid = await host.Admin('POST', F.Realm + '/clients', { clientId: F.ClientId });
        assert.equal(invalid.Status, 409);
        const clients = host.Service.Stores.Clients;
        await assert.rejects(clients.Register(F.Realm, F.ClientId, ['https://evil.example/cb'], 'secret'), ReservedClientError);
        assert.equal(await clients.Restore(F.Realm, F.ClientId, ['https://evil.example/cb'], 'hash'), false);
        assert.equal(await clients.Restore(F.Realm, 'imported', ['https://imported.example/cb'], 'hash'), true);
        await host.Session.Execute('INSERT INTO tenant_idp_clients (realm_id, client_id, redirect_uris, post_logout_redirect_uris, secret_hash, updated_at) VALUES ($1, $2, $3, $4, $5, $6)', [F.Other, F.ClientId, '["https://evil.example/cb"]', '[]', 'hash', new Date()]);
        assert.deepEqual((await clients.List(F.Other)).map(client => client.ClientId), [], 'a stored row under a seeded id is never listed');
        assert.equal((await clients.Find(F.Other, F.ClientId))?.IsPublic, true, 'nor found');
        assert.equal(await clients.Remove(F.Other, F.ClientId), false);
    });

    it('a public client presenting any other credential is refused at token and revocation', async () =>
    {
        const signedIn = await plexus.SignIn(F.Email, F.Password);
        const refresh = signedIn.Tokens.refresh_token as string;
        const bearer = await host.Http.Send('POST', plexus.Issuer + RealmIssuer.TokenPath, { Form: { grant_type: 'refresh_token', refresh_token: refresh, client_id: F.ClientId }, Headers: { authorization: 'Bearer ' + signedIn.Tokens.access_token } });
        assert.equal(bearer.Status, 401);
        assert.equal(bearer.Json().error, 'invalid_client');
        const emptySecret = await host.Http.Send('POST', plexus.Issuer + RealmIssuer.RevocationPath, { Form: { token: refresh, client_id: F.ClientId, client_secret: '' } });
        assert.equal(emptySecret.Status, 401);
        const basic = await host.Http.Send('POST', plexus.Issuer + RealmIssuer.RevocationPath, { Form: { token: refresh }, Headers: { authorization: 'Basic ' + Buffer.from(F.ClientId + ':').toString('base64') } });
        assert.equal(basic.Status, 401);
        assert.equal((await plexus.Refresh(refresh)).Status, 200, 'nothing was revoked or spent');
    });

    it('an access token is no id_token_hint: logout with one still asks to confirm', async () =>
    {
        const signedIn = await plexus.SignIn(F.Email, F.Password);
        const hinted = await plexus.Logout(signedIn.Cookie, new URLSearchParams({ id_token_hint: signedIn.Tokens.access_token }).toString());
        assert.equal(hinted.Status, 200);
        assert.ok((hinted.Header('content-type') ?? '').startsWith('text/html'), 'the confirmation page');
        assert.equal((await plexus.Authorize(plexus.Request(), signedIn.Cookie)).Status, 302, 'the SSO session is still live');
        const idHinted = await plexus.Logout(signedIn.Cookie, new URLSearchParams({ id_token_hint: signedIn.Tokens.id_token }).toString());
        assert.equal(idHinted.Json().signedOut, true, 'the ID token ends it at once');
    });
});
