import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, before, describe, it } from 'node:test';
import { createLocalJWKSet, decodeProtectedHeader, jwtVerify } from 'jose';
import { ClientKind } from '../../clients/client-kind.js';
import { OidcClient } from '../../clients/oidc-client.js';
import { SeededClients } from '../../clients/seeded-clients.js';
import type { IdpRealm } from '../../idp-realm.js';
import { IdpSigningKey } from '../../idp-signing-key.js';
import { RealmSignIn } from '../../realm-sign-in.js';
import { RealmSettings, TokenPolicy } from '../../realm-settings.js';
import { RealmTestConfiguration } from '../../tests/realm-test-configuration.js';
import { AccessTokenIssuer } from '../access-token-issuer.js';

class AccessFixture
{
    public static readonly Realm = 'tenant-a';
    public static readonly Issuer = 'https://idp.example/realms/tenant-a';
    public static readonly Iat = 1_800_000_000;
    public static readonly Family = 'family-1';
    public static readonly Roles = { roles: ['admin'], app_roles: { ledger: ['viewer'] } };
    public static readonly SignIn = new RealmSignIn('acct-1', 'local', 'acct-1', [], 'ada@acme.example', 'Ada', true, new Date(0));

    public static RealmWith(tokens: TokenPolicy): IdpRealm
    {
        return { Id: AccessFixture.Realm, Issuer: AccessFixture.Issuer, Settings: { Tokens: tokens } } as unknown as IdpRealm;
    }

    public static Claims(token: string): Record<string, unknown>
    {
        return JSON.parse(Buffer.from(token.split('.')[1]!, 'base64url').toString('utf8')) as Record<string, unknown>;
    }

    public static Settings(tokens: Record<string, string>): RealmSettings
    {
        const F = AccessFixture;
        return RealmSettings.From(F.Realm, F.Realm, RealmTestConfiguration.Of(F.Realm, { options: { tokens } }).Configuration);
    }
}

describe('the access token issuer', () =>
{
    const F = AccessFixture;
    let dir: string;
    let key: IdpSigningKey;
    let issuer: AccessTokenIssuer;

    before(async () =>
    {
        dir = mkdtempSync(join(tmpdir(), 'access-token-'));
        key = await IdpSigningKey.LoadOrCreate(join(dir, 'key.pem'));
        issuer = new AccessTokenIssuer(key);
    });

    after(() =>
    {
        rmSync(dir, { recursive: true, force: true });
    });

    it('plexus gets an at+jwt verifiable with the realm JWKS, with the contract claims', async () =>
    {
        const plexus = SeededClients.Of(F.Realm, 'plexus')!;
        const issued = await issuer.Issue(F.RealmWith(TokenPolicy.Default), plexus, F.SignIn, F.Roles, F.Family, F.Iat);
        assert.equal(decodeProtectedHeader(issued.Token).typ, 'at+jwt');
        assert.equal(decodeProtectedHeader(issued.Token).kid, key.Kid());
        const { payload } = await jwtVerify(issued.Token, createLocalJWKSet(key.PublicJwks()), { issuer: F.Issuer, audience: 'pragmatic-tenant-admin', typ: 'at+jwt', currentDate: new Date(F.Iat * 1000) });
        assert.equal(payload.sub, 'acct-1');
        assert.equal(payload.azp, 'plexus');
        assert.equal(payload.client_id, 'plexus');
        assert.equal(payload.sid, F.Family);
        assert.equal(payload.email, 'ada@acme.example');
        assert.deepEqual(payload.roles, ['admin']);
        assert.deepEqual(payload.app_roles, { ledger: ['viewer'] });
        assert.equal(payload.iat, F.Iat);
        assert.equal(typeof payload.jti, 'string');
        assert.equal(issued.ExpiresIn, 600, 'the default lifetime is 10m');
        assert.equal(payload.exp! - payload.iat!, issued.ExpiresIn);
    });

    it('follows the realm lifetime, keeps sid and draws a new jti every time', async () =>
    {
        const plexus = SeededClients.Of(F.Realm, 'plexus')!;
        const policy = new TokenPolicy(5 * 60_000, 60_000, 120_000, 60_000, 2 * 60_000);
        const first = await issuer.Issue(F.RealmWith(policy), plexus, F.SignIn, {}, F.Family, F.Iat);
        const second = await issuer.Issue(F.RealmWith(policy), plexus, F.SignIn, {}, F.Family, F.Iat);
        assert.equal(first.ExpiresIn, 120);
        const a = F.Claims(first.Token);
        const b = F.Claims(second.Token);
        assert.equal((a.exp as number) - (a.iat as number), 120);
        assert.equal(a.sid, b.sid);
        assert.notEqual(a.jti, b.jti);
    });

    it('a client without a resource audience still gets an opaque token, valid as its ID token', async () =>
    {
        const confidential = new OidcClient('console', F.Realm, ['https://console.example/cb'], [], 'hash', ClientKind.Confidential);
        const issued = await issuer.Issue(F.RealmWith(TokenPolicy.Default), confidential, F.SignIn, F.Roles, F.Family, F.Iat);
        assert.equal(issued.Token.split('.').length, 1);
        assert.equal(issued.ExpiresIn, TokenPolicy.Default.IdTokenSeconds);
    });

    it('a realm may set the lifetime from 1m to 60m and no further', () =>
    {
        assert.equal(F.Settings({ accessTokenLifetime: '1m' }).Tokens.AccessTokenSeconds, 60);
        assert.equal(F.Settings({ accessTokenLifetime: '60m' }).Tokens.AccessTokenSeconds, 3600);
        assert.equal(F.Settings({}).Tokens.AccessTokenSeconds, 600);
        assert.throws(() => F.Settings({ accessTokenLifetime: '59s' }), /accessTokenLifetime/);
        assert.throws(() => F.Settings({ accessTokenLifetime: '61m' }), /accessTokenLifetime/);
    });
});
