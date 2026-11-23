import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import { RealmIssuer } from '@pragmatic-tech-ai/pragmatic-identity';
import { TenantIdpTestHost } from './tenant-idp-test-host.js';

class OriginFixture
{
    public static readonly Realm = 'tenant-o';
}

describe('discovery by request origin (S3)', () =>
{
    const F = OriginFixture;
    let split: TenantIdpTestHost;
    let single: TenantIdpTestHost;

    before(async () =>
    {
        split = await TenantIdpTestHost.Start({ Internal: true });
        single = await TenantIdpTestHost.Start();
        await split.Admin('PUT', F.Realm, { displayName: F.Realm });
        await single.Admin('PUT', F.Realm, { displayName: F.Realm });
    });

    after(async () =>
    {
        await split.Close();
        await single.Close();
    });

    it('discovery read on the public host names public token, keys and revocation endpoints', async () =>
    {
        const issuer = split.Issuer(F.Realm);
        const doc = (await split.Http.Send('GET', issuer + RealmIssuer.DiscoveryPath)).Json();
        assert.equal(doc.issuer, issuer);
        assert.equal(doc.token_endpoint, issuer + RealmIssuer.TokenPath);
        assert.equal(doc.jwks_uri, issuer + RealmIssuer.CertsPath);
        assert.equal(doc.revocation_endpoint, issuer + RealmIssuer.RevocationPath);
        assert.equal(doc.authorization_endpoint, issuer + RealmIssuer.AuthorizePath);
        assert.equal(doc.end_session_endpoint, issuer + RealmIssuer.LogoutPath);
    });

    it('discovery read on the internal host names internal ones, and the issuer is identical in both', async () =>
    {
        const issuer = split.Issuer(F.Realm);
        const internal = RealmIssuer.Of(split.InternalUrl!, F.Realm);
        const doc = (await split.Http.Send('GET', internal + RealmIssuer.DiscoveryPath)).Json();
        assert.equal(doc.issuer, issuer);
        assert.equal(doc.token_endpoint, internal + RealmIssuer.TokenPath);
        assert.equal(doc.jwks_uri, internal + RealmIssuer.CertsPath);
        assert.equal(doc.revocation_endpoint, internal + RealmIssuer.RevocationPath);
        assert.equal(doc.authorization_endpoint, issuer + RealmIssuer.AuthorizePath, 'the browser is always sent to the public origin');
        assert.equal(doc.end_session_endpoint, issuer + RealmIssuer.LogoutPath);
        assert.equal((await split.Http.Send('GET', doc.jwks_uri)).Status, 200, 'the internal keys answer');
    });

    it('an unknown Host is refused before discovery', async () =>
    {
        const refused = await split.Http.Send('GET', split.Issuer(F.Realm) + RealmIssuer.DiscoveryPath, { Headers: { host: 'evil.example' } });
        assert.equal(refused.Status, 403);
        assert.ok(!refused.Text.includes('token_endpoint'));
    });

    it('a Host the allow-list admits but that is neither origin is named the public endpoints', async () =>
    {
        const port = new URL(split.BaseUrl).port;
        const doc = (await split.Http.Send('GET', split.Issuer(F.Realm) + RealmIssuer.DiscoveryPath, { Headers: { host: `127.0.0.1:${Number(port) + 1}` } })).Json();
        assert.equal(doc.token_endpoint, split.Issuer(F.Realm) + RealmIssuer.TokenPath);
    });

    it('with no internal URL both are the base', async () =>
    {
        const issuer = single.Issuer(F.Realm);
        const port = new URL(single.BaseUrl).port;
        const onBase = (await single.Http.Send('GET', issuer + RealmIssuer.DiscoveryPath)).Json();
        const onLoopback = (await single.Http.Send('GET', issuer + RealmIssuer.DiscoveryPath, { Headers: { host: `127.0.0.1:${port}` } })).Json();
        assert.equal(onBase.token_endpoint, issuer + RealmIssuer.TokenPath);
        assert.equal(onLoopback.token_endpoint, issuer + RealmIssuer.TokenPath);
        assert.equal(onLoopback.issuer, issuer);
    });
});
