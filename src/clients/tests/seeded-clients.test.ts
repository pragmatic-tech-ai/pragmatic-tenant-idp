import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { ClientKind } from '../client-kind.js';
import { SeededClients } from '../seeded-clients.js';

class SeededFixture
{
    public static readonly RealmA = 'tenant-a';
    public static readonly RealmB = 'tenant-b';
}

describe('the seeded clients', () =>
{
    const F = SeededFixture;

    it('plexus is a public client of every realm, the same everywhere but its realm', () =>
    {
        const a = SeededClients.Of(F.RealmA, 'plexus');
        const b = SeededClients.Of(F.RealmB, 'plexus');
        assert.ok(a !== undefined && b !== undefined);
        assert.equal(a.Kind, ClientKind.Public);
        assert.equal(a.IsPublic, true);
        assert.equal(a.RealmId, F.RealmA);
        assert.equal(b.RealmId, F.RealmB);
        assert.deepEqual(a.RedirectUris, b.RedirectUris);
        assert.deepEqual(a.RedirectUris, ['http://127.0.0.1/pragmatic-desktop/callback']);
        assert.deepEqual(a.PostLogoutRedirectUris, []);
        assert.equal(a.ResourceAudience, 'pragmatic-tenant-admin');
        assert.equal(a.SecretHash, '');
    });

    it('accepts the loopback callback on any port and nothing else', () =>
    {
        const plexus = SeededClients.Of(F.RealmA, 'plexus')!;
        assert.equal(plexus.RedirectAllowed('http://127.0.0.1:53682/pragmatic-desktop/callback'), true);
        assert.equal(plexus.RedirectAllowed('http://127.0.0.1:1/pragmatic-desktop/callback'), true);
        assert.equal(plexus.RedirectAllowed('http://localhost:53682/pragmatic-desktop/callback'), false);
        assert.equal(plexus.RedirectAllowed('http://127.0.0.1:53682/other'), false);
        assert.equal(plexus.RedirectAllowed('https://127.0.0.1:53682/pragmatic-desktop/callback'), false);
        assert.equal(plexus.RedirectAllowed('http://127.0.0.1:53682/pragmatic-desktop/callback?x=1'), false);
        assert.equal(plexus.RedirectAllowed('http://evil.example/pragmatic-desktop/callback'), false);
    });

    it('knows only its own ids', () =>
    {
        assert.equal(SeededClients.IsSeeded('plexus'), true);
        assert.equal(SeededClients.IsSeeded('console'), false);
        assert.equal(SeededClients.IsSeeded('Plexus'), false);
        assert.equal(SeededClients.Of(F.RealmA, 'console'), undefined);
    });
});
