import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { ISecretStore } from '@pragmatic-tech-ai/pragmatic-identity';
import { CloudSecretManagerSecretStore, PgSession, RealmSecretName, RealmSecretsOption, SecretsHomeFailure, SecretsHomeUnavailableError } from '@pragmatic-tech-ai/pragmatic-realm-adapters';
import { SqlTestSessions } from '@pragmatic-tech-ai/pragmatic-realm-adapters/testing';
import { RealmSecretsImport, type IRealmSecretsHomeStores } from '../realm-secrets-import.js';
import { TenantIdpDatabase } from '../tenant-idp-database.js';
import { TenantIdpSecretsHome } from '../tenant-idp-service.js';
import { TenantIdpTestHost } from './tenant-idp-test-host.js';

/** A realm secrets home in memory: one store per realm; `Down` makes every call fail as the home would. */
class MemoryRealmHome implements IRealmSecretsHomeStores
{
    public readonly Stores = new Map<string, CloudSecretManagerSecretStore>();
    public Down = false;

    public async RealmStore(realm: string): Promise<ISecretStore>
    {
        if (this.Down) throw new SecretsHomeUnavailableError(RealmSecretsOption.Gcp, SecretsHomeFailure.Unreachable);
        const store = this.Stores.get(realm) ?? new CloudSecretManagerSecretStore();
        this.Stores.set(realm, store);
        return store;
    }

    public AcceptsName(name: string): boolean
    {
        return RealmSecretName.IsName(name);
    }
}

class HomeCase
{
    public static readonly Key = Buffer.alloc(32, 3);
    public static readonly Realm = 'acme';

    public static Database(): TenantIdpDatabase
    {
        return TenantIdpDatabase.Over(new PgSession(SqlTestSessions.MemPool()));
    }
}

describe('the realm secrets home in the realm sign-in service', () =>
{
    it('realm secrets are imported once, idempotently; password hashes stay in the service\'s store', async () =>
    {
        const H = HomeCase;
        const db = H.Database();
        const old = await db.RealmSecrets(H.Realm, H.Key);
        await old.Put('google-client-secret', 'client-secret-value');
        await old.Put('entra-client-secret', 'old-entra');
        await old.Put('idp-password/p-1', 'argon2-hash');
        await old.Put('Legacy.Name', 'kept-here');
        const home = new MemoryRealmHome();
        // The console wrote this one into the home already: the home's value wins.
        await (await home.RealmStore(H.Realm)).Put('entra-client-secret', 'console-entra');

        const move = new RealmSecretsImport(db, H.Key, home);
        const [report] = await move.Copy([H.Realm]);
        assert.deepEqual(report!.Copied, ['google-client-secret']);
        assert.deepEqual(report!.Kept, ['entra-client-secret']);
        assert.deepEqual(report!.Skipped, ['Legacy.Name']);
        const target = await home.RealmStore(H.Realm);
        assert.equal(await target.Get('google-client-secret'), 'client-secret-value');
        assert.equal(await target.Get('entra-client-secret'), 'console-entra');
        assert.equal(await target.Get('idp-password/p-1'), null, 'password hashes are never moved');
        // Copied, not yet retired: the old rows are there until the configurations resolved from the home.
        assert.equal(await old.Get('google-client-secret'), 'client-secret-value');
        // A start that failed before Retire copies again, changing nothing.
        const [again] = await new RealmSecretsImport(db, H.Key, home).Copy([H.Realm]);
        assert.deepEqual(again!.Kept, ['entra-client-secret', 'google-client-secret']);

        await move.Retire();
        assert.equal(await old.Get('google-client-secret'), null);
        assert.equal(await old.Get('entra-client-secret'), null);
        assert.equal(await old.Get('idp-password/p-1'), 'argon2-hash');
        assert.equal(await old.Get('Legacy.Name'), 'kept-here');
        // Done once: a later start moves nothing.
        assert.deepEqual(await new RealmSecretsImport(db, H.Key, home).Copy([H.Realm]), []);
    });

    it('the admin secrets API writes to the realm home; a seeded password stays in the service\'s store', async () =>
    {
        const home = new MemoryRealmHome();
        const host = await TenantIdpTestHost.Start({ SecretsHome: home });
        try
        {
            assert.ok((await host.Admin('PUT', HomeCase.Realm, { displayName: 'Acme' })).Status < 300);
            const put = await host.Admin('PUT', HomeCase.Realm + '/secrets/google-client-secret', { value: 'very secret value' });
            assert.equal(put.Status, 200);
            assert.ok(!put.Text.includes('very secret value'));
            assert.equal(await (await home.RealmStore(HomeCase.Realm)).Get('google-client-secret'), 'very secret value');
            assert.equal(await host.Service.Realms.For(HomeCase.Realm)!.Secrets.Get('google-client-secret'), null, 'not in the service\'s own store');
            assert.equal((await host.Admin('PUT', HomeCase.Realm + '/secrets/Google.Secret', { value: 'x' })).Json().error, 'invalid_body', 'a name the home cannot hold');
            assert.equal((await host.Admin('DELETE', HomeCase.Realm + '/secrets/google-client-secret')).Status, 200);
            assert.equal(await (await home.RealmStore(HomeCase.Realm)).Get('google-client-secret'), null);

            assert.ok((await host.Admin('POST', HomeCase.Realm + '/accounts', { email: 'max@acme.test', principalId: 'p-max', password: 'correct horse battery', displayName: 'Max' })).Status < 300);
            assert.ok((await host.Service.Realms.For(HomeCase.Realm)!.Secrets.Get('idp-password/p-max'))?.startsWith('$argon2'));
            assert.equal(await (await home.RealmStore(HomeCase.Realm)).Get('idp-password/p-max'), null);

            home.Down = true;
            const down = await host.Admin('PUT', HomeCase.Realm + '/secrets/google-client-secret', { value: 'v' });
            assert.equal(down.Status, 503);
            assert.equal(down.Json().error, 'secrets_home_unavailable');
            assert.ok(!down.Text.includes('unreachable'));
        }
        finally
        {
            await host.Close();
        }
    });

    it('the realm store is the realm secrets home when the chart names an option, else the service\'s own', async () =>
    {
        const db = HomeCase.Database();
        const own = new TenantIdpSecretsHome(db, HomeCase.Key, undefined, {});
        assert.equal(own.UsesRealmHome, false);
        assert.equal(own.AcceptsName('Legacy.Name'), true);
        assert.equal((await own.RealmStore(HomeCase.Realm)).constructor.name, 'SqlSecretStore');
        const folder = await mkdtemp(join(tmpdir(), 'idp-home-'));
        try
        {
            const token = join(folder, 'token');
            await writeFile(token, 'projected.jwt');
            const env = {
                PRAGMATIC_REALM_SECRETS_OPTION: 'gcp', PRAGMATIC_REALM_SECRETS_PROJECT_ID: 'pragmatic-ops',
                PRAGMATIC_REALM_SECRETS_WORKLOAD_IDENTITY_AUDIENCE: '//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/pragmatic-hives/providers/customer',
                PRAGMATIC_REALM_ID: HomeCase.Realm, PRAGMATIC_WORKLOAD_TOKEN_FILE: token,
            };
            const home = new TenantIdpSecretsHome(db, HomeCase.Key, undefined, env);
            assert.equal(home.UsesRealmHome, true);
            assert.equal(home.AcceptsName('Legacy.Name'), false);
            assert.equal((await home.RealmStore('staff')).constructor.name, 'GcpRealmSecretStore');
        }
        finally
        {
            await rm(folder, { recursive: true, force: true });
        }
    });
});
