import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { ISecretStore } from '@pragmatic-tech-ai/pragmatic-identity';
import { AppliedConfiguration, ConfigurationStartError, ConfigurationStartReason, SecretStoreDirectory } from '@pragmatic-tech-ai/pragmatic-configuration';
import { CloudSecretManagerSecretStore, PgSession, RealmSecretName, RealmSecretsSettings, SqlSecretStore, WorkloadContext } from '@pragmatic-tech-ai/pragmatic-realm-adapters';
import { SqlTestSessions } from '@pragmatic-tech-ai/pragmatic-realm-adapters/testing';
import { RealmConfigurationStart, type IHomeRealmSecrets } from '../realm-configuration-start.js';
import { RealmSecretsImport } from '../realm-secrets-import.js';
import { TenantIdpComponent } from '../tenant-idp-component.js';
import { TenantIdpDatabase } from '../tenant-idp-database.js';
import { TenantIdpSecretsHome } from '../tenant-idp-service.js';
import { TenantIdpTestHost } from './tenant-idp-test-host.js';

/** The hive realm's secrets home in memory; other realms keep the service's own store. `Down` fails as the real home's
 *  open does (a start refusal); `Opens` counts the opens. */
class MemoryRealmHome implements IHomeRealmSecrets
{
    public readonly Store = new CloudSecretManagerSecretStore();
    public Down = false;
    public Opens = 0;

    public constructor(private readonly database: TenantIdpDatabase, public readonly HomeRealm: string = HomeCase.Realm)
    {
    }

    public async RealmStore(realm: string): Promise<ISecretStore>
    {
        if (realm !== this.HomeRealm) return this.database.RealmSecrets(realm, HomeCase.Key);
        this.Opens += 1;
        if (this.Down) throw new ConfigurationStartError(ConfigurationStartReason.SecretsHomeUnavailable, "the realm's secrets home is unavailable: (gcp) unreachable");
        return this.Store;
    }

    public AcceptsName(name: string, realm: string): boolean
    {
        return realm !== this.HomeRealm || RealmSecretName.IsName(name);
    }

    public async DirectoryFor(realm: string): Promise<SecretStoreDirectory>
    {
        return new SecretStoreDirectory().Add(TenantIdpSecretsHome.RealmStore, await this.RealmStore(realm));
    }
}

class HomeCase
{
    public static readonly Key = Buffer.alloc(32, 3);
    public static readonly Realm = 'acme';
    public static readonly OtherRealm = 'staff';
    public static readonly Secret = 'google-client-secret';
    public static readonly Audience = '//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/pragmatic-hives/providers/customer';

    public static Database(): TenantIdpDatabase
    {
        return TenantIdpDatabase.Over(new PgSession(SqlTestSessions.MemPool()));
    }

    /** The hive realm's configuration as the console applies it: the Google source's secret in the realm store. */
    public static async Applied(folder: string, realm: string, clientSecret: string): Promise<string>
    {
        const own = TenantIdpComponent.Descriptor();
        const document = {
            options: {
                google: { clientId: '182218337909-x.apps.googleusercontent.com', clientSecret, hostedDomain: 'pragmatic-tech.ai' },
                local: { lockout: '15m', maxAttempts: 5 },
                tokens: { accessTokenLifetime: '10m', idTokenLifetime: '5m', refreshTokenIdleLifetime: '7d', refreshTokenMaxLifetime: '30d', ssoSessionLifetime: '12h' },
            },
        };
        const applied = new AppliedConfiguration(realm, own.Name, 1, own.Version, own.ContentDigest(), document as never);
        const directory = join(folder, 'configuration');
        await mkdir(directory, { recursive: true });
        await writeFile(join(directory, realm + '.json'), applied.ToCanonicalJson());
        return directory;
    }

    public static Gcp(token: string): Record<string, string>
    {
        return {
            [RealmSecretsSettings.OptionVariable]: 'gcp', [RealmSecretsSettings.VariableOf('projectId')]: 'pragmatic-ops',
            [RealmSecretsSettings.VariableOf('workloadIdentityAudience')]: HomeCase.Audience,
            [WorkloadContext.RealmVariable]: HomeCase.Realm, [WorkloadContext.TokenVariable]: token,
        };
    }

    public static async InFolder(body: (folder: string) => Promise<void>): Promise<void>
    {
        const folder = await mkdtemp(join(tmpdir(), 'idp-home-'));
        try
        {
            await body(folder);
        }
        finally
        {
            await rm(folder, { recursive: true, force: true });
        }
    }
}

describe('the realm secrets home in the realm sign-in service', () =>
{
    it('realm secrets are imported once, idempotently; password hashes stay in the service\'s store', async () =>
    {
        const H = HomeCase;
        const db = H.Database();
        const old = await db.RealmSecrets(H.Realm, H.Key);
        await old.Put(H.Secret, 'client-secret-value');
        await old.Put('entra-client-secret', 'old-entra');
        await old.Put('saml-key', 'same-value');
        await old.Put('idp-password/p-1', 'argon2-hash');
        await old.Put('Legacy.Name', 'kept-here');
        const home = new MemoryRealmHome(db);
        // The console wrote these into the home already: the home's value wins.
        await home.Store.Put('entra-client-secret', 'console-entra');
        await home.Store.Put('saml-key', 'same-value');

        const move = new RealmSecretsImport(db, H.Key, home);
        const [report] = await move.Copy([H.Realm]);
        assert.deepEqual(report!.Copied, [H.Secret]);
        assert.deepEqual(report!.Kept, ['saml-key']);
        assert.deepEqual(report!.Differing, ['entra-client-secret']);
        assert.deepEqual(report!.Skipped, ['Legacy.Name']);
        assert.equal(await home.Store.Get(H.Secret), 'client-secret-value');
        assert.equal(await home.Store.Get('entra-client-secret'), 'console-entra');
        assert.equal(await home.Store.Get('idp-password/p-1'), null, 'password hashes are never moved');
        // Copied, not yet retired: the old rows are there until the configurations resolved from the home.
        assert.equal(await old.Get(H.Secret), 'client-secret-value');
        // A start that failed before Retire copies again, changing nothing.
        const [again] = await new RealmSecretsImport(db, H.Key, home).Copy([H.Realm]);
        assert.deepEqual(again!.Kept, [H.Secret, 'saml-key']);
        // Retired only for a realm whose configuration was read.
        await move.Retire([H.OtherRealm]);
        assert.equal(await old.Get(H.Secret), 'client-secret-value');
        await move.Retire([H.Realm]);
        assert.equal(await old.Get(H.Secret), null);
        assert.equal(await old.Get('entra-client-secret'), null);
        assert.equal(await old.Get('idp-password/p-1'), 'argon2-hash');
        assert.equal(await old.Get('Legacy.Name'), 'kept-here');
        // Done once: a later start moves nothing.
        assert.deepEqual(await new RealmSecretsImport(db, H.Key, home).Copy([H.Realm]), []);
    });

    it('a realm with nothing to move never opens the home', async () =>
    {
        const db = HomeCase.Database();
        const home = new MemoryRealmHome(db);
        home.Down = true;
        await (await db.RealmSecrets(HomeCase.Realm, HomeCase.Key)).Put('idp-password/p-1', 'hash');
        const [report] = await new RealmSecretsImport(db, HomeCase.Key, home).Copy([HomeCase.Realm]);
        assert.deepEqual(report!.Copied, []);
        assert.equal(home.Opens, 0);
    });

    it('the start copies before reading, so a reference resolves from the home; it retires only after the read', async () =>
    {
        await HomeCase.InFolder(async folder =>
        {
            const H = HomeCase;
            const db = H.Database();
            const old = await db.RealmSecrets(H.Realm, H.Key);
            await old.Put(H.Secret, 'client-secret-value');
            const home = new MemoryRealmHome(db);
            const lines: string[] = [];
            const directory = await H.Applied(folder, H.Realm, 'secret:realm/' + H.Secret);
            const [realm] = await new RealmConfigurationStart(home, db, H.Key, line => lines.push(line)).Read(directory, undefined);
            assert.equal(realm!.Configuration.Secret('google', 'clientSecret')?.Reveal(), 'client-secret-value');
            assert.equal(await old.Get(H.Secret), null, 'retired after the read');
            assert.match(lines.join('\n'), /realm secrets of acme: copied into the realm secrets home: google-client-secret/);
            assert.ok(!lines.join('\n').includes('client-secret-value'));
        });
        await HomeCase.InFolder(async folder =>
        {
            const H = HomeCase;
            const db = H.Database();
            const old = await db.RealmSecrets(H.Realm, H.Key);
            await old.Put(H.Secret, 'client-secret-value');
            const home = new MemoryRealmHome(db);
            // The read fails (a reference the home does not hold): nothing is retired.
            const directory = await H.Applied(folder, H.Realm, 'secret:realm/absent-secret');
            await assert.rejects(new RealmConfigurationStart(home, db, H.Key, () => undefined).Read(directory, undefined), (error: Error) => error instanceof ConfigurationStartError && error.Reason === ConfigurationStartReason.SecretMissing);
            assert.equal(await old.Get(H.Secret), 'client-secret-value', 'the old row stays when the read failed');
            assert.equal(await home.Store.Get(H.Secret), 'client-secret-value');
        });
    });

    it('the admin secrets API writes the hive realm\'s secrets to the realm home and other realms\' to its own store', async () =>
    {
        const db = HomeCase.Database();
        const home = new MemoryRealmHome(db);
        const host = await TenantIdpTestHost.Start({ SecretsHome: home, Session: db.Session, MasterKey: HomeCase.Key });
        try
        {
            for (const realm of [HomeCase.Realm, HomeCase.OtherRealm])
            {
                assert.ok((await host.Admin('PUT', realm, { displayName: realm })).Status < 300);
            }
            const put = await host.Admin('PUT', HomeCase.Realm + '/secrets/' + HomeCase.Secret, { value: 'very secret value' });
            assert.equal(put.Status, 200);
            assert.ok(!put.Text.includes('very secret value'));
            assert.equal(await home.Store.Get(HomeCase.Secret), 'very secret value');
            assert.equal(await host.Service.Realms.For(HomeCase.Realm)!.Secrets.Get(HomeCase.Secret), null, 'not in the service\'s own store');
            assert.equal((await host.Admin('PUT', HomeCase.Realm + '/secrets/Google.Secret', { value: 'x' })).Json().error, 'invalid_body', 'a name the home cannot hold');
            // Another realm the service serves keeps its own store, and its names.
            assert.equal((await host.Admin('PUT', HomeCase.OtherRealm + '/secrets/Google.Secret', { value: 'staff-value' })).Status, 200);
            assert.equal(await host.Service.Realms.For(HomeCase.OtherRealm)!.Secrets.Get('Google.Secret'), 'staff-value');
            assert.equal((await host.Admin('DELETE', HomeCase.Realm + '/secrets/' + HomeCase.Secret)).Status, 200);
            assert.equal(await home.Store.Get(HomeCase.Secret), null);

            assert.ok((await host.Admin('POST', HomeCase.Realm + '/accounts', { email: 'max@acme.test', principalId: 'p-max', password: 'correct horse battery', displayName: 'Max' })).Status < 300);
            assert.ok((await host.Service.Realms.For(HomeCase.Realm)!.Secrets.Get('idp-password/p-max'))?.startsWith('$argon2'));
            assert.equal(await home.Store.Get('idp-password/p-max'), null);

            // A home that cannot be opened (the real path's start refusal) is a 503 with a fixed code.
            home.Down = true;
            const down = await host.Admin('PUT', HomeCase.Realm + '/secrets/' + HomeCase.Secret, { value: 'v' });
            assert.equal(down.Status, 503);
            assert.equal(down.Json().error, 'secrets_home_unavailable');
            assert.ok(!down.Text.includes('unreachable'));
        }
        finally
        {
            await host.Close();
        }
    });

    it('the realm store is the realm secrets home for the hive realm only, opened once, when the chart names an option', async () =>
    {
        await HomeCase.InFolder(async folder =>
        {
            const db = HomeCase.Database();
            const own = new TenantIdpSecretsHome(db, HomeCase.Key, undefined, {});
            assert.equal(own.HomeRealm, undefined);
            assert.equal(own.AcceptsName('Legacy.Name', HomeCase.Realm), true);
            assert.ok(await own.RealmStore(HomeCase.Realm) instanceof SqlSecretStore);

            const missing = new TenantIdpSecretsHome(db, HomeCase.Key, undefined, HomeCase.Gcp(join(folder, 'no-token')));
            await assert.rejects(missing.RealmStore(HomeCase.Realm), (error: Error) => error instanceof ConfigurationStartError && /\(gcp\) token-unreadable/.test(error.message), 'the gcp home was chosen and verified');

            // An option without the hive's realm refuses rather than quietly keeping the service's store.
            const noRealm = { ...HomeCase.Gcp(join(folder, 'token')), [WorkloadContext.RealmVariable]: '' };
            assert.throws(() => new TenantIdpSecretsHome(db, HomeCase.Key, undefined, noRealm).HomeRealm, (error: Error) => error instanceof ConfigurationStartError && error.Reason === ConfigurationStartReason.SecretsHomeUnavailable);
            const token = join(folder, 'token');
            await writeFile(token, 'projected.jwt');
            const home = new TenantIdpSecretsHome(db, HomeCase.Key, undefined, HomeCase.Gcp(token));
            assert.equal(home.HomeRealm, HomeCase.Realm);
            assert.equal(home.UsesRealmHome(HomeCase.OtherRealm), false);
            assert.equal(home.AcceptsName('Legacy.Name', HomeCase.Realm), false);
            assert.equal(home.AcceptsName('Legacy.Name', HomeCase.OtherRealm), true);
            assert.ok(await home.RealmStore(HomeCase.OtherRealm) instanceof SqlSecretStore, 'another realm keeps the service\'s store');
            const first = await home.RealmStore(HomeCase.Realm);
            assert.ok(!(first instanceof SqlSecretStore));
            assert.equal(await home.RealmStore(HomeCase.Realm), first, 'opened once');
        });
    });
});
