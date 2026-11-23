import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { AppliedConfiguration, AppliedConfigurationEntries, ComponentStartConfiguration, ConfigurationStartError, ConfigurationStartReason, SecretStoreDirectory } from '@pragmatic-tech-ai/pragmatic-configuration';
import { RealmConfigurationReader, type IRealmSecretsHome } from '../realm-configuration-reader.js';
import { TenantIdpComponent } from '../tenant-idp-component.js';

/** A realm whose configuration was applied for the previous release's descriptor, with an entry prepared for this one. */
class PreparedRealm
{
    public static readonly Realm = 'pragmatic-001';
    public static readonly OldDigest = `sha256:${'0'.repeat(64)}`;
    public static readonly Document = { options: { local: { maxAttempts: 5 } } };

    public static Old(version = 3): AppliedConfiguration
    {
        return new AppliedConfiguration(PreparedRealm.Realm, TenantIdpComponent.Name, version, '0.2.0', PreparedRealm.OldDigest, PreparedRealm.Document as never);
    }

    public static Prepared(version = 4): AppliedConfiguration
    {
        const d = TenantIdpComponent.Descriptor();
        return new AppliedConfiguration(PreparedRealm.Realm, d.Name, version, d.Version, d.ContentDigest(), { options: { local: { maxAttempts: 7 } } } as never);
    }

    public static Secrets(): IRealmSecretsHome
    {
        return { DirectoryFor: async () => new SecretStoreDirectory() };
    }

    /** The mounted ConfigMap folder: configuration.json, and the prepared entry when given. */
    public static async InFolder(withEntry: boolean, body: (folder: string) => Promise<void>): Promise<void>
    {
        const folder = await mkdtemp(join(tmpdir(), 'idp-prepared-'));
        try
        {
            await writeFile(join(folder, 'configuration.json'), PreparedRealm.Old().ToCanonicalJson());
            if (withEntry)
            {
                const entry = PreparedRealm.Prepared();
                await writeFile(join(folder, AppliedConfigurationEntries.KeyOf(entry.DescriptorDigest)), entry.ToCanonicalJson());
            }
            await body(folder);
        }
        finally
        {
            await rm(folder, { recursive: true, force: true });
        }
    }
}

describe('the realm sign-in service upgraded onto a new descriptor', () =>
{
    it('reads the entry prepared for its own descriptor, once per realm (the entry is never taken for another realm file)', async () =>
    {
        await PreparedRealm.InFolder(true, async folder =>
        {
            const realms = await new RealmConfigurationReader(TenantIdpComponent.Descriptor(), PreparedRealm.Secrets()).ReadDirectory(folder);
            assert.deepEqual(realms.map(r => r.RealmId), [PreparedRealm.Realm]);
            assert.equal(realms[0].Configuration.Version, 4);
            assert.equal(realms[0].Configuration.Value('local', 'maxAttempts'), 7);
        });
    });

    it('the start step reads the same entry', async () =>
    {
        await PreparedRealm.InFolder(true, async folder =>
        {
            const env: NodeJS.ProcessEnv = { PRAGMATIC_CONFIGURATION_FILE: join(folder, 'configuration.json') };
            const report = await ComponentStartConfiguration.Apply({ Declaration: TenantIdpComponent.Declaration, Env: env, SecretsDir: join(folder, 'run') });
            assert.equal(report.Version, 4);
        });
    });

    it('without a prepared entry it still refuses the configuration validated for another descriptor', async () =>
    {
        await PreparedRealm.InFolder(false, async folder =>
        {
            const reader = new RealmConfigurationReader(TenantIdpComponent.Descriptor(), PreparedRealm.Secrets());
            await assert.rejects(reader.ReadDirectory(folder), (error: unknown) => error instanceof ConfigurationStartError && error.Reason === ConfigurationStartReason.DescriptorMismatch);
        });
    });
});
