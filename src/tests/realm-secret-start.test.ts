import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { AppliedConfiguration, AppliedConfigurationEntries, ComponentStartConfiguration, ConfigurationRuntimeReader, SecretStoreDirectory, type ISecretSource, type IStartProcess } from '@pragmatic-tech-ai/pragmatic-configuration';
import { K8sManifestBuilder, type IdpWorkloadSpec } from '@pragmatic-tech-ai/pragmatic-tenant-plane';
import { IdpMain } from '../idp-main.js';
import { RealmConfigurationReader, type IRealmSecretsHome } from '../realm-configuration-reader.js';
import { TenantIdpComponent } from '../tenant-idp-component.js';
import { TenantIdpSecretsHome } from '../tenant-idp-service.js';

/** The realm's sealed store: what the admin API put for the realm (here a map). */
class RealmStore implements ISecretSource
{
    public constructor(private readonly values: ReadonlyMap<string, string>)
    {
    }

    public Get(reference: string): Promise<string | null>
    {
        return Promise.resolve(this.values.get(reference) ?? null);
    }

    public Put(): Promise<void>
    {
        return Promise.resolve();
    }

    public Delete(): Promise<void>
    {
        return Promise.resolve();
    }
}

class ExitRecorder implements IStartProcess
{
    public Code: number | undefined;
    public Text = '';
    public readonly stderr = { write: (text: string): boolean => { this.Text += text; return true; } };

    public exit(code: number): never
    {
        this.Code = code;
        throw new Error('exit ' + code + ': ' + this.Text);
    }
}

/** The live staff realm (early.10 reinstall): its Google source's client secret is a realm-store reference. */
class LiveRealm
{
    public static readonly Realm = 'pragmatic-001';
    public static readonly Secret = 'google-secret-value-3c1e';
    public static readonly Spec: IdpWorkloadSpec = {
        tenantId: 'pragmatic-001', hiveId: 'default-mvp-hive', image: 'pragmatic-tenant-idp@sha256:' + 'd'.repeat(64), port: 9443,
        adminTokenSecretName: 'pragmatic-idp-pragmatic-001-admin', adminTokenRef: 'admin-token', tlsSecretName: 'pragmatic-idp-pragmatic-001-tls',
        database: { image: 'pragmatic-postgres', secretName: 'pragmatic-idp-pragmatic-001-postgres' },
    };

    public static readonly AdminToken = 'admin-token-value-91f0';

    public static Document(): Record<string, unknown>
    {
        return {
            options: {
                core: { adminToken: 'secret:file/admin-token' },
                google: { clientId: '182218337909-x.apps.googleusercontent.com', clientSecret: 'secret:realm/google-client-secret', hostedDomain: 'pragmatic-tech.ai' },
                local: { lockout: '15m', maxAttempts: 5 },
                tokens: { accessTokenLifetime: '10m', idTokenLifetime: '5m', refreshTokenIdleLifetime: '7d', refreshTokenMaxLifetime: '30d', ssoSessionLifetime: '12h' },
            },
        };
    }

    /** The environment the 0.18 builder renders for the IdP container (its literal values), the mounted paths moved into `folder`. */
    public static Env(folder: string): NodeJS.ProcessEnv
    {
        const items = JSON.parse(new K8sManifestBuilder().RenderIdp(LiveRealm.Spec)).items as Array<{ kind: string; spec?: { template: { spec: { containers: Array<{ name: string; env?: Array<{ name: string; value?: string }> }> } } } }>;
        const container = items.find(i => i.kind === 'Deployment')?.spec?.template.spec.containers.find(c => c.name === 'idp');
        const env: NodeJS.ProcessEnv = {};
        for (const variable of container?.env ?? [])
        {
            if (variable.value !== undefined) env[variable.name] = variable.value;
        }
        assert.ok(env.PRAGMATIC_IDP_SECRETS_DIR !== undefined, 'the builder renders the IdP secrets folder');
        env.PRAGMATIC_IDP_SECRETS_DIR = join(folder, 'store');
        env.PRAGMATIC_CONFIGURATION_FILE = join(folder, 'mount', 'configuration.json');
        env.PRAGMATIC_IDP_CONFIGURATION_DIR = join(folder, 'mount');
        return env;
    }

    /** configuration.json applied for 0.2.0 and the entry prepared for this image's descriptor, as the console wrote them. */
    public static async Mount(folder: string): Promise<void>
    {
        const L = LiveRealm;
        const old = new AppliedConfiguration(L.Realm, TenantIdpComponent.Name, 3, '0.2.0', `sha256:${'0'.repeat(64)}`, L.Document() as never);
        const own = TenantIdpComponent.Descriptor();
        const entry = new AppliedConfiguration(L.Realm, own.Name, 1, own.Version, own.ContentDigest(), L.Document() as never);
        await mkdir(join(folder, 'mount'));
        await writeFile(join(folder, 'mount', 'configuration.json'), old.ToCanonicalJson());
        await writeFile(join(folder, 'mount', AppliedConfigurationEntries.KeyOf(entry.DescriptorDigest)), entry.ToCanonicalJson());
        // The component's own Secret, as mounted at /run/secrets/pragmatic/<component> (store `file`).
        await mkdir(join(folder, 'component', TenantIdpComponent.Name), { recursive: true });
        await writeFile(join(folder, 'component', TenantIdpComponent.Name, 'admin-token'), L.AdminToken);
    }

    public static Secrets(): IRealmSecretsHome
    {
        return { DirectoryFor: async () => new SecretStoreDirectory().Add(TenantIdpSecretsHome.RealmStore, new RealmStore(new Map([['google-client-secret', LiveRealm.Secret]]))) };
    }
}

describe('the realm sign-in service starts on a realm configuration whose secrets live in the realm store', () =>
{
    it('the start step overlays the core options and leaves the realm options (and their realm-store secrets) to the realm reader', async () =>
    {
        const folder = await mkdtemp(join(tmpdir(), 'idp-realm-secret-'));
        try
        {
            await LiveRealm.Mount(folder);
            const env = LiveRealm.Env(folder);
            const process = new ExitRecorder();
            await IdpMain.StartConfiguration(env, process, ComponentStartConfiguration.Stores(TenantIdpComponent.Name, join(folder, 'component')), join(folder, 'run'));
            assert.equal(process.Code, undefined, 'the start was refused: ' + process.Text);
            // The sourced core secret went to its file, behind its _FILE variable.
            assert.equal(await readFile(env.PRAGMATIC_IDP_ADMIN_TOKEN_REF_FILE as string, 'utf8'), LiveRealm.AdminToken);
            // The realm reader reads the folder the service derives (the start step's mount by default), with the realm store
            // alone: it resolves the realm options' secrets, never the core one the start step resolved.
            assert.equal(IdpMain.ConfigurationDirOf({}), dirname(ConfigurationRuntimeReader.DefaultPath));
            const realms = await new RealmConfigurationReader(TenantIdpComponent.Descriptor(), LiveRealm.Secrets()).ReadDirectory(IdpMain.ConfigurationDirOf(env));
            assert.deepEqual(realms.map(r => r.RealmId), [LiveRealm.Realm]);
            assert.equal(realms[0].Configuration.Secret('google', 'clientSecret')?.Reveal(), LiveRealm.Secret);
            assert.equal(realms[0].Configuration.Secret('core', 'adminToken'), undefined);
        }
        finally
        {
            await rm(folder, { recursive: true, force: true });
        }
    });
});
