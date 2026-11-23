import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { SettingType } from '@pragmatic-tech-ai/pragmatic-component';
import { AppliedConfiguration, ComponentStartConfiguration, type IStartProcess } from '@pragmatic-tech-ai/pragmatic-configuration';
import { IdpMain } from '../idp-main.js';
import { TenantIdpComponent } from '../tenant-idp-component.js';

class IdpStart
{
    public static Env(path: string): NodeJS.ProcessEnv
    {
        return { PRAGMATIC_CONFIGURATION_FILE: path, PRAGMATIC_IDP_BASE_URL: 'https://idp.env.test', PRAGMATIC_IDP_PORT: '7100', PRAGMATIC_IDP_ADMIN_TOKEN_REF: 'admin-token' };
    }

    public static async InFolder(body: (folder: string) => Promise<void>): Promise<void>
    {
        const folder = await mkdtemp(join(tmpdir(), 'idp-start-'));
        try
        {
            await body(folder);
        }
        finally
        {
            await rm(folder, { recursive: true, force: true });
        }
    }

    public static async Configuration(folder: string, core: Record<string, unknown>): Promise<string>
    {
        const d = TenantIdpComponent.Descriptor();
        const path = join(folder, 'configuration.json');
        await writeFile(path, new AppliedConfiguration('acme', d.Name, 1, d.Version, d.ContentDigest(), { options: { core } } as never).ToCanonicalJson());
        return path;
    }
}

class ExitRecorder implements IStartProcess
{
    public Code: number | undefined;
    public readonly stderr = { write: (): boolean => true };

    public exit(code: number): never
    {
        this.Code = code;
        throw new Error('exit');
    }
}

describe('the realm sign-in service reads its core configuration at start', () =>
{
    const Core = { baseUrl: 'https://idp.configured.test', port: 7443, adminToken: 'secret:file/admin-tokens' };

    it('a mounted configuration overrides the declared variable before the settings are read', async () =>
    {
        await IdpStart.InFolder(async folder =>
        {
            const env = IdpStart.Env(await IdpStart.Configuration(folder, Core));
            await writeFile(join(folder, 'admin-tokens'), 'token-a\ntoken-b\n');
            await ComponentStartConfiguration.Apply({ Declaration: TenantIdpComponent.Declaration, Env: env, Stores: ComponentStartConfiguration.Stores('', folder), SecretsDir: join(folder, 'run') });
            assert.deepEqual([env.PRAGMATIC_IDP_BASE_URL, env.PRAGMATIC_IDP_PORT], ['https://idp.configured.test', '7443']);
            assert.equal(env.PRAGMATIC_IDP_ADMIN_TOKEN_REF, undefined, 'the configured token wins over the deployment\'s ref');
            assert.deepEqual(IdpMain.AdminTokensOf(env, join(folder, 'data')), ['token-a', 'token-b']);
        });
    });

    it('no configuration starts as before', async () =>
    {
        await IdpStart.InFolder(async folder =>
        {
            const env = IdpStart.Env(join(folder, 'absent.json'));
            assert.equal((await ComponentStartConfiguration.ApplyOrExit({ Declaration: TenantIdpComponent.Declaration, Env: env })).Applied, false);
            assert.equal(env.PRAGMATIC_IDP_BASE_URL, 'https://idp.env.test');
            assert.equal(IdpMain.AdminTokensOf(env, join(folder, 'data')), undefined, 'no token file under the data folder: admin is off');
        });
    });

    it('an invalid configuration exits with the start error code 78 and the reason', async () =>
    {
        await IdpStart.InFolder(async folder =>
        {
            const process = new ExitRecorder();
            const env = IdpStart.Env(await IdpStart.Configuration(folder, { ...Core, port: 'not-a-port' }));
            await assert.rejects(ComponentStartConfiguration.ApplyOrExit({ Declaration: TenantIdpComponent.Declaration, Env: env }, process));
            assert.equal(process.Code, 78);
        });
    });

    it('every list setting reads the JSON array encoding', () =>
    {
        const core = TenantIdpComponent.Declaration.options.find(o => o.name === 'core');
        assert.deepEqual(core?.settings.filter(s => s.type === SettingType.List && s.source !== undefined), [], 'the core option has no list read from a variable; realm lists are read from the document');
    });
});
