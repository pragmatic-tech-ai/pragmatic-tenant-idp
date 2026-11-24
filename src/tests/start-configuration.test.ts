import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ConfigurationValidator, SettingType } from '@pragmatic-tech-ai/pragmatic-component';
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
    it('a mounted realm configuration overlays nothing: the container environment stays the deployment own', async () =>
    {
        await IdpStart.InFolder(async folder =>
        {
            const d = TenantIdpComponent.Descriptor();
            const path = join(folder, 'configuration.json');
            await writeFile(path, new AppliedConfiguration('acme', d.Name, 1, d.Version, d.ContentDigest(), { options: { local: { maxAttempts: 7 } } } as never).ToCanonicalJson());
            const env = IdpStart.Env(path);
            const before = { ...env };
            const report = await ComponentStartConfiguration.Apply({ Declaration: TenantIdpComponent.Declaration, Env: env, Stores: ComponentStartConfiguration.Stores('', folder), SecretsDir: join(folder, 'run') });
            assert.equal(report.Applied, true);
            assert.deepEqual(env, before, 'the wiring stays the deployment own');
        });
    });

    it('the staff realm document as applied on the live hive (google, local, tokens; no core) validates against this descriptor', async () =>
    {
        const live = {
            options: {
                google: { clientId: '182218337909-x.apps.googleusercontent.com', clientSecret: 'secret:realm/google-client-secret', hostedDomain: 'pragmatic-tech.ai' },
                local: { lockout: '15m', maxAttempts: 5 },
                tokens: { accessTokenLifetime: '10m', idTokenLifetime: '5m', refreshTokenIdleLifetime: '7d', refreshTokenMaxLifetime: '30d', ssoSessionLifetime: '12h' },
            },
        };
        const result = new ConfigurationValidator(TenantIdpComponent.Descriptor()).Validate(live);
        assert.equal(result.Valid, true, result.Errors.map(e => e.toString()).join('; '));
    });

    it('a configuration of an earlier version that set its wiring is refused by name, never overlaid', async () =>
    {
        await IdpStart.InFolder(async folder =>
        {
            const process = new ExitRecorder();
            const env = IdpStart.Env(await IdpStart.Configuration(folder, { baseUrl: 'https://idp.configured.test' }));
            await assert.rejects(ComponentStartConfiguration.ApplyOrExit({ Declaration: TenantIdpComponent.Declaration, Env: env }, process));
            assert.equal(process.Code, 78);
            assert.equal(env.PRAGMATIC_IDP_BASE_URL, 'https://idp.env.test');
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
            const env = IdpStart.Env(await IdpStart.Configuration(folder, { secureCookie: false }));
            await assert.rejects(ComponentStartConfiguration.ApplyOrExit({ Declaration: TenantIdpComponent.Declaration, Env: env }, process));
            assert.equal(process.Code, 78);
        });
    });

    it('every list setting reads the JSON array encoding', () =>
    {
        const sourced = TenantIdpComponent.Declaration.options.flatMap(o => o.settings).filter(s => s.type === SettingType.List && s.source !== undefined);
        assert.deepEqual(sourced, [], 'no list is read from a variable; realm lists are read from the document');
    });
});
