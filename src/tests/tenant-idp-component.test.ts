import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { TenantIdpComponent } from '../tenant-idp-component.js'
import { ComponentGolden } from './component-golden.js'
import { ComponentSources } from './component-sources.js'

class TenantIdpComponentFixture
{
    public static readonly Here = dirname(fileURLToPath(import.meta.url))
    public static readonly Golden = join(TenantIdpComponentFixture.Here, 'fixtures', 'pragmatic-tenant-idp.component.json')
    public static readonly Digest = 'sha256:9c31901b421be0bcce7e4a96ee05f61a8f05bd7f9a4dcc055f0c1d6eebbc6ace'
    public static readonly Readers = [['..', 'idp-main.ts'], ['..', 'tenant-idp-database.ts']].map(path => join(TenantIdpComponentFixture.Here, ...path))
    /** Platform-owned: injected by the manifests the console and the platform render, never tenant-configurable, by reason. */
    public static readonly PlatformOwned: Readonly<Record<string, readonly string[]>> = {
        // Every realm's issuer is <baseUrl>/realms/<realm>; the console signs in against its injected browser URL.
        'its origins (the issuer the console signs in against)': ['PRAGMATIC_IDP_BASE_URL', 'PRAGMATIC_IDP_INTERNAL_URL'],
        'its listener (the Service, the Ingress and the probe are rendered against it)': ['PRAGMATIC_IDP_HOST', 'PRAGMATIC_IDP_PORT', 'PRAGMATIC_IDP_TLS', 'PRAGMATIC_IDP_TRUSTED_PROXY'],
        'its folders (the mounts the manifests render)': [
            'PRAGMATIC_IDP_DATA', 'PRAGMATIC_IDP_LOGIN_DIR', 'PRAGMATIC_IDP_CONFIGURATION_DIR', 'PRAGMATIC_IDP_BOOTSTRAP_REALM_FILE', 'PRAGMATIC_IDP_SECRETS_DIR', 'PRAGMATIC_IDP_APPLICATIONS_DIR',
        ],
        // The console's injected PRAGMATIC_IDP_ADMIN_TOKEN_FILE holds the token this must match.
        'the admin token the console holds': ['PRAGMATIC_IDP_ADMIN_TOKEN_REF', 'PRAGMATIC_IDP_ADMIN_TOKEN_REF_FILE'],
        'its database': ['PRAGMATIC_IDP_DATABASE_URL_FILE'],
        // Always behind TLS: Secure is the only right value; off would only be a downgrade a tenant could choose.
        'the Secure cookie flag': ['PRAGMATIC_IDP_SECURE_COOKIE'],
    };
    public static readonly Undeclared: readonly string[] = Object.values(TenantIdpComponentFixture.PlatformOwned).flat()
}

describe('TenantIdpComponent', () =>
{
    it('pins the descriptor: golden JSON and content digest', () =>
    {
        ComponentGolden.Check(TenantIdpComponent.Descriptor(), TenantIdpComponentFixture.Golden, TenantIdpComponentFixture.Digest)
    })

    it('declares exactly the variables its configuration readers read', () =>
    {
        ComponentSources.AssertCovers(TenantIdpComponent.Descriptor(), TenantIdpComponentFixture.Readers, TenantIdpComponentFixture.Undeclared)
    })

    it('declares no core option: everything the container reads from its environment is the platform own', () =>
    {
        assert.equal(TenantIdpComponent.Descriptor().Options.some(o => o.Name === 'core'), false);
    });

    it('declares none of its wiring (origins, listener, folders, admin token, cookies), so no configuration can lock the tenant out of sign-in', () =>
    {
        const descriptor = TenantIdpComponent.Descriptor();
        const declared = ComponentSources.Declared(descriptor);
        for (const [reason, variables] of Object.entries(TenantIdpComponentFixture.PlatformOwned))
        {
            assert.deepEqual(variables.filter(v => declared.includes(v)), [], reason);
        }
    });

    it('is named for its release image', () =>
    {
        assert.equal(TenantIdpComponent.Descriptor().Name, 'pragmatic-tenant-idp')
    })
})
