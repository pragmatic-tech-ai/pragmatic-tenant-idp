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
    public static readonly Digest = 'sha256:77cd979c15f71decfebbf9c135b5d545b0255d07b5bed406d1e300678b7cc21f'
    public static readonly Readers = [['..', 'idp-main.ts'], ['..', 'tenant-idp-database.ts']].map(path => join(TenantIdpComponentFixture.Here, ...path))
    /** The file variable the start step sets for the secret setting adminToken (source PRAGMATIC_IDP_ADMIN_TOKEN_REF). */
    public static readonly Undeclared: readonly string[] = ['PRAGMATIC_IDP_ADMIN_TOKEN_REF_FILE', 'PRAGMATIC_IDP_DATABASE_URL_FILE']
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

    it('requires no core setting and holds no database URL: the manifests inject them', () =>
    {
        const core = TenantIdpComponent.Descriptor().Options.find(o => o.Name === 'core')!
        assert.deepEqual(core.Settings.filter(s => s.Required).map(s => s.Name), []);
        assert.equal(core.Settings.some(s => s.Name === 'databaseUrl'), false);
    });

    it('is named for its release image', () =>
    {
        assert.equal(TenantIdpComponent.Descriptor().Name, 'pragmatic-tenant-idp')
    })
})
