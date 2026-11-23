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
    public static readonly Digest = 'sha256:b471c1f60f919a8c8393b72950fe2e83ad58d65fbd225feae8fdcc81bb9e0b0a'
    public static readonly Readers = [['..', 'idp-main.ts'], ['..', 'tenant-idp-database.ts']].map(path => join(TenantIdpComponentFixture.Here, ...path))
    /** The file variable the start step sets for the secret setting adminToken (source PRAGMATIC_IDP_ADMIN_TOKEN_REF). */
    public static readonly Undeclared: readonly string[] = ['PRAGMATIC_IDP_ADMIN_TOKEN_REF_FILE']
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

    it('is named for its release image', () =>
    {
        assert.equal(TenantIdpComponent.Descriptor().Name, 'pragmatic-tenant-idp')
    })
})
