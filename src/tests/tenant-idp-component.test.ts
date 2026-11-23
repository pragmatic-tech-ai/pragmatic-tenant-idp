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
    public static readonly Digest = 'sha256:0a1e97abda263a1286687f4556b30848192ee7d19ce378bd60f08ec536a96f90'
    public static readonly Readers = [['..', 'idp-main.ts'], ['..', 'tenant-idp-database.ts']].map(path => join(TenantIdpComponentFixture.Here, ...path))
    public static readonly Undeclared: readonly string[] = []
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
