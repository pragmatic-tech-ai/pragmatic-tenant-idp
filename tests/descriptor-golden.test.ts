import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { ReleaseApp } from '@pragmatic-tech-ai/pragmatic-release-toolkit';
import { Components } from '../src/release-components.js';
import { TenantIdpComponent } from '../src/tenant-idp-component.js';
import { ComponentGolden } from '../src/tests/component-golden.js';

/**
 * The descriptor the image build emits (`pragmatic-component-descriptors --components dist/release-components.js`) is
 * the pinned golden: same JSON, same digest as the fixture, so the platform release signs exactly this component.
 * (pragmatic-server's pin until 0.1.0; from 0.2.0 on, `tokens.accessTokenLifetime` is added, E.s S2.)
 */
class DescriptorGoldenFixture
{
    private static readonly Here = dirname(fileURLToPath(import.meta.url));
    /** The digest of the fixture (also pinned by src/tests/tenant-idp-component.test.ts). */
    public static readonly Digest = 'sha256:b471c1f60f919a8c8393b72950fe2e83ad58d65fbd225feae8fdcc81bb9e0b0a';
    public static readonly Golden = join(DescriptorGoldenFixture.Here, '..', 'src', 'tests', 'fixtures', 'pragmatic-tenant-idp.component.json');
    private static readonly PackageJson = join(DescriptorGoldenFixture.Here, '..', 'package.json');
    private static readonly Utf8 = 'utf8';

    public static PackageVersion(): string
    {
        return (JSON.parse(readFileSync(DescriptorGoldenFixture.PackageJson, DescriptorGoldenFixture.Utf8)) as { version: string }).version;
    }
}

describe('the release descriptor', () =>
{
    it('is the golden: JSON and digest', () =>
    {
        const F = DescriptorGoldenFixture;
        ComponentGolden.Check(Components.Of(ReleaseApp.TenantIdp), F.Golden, F.Digest);
    });

    it('is the one component of this repository', () =>
    {
        const all = Components.All();
        assert.equal(all.length, 1);
        assert.equal(all[0][0], ReleaseApp.TenantIdp);
        assert.equal(all[0][1].ContentDigest(), DescriptorGoldenFixture.Digest);
    });

    it('carries the package version', () =>
    {
        assert.equal(TenantIdpComponent.Version, DescriptorGoldenFixture.PackageVersion());
        assert.equal(Components.Of(ReleaseApp.TenantIdp).Version, DescriptorGoldenFixture.PackageVersion());
    });
});
