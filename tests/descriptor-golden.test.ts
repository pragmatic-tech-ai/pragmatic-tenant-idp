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
 * the one pragmatic-server pinned before the split: same JSON, same digest, so the platform release signs the same
 * component.
 */
class DescriptorGoldenFixture
{
    private static readonly Here = dirname(fileURLToPath(import.meta.url));
    /** pragmatic-server's pin (src/idp/tests/tenant-idp-component.test.ts and admin/control-plane/descriptors/digests.json). */
    public static readonly Digest = 'sha256:95021d7f98dcf5820ba1fe8a860cb76485a3d618fb77bff464174c4840227a67';
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
    it('is the pragmatic-server golden: JSON and digest', () =>
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
