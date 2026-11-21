import { ContainerComponentSource, ReleaseApp } from '@pragmatic-tech-ai/pragmatic-release-toolkit';
import { TenantIdpComponent } from './tenant-idp-component.js';

/**
 * This repository's one component, as `pragmatic-component-descriptors --components dist/release-components.js` reads
 * it (the image build's component stages): the realm sign-in service's descriptor.
 */
export const Components = new ContainerComponentSource(ReleaseApp.TenantIdp, () => TenantIdpComponent.Descriptor());
