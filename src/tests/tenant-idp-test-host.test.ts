import assert from 'node:assert/strict';
import { connect } from 'node:net';
import { describe, it } from 'node:test';
import { RealmIssuer } from '@pragmatic-tech-ai/pragmatic-identity';
import { LoopbackForwarder, TenantIdpTestHost } from './tenant-idp-test-host.js';

/** Whether a TCP connection to the loopback port is accepted. */
class LoopbackPort
{
    public static Accepts(port: number): Promise<boolean>
    {
        return new Promise<boolean>(resolve =>
        {
            const socket = connect(port, TenantIdpTestHost.Loopback);
            socket.once('connect', () => { socket.destroy(); resolve(true); });
            socket.once('error', () => resolve(false));
        });
    }
}

describe('the test host reaches itself as localhost (pragmatic-shared 0.18.14 certificates name no IP)', () =>
{
    it('serves its internal origin as localhost on a forwarded port of its own, verified against its CA', async () =>
    {
        const host = await TenantIdpTestHost.Start({ Internal: true });
        try
        {
            const internal = new URL(host.InternalUrl!);
            const base = new URL(host.BaseUrl);
            assert.equal(internal.hostname, TenantIdpTestHost.Localhost);
            assert.equal(base.hostname, TenantIdpTestHost.Localhost);
            assert.notEqual(internal.port, base.port);
            await host.Admin('PUT', 'tenant-h', { displayName: 'h' });
            const doc = (await host.Http.Send('GET', RealmIssuer.Of(host.InternalUrl!, 'tenant-h') + RealmIssuer.DiscoveryPath)).Json();
            assert.equal(doc.issuer, host.Issuer('tenant-h'));
        }
        finally
        {
            await host.Close();
        }
    });

    it('closing the forwarder stops its port', async () =>
    {
        const forwarder = await LoopbackForwarder.Open(1);
        assert.ok(forwarder.Port > 0);
        assert.equal(await LoopbackPort.Accepts(forwarder.Port), true);
        await forwarder.Close();
        assert.equal(await LoopbackPort.Accepts(forwarder.Port), false);
    });
});
