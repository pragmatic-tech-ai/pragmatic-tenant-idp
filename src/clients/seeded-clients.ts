import { OidcClient } from './oidc-client.js';
import { ClientKind } from './client-kind.js';

/**
 * The clients every realm has without registration: properties of the service, one id everywhere, never stored, never
 * removable, never registered over (E spec section 1). Today one: `plexus`, the Plexus desktop (a public native client
 * on the RFC 8252 loopback redirect, any port), whose access tokens are for the tenant admin console.
 */
export class SeededClients
{
    public static readonly PlexusClientId = 'plexus';
    /** Registered portless: the loopback rule accepts it on any port (RFC 8252 section 7.3). */
    public static readonly PlexusRedirect = 'http://127.0.0.1/pragmatic-desktop/callback';
    /** The resource server Plexus's access tokens are for (their `aud`). */
    public static readonly TenantAdminAudience = 'pragmatic-tenant-admin';
    private static readonly NoSecret = '';
    /** The one home of the seeded ids: each id and how its client of a realm is built. */
    private static readonly Seeds: ReadonlyMap<string, (realmId: string) => OidcClient> = new Map([
        [SeededClients.PlexusClientId, (realmId: string) => SeededClients.Plexus(realmId)],
    ]);

    /** The seeded client of that id in the realm, or undefined when the id is not seeded. */
    public static Of(realmId: string, clientId: string): OidcClient | undefined
    {
        return SeededClients.Seeds.get(clientId)?.(realmId);
    }

    /** Whether the id belongs to a seeded client (reserved: the admin API cannot register or remove it). */
    public static IsSeeded(clientId: string): boolean
    {
        return SeededClients.Seeds.has(clientId);
    }

    private static Plexus(realmId: string): OidcClient
    {
        const S = SeededClients;
        return new OidcClient(S.PlexusClientId, realmId, [S.PlexusRedirect], [], S.NoSecret, ClientKind.Public, S.TenantAdminAudience);
    }
}
