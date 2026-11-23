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
    private static readonly SeededIds: ReadonlySet<string> = new Set([SeededClients.PlexusClientId]);
    private static readonly NoSecret = '';

    /** The seeded client of that id in the realm, or undefined when the id is not seeded. */
    public static Of(realmId: string, clientId: string): OidcClient | undefined
    {
        const S = SeededClients;
        if (clientId !== S.PlexusClientId)
        {
            return undefined;
        }
        return new OidcClient(S.PlexusClientId, realmId, [S.PlexusRedirect], [], S.NoSecret, ClientKind.Public, S.TenantAdminAudience);
    }

    /** Whether the id belongs to a seeded client (reserved: the admin API cannot register or remove it). */
    public static IsSeeded(clientId: string): boolean
    {
        return SeededClients.SeededIds.has(clientId);
    }
}
