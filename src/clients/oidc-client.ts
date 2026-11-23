import { ClientKind } from './client-kind.js';

/**
 * A client of a realm: a registered confidential one (holds only the secret's hash, never the secret) or a seeded
 * public one (no secret; `SeededClients`). A client naming a resource audience gets JWT access tokens for that
 * resource (RFC 9068); any other gets the opaque access token no resource server reads.
 */
export class OidcClient
{
    public constructor(
        public readonly ClientId: string,
        public readonly RealmId: string,
        public readonly RedirectUris: readonly string[],
        public readonly PostLogoutRedirectUris: readonly string[],
        public readonly SecretHash: string,
        public readonly Kind: ClientKind = ClientKind.Confidential,
        public readonly ResourceAudience: string | undefined = undefined)
    {
        Object.freeze(this);
    }

    public get IsPublic(): boolean
    {
        return this.Kind === ClientKind.Public;
    }

    /**
     * Exact string equality against the registered allowlist (no prefix, normalization or query tolerance), plus the
     * RFC 8252 section 7.3 loopback rule: a registered portless http://127.0.0.1 URI matches the identical URI on any
     * port 1-65535.
     */
    public RedirectAllowed(redirectUri: string): boolean
    {
        return this.RedirectUris.includes(redirectUri) || this.RedirectUris.some(registered => LoopbackRedirect.Matches(registered, redirectUri));
    }

    /** A post-logout redirect must be registered as one, or be one of the client's redirect URIs (exactly). */
    public PostLogoutAllowed(uri: string): boolean
    {
        return this.PostLogoutRedirectUris.includes(uri) || this.RedirectUris.includes(uri);
    }
}

/** RFC 8252 section 7.3: the loopback redirect of a native client matches on any port. */
class LoopbackRedirect
{
    private static readonly LoopbackScheme = 'http:';
    private static readonly LoopbackHost = '127.0.0.1';
    private static readonly LoopbackOrigin = 'http://127.0.0.1';
    private static readonly NoPort = '';
    private static readonly PortMark = ':';
    private static readonly QueryMark = '?';
    private static readonly FragmentMark = '#';
    private static readonly MinPort = 1;
    private static readonly MaxPort = 65535;

    public static Matches(registered: string, presented: string): boolean
    {
        const L = LoopbackRedirect;
        if (!registered.startsWith(L.LoopbackOrigin) || presented.includes(L.QueryMark) || presented.includes(L.FragmentMark))
        {
            return false;
        }
        try
        {
            const reg = new URL(registered);
            const pres = new URL(presented);
            if (reg.protocol !== L.LoopbackScheme || reg.hostname !== L.LoopbackHost || reg.port !== L.NoPort || registered.startsWith(L.LoopbackOrigin + L.PortMark))
            {
                return false;
            }
            const port = Number(pres.port);
            if (!Number.isInteger(port) || port < L.MinPort || port > L.MaxPort)
            {
                return false;
            }
            // Byte-identical path: URL parsing would otherwise fold dot segments and escapes into a false match.
            return presented === L.LoopbackOrigin + L.PortMark + pres.port + registered.slice(L.LoopbackOrigin.length);
        }
        catch
        {
            return false;
        }
    }
}
