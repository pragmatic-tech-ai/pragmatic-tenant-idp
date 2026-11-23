/** How a client of a realm authenticates at the token and revocation endpoints. */
export enum ClientKind
{
    /** Holds a secret (`client_secret_post` / `client_secret_basic`); every client the admin API registers. */
    Confidential = 'confidential',
    /** A native app that cannot keep a secret (RFC 8252): `token_endpoint_auth_method=none`, PKCE S256 always. */
    Public = 'public',
}
