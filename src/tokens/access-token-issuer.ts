import { randomBytes, randomUUID } from 'node:crypto';
import type { OidcClient } from '../clients/oidc-client.js';
import type { IdpRealm } from '../idp-realm.js';
import type { IdpSigningKey } from '../idp-signing-key.js';
import type { RealmSignIn } from '../realm-sign-in.js';
import { JwtHeaderType } from './jwt-header-type.js';

/** An access token and how long it is valid (the token answer's `expires_in`). */
export class IssuedAccessToken
{
    public constructor(public readonly Token: string, public readonly ExpiresIn: number)
    {
        Object.freeze(this);
    }
}

/**
 * A realm's access tokens. For a client that names a resource audience (`plexus` -> `pragmatic-tenant-admin`), an
 * RFC 9068 JWT signed with the realm key: header `typ: at+jwt` and the key's `kid`; claims `iss`, `sub` (the realm
 * account), `aud` (the resource), `azp` and `client_id` (the client), `iat`, `exp` (the realm's access token lifetime,
 * so `expires_in` = `exp - iat`), a random `jti`, `sid` (the refresh-token family: stable across renewals, so a
 * resource can end everything of one sign-in), `email` and the role claims resolved at this issue. For any other
 * client, the opaque random token no resource server reads, valid as long as the ID token issued with it.
 */
export class AccessTokenIssuer
{
    private static readonly IssClaim = 'iss';
    private static readonly SubClaim = 'sub';
    private static readonly AudClaim = 'aud';
    private static readonly AzpClaim = 'azp';
    private static readonly ClientIdClaim = 'client_id';
    private static readonly IatClaim = 'iat';
    private static readonly ExpClaim = 'exp';
    private static readonly JtiClaim = 'jti';
    private static readonly SidClaim = 'sid';
    private static readonly EmailClaim = 'email';
    private static readonly OpaqueBytes = 32;
    private static readonly OpaqueEncoding = 'base64url';

    public constructor(private readonly signingKey: IdpSigningKey)
    {
    }

    /**
     * The access token of one exchange or refresh: `iat` in seconds, `roleClaims` the `roles` / `app_roles` payload the
     * ID token carries too, `familyId` the refresh family the token answer belongs to.
     */
    public async Issue(realm: IdpRealm, client: OidcClient, signIn: RealmSignIn, roleClaims: Record<string, unknown>, familyId: string, iat: number): Promise<IssuedAccessToken>
    {
        const A = AccessTokenIssuer;
        const tokens = realm.Settings.Tokens;
        if (client.ResourceAudience === undefined)
        {
            return new IssuedAccessToken(randomBytes(A.OpaqueBytes).toString(A.OpaqueEncoding), tokens.IdTokenSeconds);
        }
        const lifetime = tokens.AccessTokenSeconds;
        const claims: Record<string, unknown> = {
            [A.IssClaim]: realm.Issuer,
            [A.SubClaim]: signIn.AccountId,
            [A.AudClaim]: client.ResourceAudience,
            [A.AzpClaim]: client.ClientId,
            [A.ClientIdClaim]: client.ClientId,
            [A.IatClaim]: iat,
            [A.ExpClaim]: iat + lifetime,
            [A.JtiClaim]: randomUUID(),
            [A.SidClaim]: familyId,
            [A.EmailClaim]: signIn.Email,
            ...roleClaims,
        };
        return new IssuedAccessToken(await this.signingKey.Sign(claims, JwtHeaderType.AccessToken), lifetime);
    }
}
