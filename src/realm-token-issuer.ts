import { RealmRoleScope } from '@pragmatic-tech-ai/pragmatic-identity-realm';
import type { RealmRoleResolver } from '@pragmatic-tech-ai/pragmatic-identity-realm';
import type { OidcClient } from './clients/oidc-client.js';
import type { IdpRealm } from './idp-realm.js';
import type { IdpSigningKey } from './idp-signing-key.js';
import type { RealmSignIn } from './realm-sign-in.js';
import { AccessTokenIssuer } from './tokens/access-token-issuer.js';

/** The tokens one exchange or refresh issues (the refresh token is added by the token endpoint). */
export class IssuedTokens
{
    public constructor(public readonly IdToken: string, public readonly AccessToken: string, public readonly ExpiresIn: number)
    {
        Object.freeze(this);
    }
}

/**
 * Signs a realm's ID tokens: issuer, audience and authorized party (the client), subject (the realm account), issue,
 * expiry (the realm's ID token lifetime) and authentication times, the nonce of a code exchange (none on refresh, OIDC
 * Core 12.2), email, name, and the role claims `roles` / `app_roles` the realm's role mappings grant this sign-in,
 * resolved once per issue (so a mapping change reaches the next refresh) for both tokens. The access token is the
 * `AccessTokenIssuer`'s: a JWT for a client with a resource audience, else opaque and not stored.
 */
export class RealmTokenIssuer
{
    private static readonly IssClaim = 'iss';
    private static readonly AudClaim = 'aud';
    private static readonly AzpClaim = 'azp';
    private static readonly SubClaim = 'sub';
    private static readonly NonceClaim = 'nonce';
    private static readonly IatClaim = 'iat';
    private static readonly ExpClaim = 'exp';
    private static readonly AuthTimeClaim = 'auth_time';
    private static readonly EmailClaim = 'email';
    private static readonly EmailVerifiedClaim = 'email_verified';
    private static readonly NameClaim = 'name';
    private static readonly MillisPerSecond = 1000;

    private readonly access: AccessTokenIssuer;

    public constructor(
        private readonly signingKey: IdpSigningKey,
        private readonly roles: RealmRoleResolver,
        private readonly now: () => Date = () => new Date())
    {
        this.access = new AccessTokenIssuer(signingKey);
    }

    /** The ID and access tokens of one exchange or refresh of `familyId` (the refresh family the answer belongs to). */
    public async Issue(realm: IdpRealm, client: OidcClient, signIn: RealmSignIn, nonce: string | undefined, familyId: string): Promise<IssuedTokens>
    {
        const T = RealmTokenIssuer;
        const clientId = client.ClientId;
        const iat = Math.floor(this.now().getTime() / T.MillisPerSecond);
        const lifetime = realm.Settings.Tokens.IdTokenSeconds;
        const roleClaims = (await this.roles.Resolve(new RealmRoleScope(realm.Id, realm.Settings.SourceIds()), signIn.Facts())).ToPayload();
        const claims: Record<string, unknown> = {
            [T.IssClaim]: realm.Issuer,
            [T.AudClaim]: clientId,
            [T.AzpClaim]: clientId,
            [T.SubClaim]: signIn.AccountId,
            [T.IatClaim]: iat,
            [T.ExpClaim]: iat + lifetime,
            [T.AuthTimeClaim]: Math.floor(signIn.AuthenticatedAt.getTime() / T.MillisPerSecond),
            [T.EmailClaim]: signIn.Email,
            ...roleClaims,
        };
        if (nonce !== undefined)
        {
            claims[T.NonceClaim] = nonce;
        }
        if (signIn.EmailVerified !== undefined)
        {
            claims[T.EmailVerifiedClaim] = signIn.EmailVerified;
        }
        if (signIn.Name !== '')
        {
            claims[T.NameClaim] = signIn.Name;
        }
        const idToken = await this.signingKey.Sign(claims);
        const access = await this.access.Issue(realm, client, signIn, roleClaims, familyId, iat);
        return new IssuedTokens(idToken, access.Token, access.ExpiresIn);
    }
}
