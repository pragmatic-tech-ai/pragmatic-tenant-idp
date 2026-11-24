import { SettingType, type ComponentDescriptor, ComponentDeclarations, type ComponentDeclaration, type OptionDeclaration } from '@pragmatic-tech-ai/pragmatic-component';
import { RealmSourceKind, TenantIdpOptions as O } from './tenant-idp-options.js';

/**
 * The component descriptor of the realm sign-in service image (`pragmatic-tenant-idp`). Its options are a realm's
 * configuration document (one per realm, read at start from its applied configuration file by `RealmConfigurationReader`):
 * token lifetimes and the realm's identity sources, every secret a `SecretReference`. It declares no `core` option: what
 * `IdpMain` reads from its environment is all the platform's (a realm document naming `core` is refused, RealmSettings).
 *
 * Only what a tenant may tune is declared. What binds the service to the platform's manifests and to the trust the
 * console is injected with is the platform's, left out of the descriptor so no configuration can set it (C3.1 Ledger,
 * platform-owned settings): its origins (`baseUrl`, `internalUrl`: every realm's issuer, which the console's injected
 * browser URL signs in against), its listener (`host`, `port`, `tls`, proxy trust), its folders (data, sign-in app,
 * configuration, realm secrets, application descriptors, the bootstrap realm file), the admin token the console's
 * injected token file must match, the Secure cookie flag (the service is always behind TLS: off is only a downgrade), and
 * the database URL. A value of one of these that starts and passes /healthz but is
 * wrong would lock the tenant out of sign-in, and with it out of the console that would repair it.
 */
export class TenantIdpComponent
{
    public static readonly Name = 'pragmatic-tenant-idp';
    /** The descriptor version: this application's package version (the release test pins it to package.json). */
    public static readonly Version = '0.2.6';

    private static readonly Tokens: OptionDeclaration = {
        name: O.Tokens,
        description: 'Token and session lifetimes of the realm.',
        settings: [
            { name: O.IdTokenLifetime, type: SettingType.Duration, default: O.DefaultIdTokenLifetime, description: 'How long an ID token (and an opaque access token issued with it) is valid.' },
            { name: O.AccessTokenLifetime, type: SettingType.Duration, default: O.DefaultAccessTokenLifetime, description: 'How long a JWT access token (a client with a resource audience, such as plexus) is valid: 1m to 60m.' },
            { name: O.RefreshTokenIdleLifetime, type: SettingType.Duration, default: O.DefaultRefreshTokenIdleLifetime, description: 'How long a refresh token is valid unused (each refresh rotates it).' },
            { name: O.RefreshTokenMaxLifetime, type: SettingType.Duration, default: O.DefaultRefreshTokenMaxLifetime, description: 'How long refreshing can go on after the sign-in.' },
            { name: O.SsoSessionLifetime, type: SettingType.Duration, default: O.DefaultSsoSessionLifetime, description: 'How long the login domain\'s single sign-on session re-authenticates silently.' },
        ],
    };

    private static readonly Local: OptionDeclaration = {
        name: RealmSourceKind.Local,
        description: 'Local accounts of the realm (email and password, provisioned by the tenant admin).',
        settings: [
            { name: O.MaxAttempts, type: SettingType.Integer, default: O.DefaultMaxAttempts, description: 'Failed sign-ins of one account from one address before it locks.' },
            { name: O.Lockout, type: SettingType.Duration, default: O.DefaultLockout, description: 'How long a locked sign-in stays locked.' },
        ],
    };

    private static readonly Google: OptionDeclaration = {
        name: RealmSourceKind.Google,
        description: 'Sign in with Google (an OAuth client of the tenant\'s Google Cloud project).',
        settings: [
            { name: O.ClientId, type: SettingType.String, required: true, description: 'The OAuth client id.' },
            { name: O.ClientSecret, type: SettingType.String, required: true, secret: true, description: 'The OAuth client secret.' },
            { name: O.HostedDomain, type: SettingType.String, description: 'Only accounts of this Google Workspace domain sign in (the hd claim).' },
        ],
    };

    private static readonly Entra: OptionDeclaration = {
        name: RealmSourceKind.Entra,
        description: 'Sign in with Microsoft Entra ID (an app registration of the tenant\'s directory).',
        settings: [
            { name: O.TenantId, type: SettingType.String, required: true, description: 'The directory (tenant) id.' },
            { name: O.ClientId, type: SettingType.String, required: true, description: 'The application (client) id.' },
            { name: O.ClientSecret, type: SettingType.String, required: true, secret: true, description: 'The client secret.' },
        ],
    };

    private static readonly Oidc: OptionDeclaration = {
        name: RealmSourceKind.Oidc,
        description: 'Sign in with any OpenID Connect provider.',
        settings: [
            { name: O.Issuer, type: SettingType.Url, required: true, description: 'The provider\'s issuer.' },
            { name: O.DiscoveryUrl, type: SettingType.Url, description: 'The discovery document (default <issuer>/.well-known/openid-configuration).' },
            { name: O.ClientId, type: SettingType.String, required: true, description: 'The client id.' },
            { name: O.ClientSecret, type: SettingType.String, required: true, secret: true, description: 'The client secret.' },
            { name: O.Scopes, type: SettingType.List, default: [...O.DefaultOidcScopes], description: 'The scopes asked for.' },
            { name: O.GroupsClaim, type: SettingType.String, default: O.DefaultGroupsClaim, description: 'The ID token claim listing the person\'s groups.' },
            { name: O.Label, type: SettingType.String, description: 'The sign-in button\'s text.' },
            { name: O.CaBundleFile, type: SettingType.String, description: 'A PEM CA bundle file trusted besides the public roots (a provider on a private CA).' },
        ],
    };

    private static readonly Pragmatic: OptionDeclaration = {
        name: RealmSourceKind.Pragmatic,
        description: 'Sign in with Pragmatic (the central login as an OpenID Connect upstream).',
        settings: [
            { name: O.ClientId, type: SettingType.String, required: true, description: 'The client id registered at the central login.' },
            { name: O.ClientSecret, type: SettingType.String, required: true, secret: true, description: 'The client secret.' },
            { name: O.Issuer, type: SettingType.Url, description: 'The central realm\'s issuer (default https://login.pragmatic-tech.ai/realms/central).' },
            { name: O.CaBundleFile, type: SettingType.String, description: 'A PEM CA bundle file trusted besides the public roots (a development central login).' },
        ],
    };

    private static readonly IdentityPlatform: OptionDeclaration = {
        name: RealmSourceKind.IdentityPlatform,
        description: 'Google Identity Platform accounts (the central realm): email and password with sign-up and a verified email, Google accounts.',
        settings: [
            { name: O.ProjectId, type: SettingType.String, required: true, description: 'The Google Cloud project.' },
            { name: O.ApiKey, type: SettingType.String, required: true, secret: true, description: 'The browser API key the login page uses (public by design, restricted by referrer and API).' },
            { name: O.Providers, type: SettingType.List, default: [...O.DefaultProviders], description: 'The Identity Platform providers accepted: password, google.com.' },
            { name: O.TenantId, type: SettingType.String, description: 'The Identity Platform tenant, when the project uses multi-tenancy.' },
            { name: O.MaxAuthAge, type: SettingType.Duration, default: O.DefaultMaxAuthAge, description: 'How old an Identity Platform sign-in may be when the page posts its token.' },
            { name: O.AuthDomain, type: SettingType.String, description: 'The Identity Platform auth domain (default <projectId>.firebaseapp.com).' },
        ],
    };

    /** The declaration: the descriptor, and the variable the start step overlays each configured `core` setting onto. */
    public static readonly Declaration: ComponentDeclaration = {
        name: TenantIdpComponent.Name,
        version: TenantIdpComponent.Version,
        options: [
            TenantIdpComponent.Tokens,
            TenantIdpComponent.Local,
            TenantIdpComponent.Google,
            TenantIdpComponent.Entra,
            TenantIdpComponent.Oidc,
            TenantIdpComponent.Pragmatic,
            TenantIdpComponent.IdentityPlatform,
        ],
        roles: [],
        postgres: true,
        ports: [{ name: 'https', number: 7100 }],
        health: { port: 'https', path: '/healthz' },
    };

    public static Descriptor(): ComponentDescriptor
    {
        return ComponentDeclarations.Build(TenantIdpComponent.Declaration);
    }
}
