// Where the sign-in page was served and for what: the realm issuer's path
// (the page's path without the authorize suffix), the OIDC authorize request
// (the page's query without its `?`), and the two parameters the page itself
// reads from that request: `prompt=create` (open in sign-up mode) and
// `login_hint` (prefill the email). The IdP's notice marker
// (`pragmatic_notice`, set when an upstream source sent the person back) is
// never part of the request: it is dropped here, so no post, broker link or
// round trip built from the location carries it.
export class LoginPageLocation
{
    public static readonly AuthorizeSuffix = '/protocol/openid-connect/auth'
    // Where a federated provider returns the browser: one path for every realm of the login domain (the redirect URI
    // registered with the provider's OAuth client), served as this page without validating anything; the realm and the
    // authorize request come back from the round-trip storage.
    public static readonly HandlerPath = '/__/auth/handler'
    private static readonly LoginSuffix = '/login'
    private static readonly ConfigSuffix = '/login/config'
    private static readonly QueryMark = '?'
    private static readonly PromptParam = 'prompt'
    private static readonly PromptCreate = 'create'
    private static readonly PromptSeparator = ' '
    private static readonly LoginHintParam = 'login_hint'
    public static readonly NoticeParam = 'pragmatic_notice'
    private static readonly NoText = ''

    private constructor(
        public readonly Origin: string,
        public readonly IssuerPath: string,
        public readonly Request: string,
        /** The page's full URL as the browser shows it (what a federated provider answered to). */
        public readonly Href: string,
        /** True when the page's query carried the IdP's notice marker (dropped from Request). */
        public readonly CarriedNotice: boolean = false)
    {
    }

    // The location of a page served at `origin` + `pathname` + `search`.
    public static From(origin: string, pathname: string, search: string): LoginPageLocation
    {
        const L = LoginPageLocation
        return LoginPageLocation.FromHref(origin, pathname, search, origin + pathname + search)
    }

    // As From, keeping the full URL the browser shows (a provider's answer may be in its fragment).
    public static FromHref(origin: string, pathname: string, search: string, href: string): LoginPageLocation
    {
        const L = LoginPageLocation
        const issuer = pathname.endsWith(L.AuthorizeSuffix) ? pathname.slice(0, pathname.length - L.AuthorizeSuffix.length) : pathname
        const request = search.startsWith(L.QueryMark) ? search.slice(1) : search
        const stripped = L.WithoutNotice(request)
        return new LoginPageLocation(origin, issuer, stripped, href, stripped !== request)
    }

    public static FromWindow(): LoginPageLocation
    {
        return LoginPageLocation.FromHref(window.location.origin, window.location.pathname, window.location.search, window.location.href)
    }

    // The page served at the federated return handler (its realm is not in its path).
    public get IsFederatedReturn(): boolean
    {
        return this.IssuerPath === LoginPageLocation.HandlerPath
    }

    // The same page under the realm the round trip began in.
    public WithIssuer(issuerPath: string): LoginPageLocation
    {
        return new LoginPageLocation(this.Origin, issuerPath, this.Request, this.Href, this.CarriedNotice)
    }

    // The same page for another authorize request (the original one, restored after a round trip).
    public WithRequest(request: string): LoginPageLocation
    {
        return new LoginPageLocation(this.Origin, this.IssuerPath, LoginPageLocation.WithoutNotice(request), this.Href)
    }

    // The request without the notice marker; unchanged when it carries none.
    public static WithoutNotice(request: string): string
    {
        const params = new URLSearchParams(request)
        if (!params.has(LoginPageLocation.NoticeParam))
        {
            return request
        }
        params.delete(LoginPageLocation.NoticeParam)
        return params.toString()
    }

    // The page's own query, as `location.search` reports it.
    public get Search(): string
    {
        return this.Request === LoginPageLocation.NoText ? LoginPageLocation.NoText : LoginPageLocation.QueryMark + this.Request
    }

    // `GET` here answers what the realm's page offers.
    public get ConfigPath(): string
    {
        return this.IssuerPath + LoginPageLocation.ConfigSuffix
    }

    // `POST` (JSON) here signs in.
    public get LoginPath(): string
    {
        return this.IssuerPath + LoginPageLocation.LoginSuffix
    }

    // The absolute authorize URL with this request: the page itself.
    public get AuthorizeUrl(): string
    {
        return this.Origin + this.IssuerPath + LoginPageLocation.AuthorizeSuffix + this.Search
    }

    // Where a federated provider sends the browser back (the page, never the authorize endpoint).
    public get ContinueUrl(): string
    {
        return this.Origin + LoginPageLocation.HandlerPath
    }

    // True when the request carries `prompt=create` (OpenID Connect Initiating User Registration).
    public get PromptsCreate(): boolean
    {
        const prompt = this.Params().get(LoginPageLocation.PromptParam) ?? LoginPageLocation.NoText
        return prompt.split(LoginPageLocation.PromptSeparator).includes(LoginPageLocation.PromptCreate)
    }

    // The request's `login_hint`, or '' without one.
    public get LoginHint(): string
    {
        return this.Params().get(LoginPageLocation.LoginHintParam) ?? LoginPageLocation.NoText
    }

    private Params(): URLSearchParams
    {
        return new URLSearchParams(this.Request)
    }
}
