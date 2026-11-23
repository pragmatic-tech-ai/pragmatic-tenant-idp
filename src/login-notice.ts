/** Why the sign-in page was opened again after an upstream source refused (the notice the page shows). */
export enum LoginNoticeReason
{
    /** The account is not of the source's hosted domain ("Only <domain> accounts can sign in here."). */
    Domain = 'domain',
    /** The account is linked but not active in the realm ("This account can't sign in here."). */
    Inactive = 'inactive',
    /** The round trip did not complete: a bad or expired state, a failed code exchange, a refusal at the upstream. */
    Incomplete = 'incomplete',
}

/**
 * The notice an upstream source's callback hands the realm's sign-in page when it sends the browser back to the
 * original authorize request: a marker parameter on that request (`pragmatic_notice=<reason>.<source>`). The marker is
 * never part of the OIDC request (`Strip` takes it out before validation) and carries no text: the reason is one of a
 * fixed set and the source must be one of the realm's, so the page only ever shows its own known messages.
 */
export class LoginNotice
{
    public static readonly MarkerParam = 'pragmatic_notice';
    private static readonly Separator = '.';
    private static readonly ParamSeparator = '&';
    private static readonly ValueSeparator = '=';
    private static readonly NoText = '';
    private static readonly Reasons: ReadonlySet<string> = new Set(Object.values(LoginNoticeReason));

    public constructor(public readonly Reason: LoginNoticeReason, public readonly SourceId: string | undefined)
    {
        Object.freeze(this);
    }

    /** The notice a request's query carries; undefined without a marker or with one this service did not write. */
    public static FromQuery(query: string): LoginNotice | undefined
    {
        const value = new URLSearchParams(query).get(LoginNotice.MarkerParam);
        if (value === null)
        {
            return undefined;
        }
        const at = value.indexOf(LoginNotice.Separator);
        const reason = at < 0 ? value : value.slice(0, at);
        const source = at < 0 ? LoginNotice.NoText : value.slice(at + 1);
        if (!LoginNotice.Reasons.has(reason))
        {
            return undefined;
        }
        return new LoginNotice(reason as LoginNoticeReason, source === LoginNotice.NoText ? undefined : source);
    }

    /** The query without the marker; unchanged (byte for byte) when it carries none. */
    public static Strip(query: string): string
    {
        const params = new URLSearchParams(query);
        if (!params.has(LoginNotice.MarkerParam))
        {
            return query;
        }
        params.delete(LoginNotice.MarkerParam);
        return params.toString();
    }

    /** The same notice keeping its source only when `known` says it is one of the realm's. */
    public Within(known: (sourceId: string) => boolean): LoginNotice
    {
        return this.SourceId === undefined || known(this.SourceId) ? this : new LoginNotice(this.Reason, undefined);
    }

    /** `query` (a validated request, without a marker) with this notice's marker appended. */
    public AppendTo(query: string): string
    {
        const L = LoginNotice;
        const value = this.SourceId === undefined ? this.Reason : this.Reason + L.Separator + this.SourceId;
        const marker = encodeURIComponent(L.MarkerParam) + L.ValueSeparator + encodeURIComponent(value);
        return query === L.NoText ? marker : query + L.ParamSeparator + marker;
    }
}
