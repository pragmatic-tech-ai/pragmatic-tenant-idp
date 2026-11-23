// Why the IdP opened the page again after an upstream source signed nobody in
// (the reasons the service's `data-reason` may name; anything else is no notice).
export enum LoginNoticeReason
{
    Domain = 'domain',
    Inactive = 'inactive',
    Incomplete = 'incomplete',
}

// The notice an upstream source's callback left for the page: why, and which
// of the realm's sources (its id; the page takes its label and hosted domain
// from the realm's config, never from the URL).
export class LoginNotice
{
    public constructor(public readonly Reason: LoginNoticeReason, public readonly SourceId: string | undefined)
    {
    }
}

// What the IdP told the page when it served it: a `<meta name="pragmatic-login">`
// whose content is "failed" after a rejected sign-in, "notice" (with
// `data-reason` and `data-source`) when an upstream source sent the person
// back to choose another account, and "ready" otherwise.
export class LoginBootState
{
    public static readonly MetaSelector = 'meta[name="pragmatic-login"]'
    public static readonly FailedValue = 'failed'
    public static readonly NoticeValue = 'notice'
    private static readonly ContentAttribute = 'content'
    private static readonly ReasonAttribute = 'data-reason'
    private static readonly SourceAttribute = 'data-source'
    private static readonly NoText = ''
    private static readonly Reasons: ReadonlySet<string> = new Set(Object.values(LoginNoticeReason))

    private constructor(public readonly Failed: boolean, public readonly Notice: LoginNotice | undefined)
    {
    }

    // The state carried by a meta tag's content; anything but "failed" reads as a fresh page.
    public static FromContent(content: string | null | undefined): LoginBootState
    {
        return new LoginBootState(content === LoginBootState.FailedValue, undefined)
    }

    // The state carried by a meta tag's content and notice attributes: a notice
    // only for "notice" with a known reason.
    public static FromMeta(content: string | null | undefined, reason: string | null | undefined, source: string | null | undefined): LoginBootState
    {
        const B = LoginBootState
        if (content !== B.NoticeValue || reason === null || reason === undefined || !B.Reasons.has(reason))
        {
            return B.FromContent(content)
        }
        const sourceId = source === null || source === undefined || source === B.NoText ? undefined : source
        return new LoginBootState(false, new LoginNotice(reason as LoginNoticeReason, sourceId))
    }

    public static FromDocument(doc: Document): LoginBootState
    {
        const B = LoginBootState
        const meta = doc.querySelector(B.MetaSelector)
        return B.FromMeta(meta?.getAttribute(B.ContentAttribute), meta?.getAttribute(B.ReasonAttribute), meta?.getAttribute(B.SourceAttribute))
    }
}
