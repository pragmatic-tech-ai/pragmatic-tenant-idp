/**
 * What a browser sees when an upstream source's callback cannot be tied back to a sign-in this service began (no or an
 * unknown state, a browser that did not begin it, a request no longer valid, an unknown realm or source): a small
 * static page, never JSON. It renders nothing from the request, so nothing upstream-provided can reach it. It links
 * nowhere: the realm has no page of its own to start from (an authorize request needs the application's PKCE and
 * state), so it sends the person back to the application they came from.
 */
export class SignInFailurePage
{
    public static readonly Title = 'Sign-in couldn\'t be completed';
    public static readonly WhatToDo = 'What to do';
    public static readonly Advice = 'Go back to the application you came from and sign in again from there.';
    private static readonly Html = '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        + '<meta name="viewport" content="width=device-width, initial-scale=1">'
        + '<title>' + SignInFailurePage.Title + '</title>'
        + '<style>'
        + 'html,body{margin:0;height:100%;background:#0f1115;color:#e6e8ec;font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}'
        + 'main{max-width:420px;margin:15vh auto 0;padding:24px;border:1px solid #2a2f3a;background:#161a21;border-radius:8px}'
        + 'h1{font-size:20px;margin:0 0 8px}h2{font-size:15px;margin:16px 0 4px}p{margin:0;color:#a9afbb}'
        + '</style></head><body><main>'
        + '<h1>' + SignInFailurePage.Title + '</h1>'
        + '<h2>' + SignInFailurePage.WhatToDo + '</h2>'
        + '<p>' + SignInFailurePage.Advice + '</p>'
        + '</main></body></html>';

    /** The page document (always the same). */
    public static Render(): string
    {
        return SignInFailurePage.Html;
    }
}
