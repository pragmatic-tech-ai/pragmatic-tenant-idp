// Top-level navigation away from the sign-in page (to the application's
// redirect, an upstream source's broker login, or a federated provider).
// Injected so tests capture where the page went without a DOM.
export interface IPageNavigator
{
    Assign(url: string): void
    // Replaces the address bar's URL without navigating (same origin only).
    Replace(url: string): void
}

export class BrowserPageNavigator implements IPageNavigator
{
    private static readonly NoTitle = ''

    public Assign(url: string): void
    {
        window.location.assign(url)
    }

    public Replace(url: string): void
    {
        window.history.replaceState(window.history.state, BrowserPageNavigator.NoTitle, url)
    }
}
