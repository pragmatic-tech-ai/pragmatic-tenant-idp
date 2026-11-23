import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { after, before, describe, it, test } from 'node:test';
import { FakeOidcHttpClient, FakeOidcIdp } from '@pragmatic-tech-ai/pragmatic-identity-source-oidc/testing';
import { FakeIdentityPlatformHttp, FakeIdentityPlatform } from '@pragmatic-tech-ai/pragmatic-identity-source-identity-platform/testing';
import { GoogleIdentityProfile } from '@pragmatic-tech-ai/pragmatic-identity-source-google';
import { RealmIssuer } from '@pragmatic-tech-ai/pragmatic-identity';
import { IdpSourceClients } from '../idp-realm.js';
import { IdpLoginPage } from '../idp-login-page.js';
import { LoginNotice, LoginNoticeReason } from '../login-notice.js';
import { SignInFailurePage } from '../sign-in-failure-page.js';
import { IdpTestFlow, type IdpTestRequest } from './idp-test-flow.js';
import { RealmTestConfiguration } from './realm-test-configuration.js';
import { TenantIdpTestHost, type IdpTestReply } from './tenant-idp-test-host.js';

class RefusalFixture
{
    public static readonly Staff = 'staff';
    public static readonly ClientId = 'cabinet';
    public static readonly Secret = 'cabinet-secret';
    public static readonly Redirect = 'https://cabinet.example/cb';
    public static readonly Domain = 'pragmatic-tech.ai';
    public static readonly GoogleClient = 'google-client';
    public static readonly Index = '<html><head><meta name="pragmatic-login" content="ready"></head><body></body></html>';
}

test('a notice marker round-trips through a query and is stripped from it', () =>
{
    const notice = new LoginNotice(LoginNoticeReason.Domain, 'google');
    const query = notice.AppendTo('response_type=code&prompt=login%20create');
    assert.equal(query, 'response_type=code&prompt=login%20create&pragmatic_notice=domain.google');
    assert.deepEqual(LoginNotice.FromQuery(query), notice);
    assert.equal(LoginNotice.Strip(query), 'response_type=code&prompt=login+create');
    assert.equal(LoginNotice.Strip('response_type=code&prompt=login%20create'), 'response_type=code&prompt=login%20create', 'byte for byte without a marker');
    assert.deepEqual(LoginNotice.FromQuery('pragmatic_notice=incomplete'), new LoginNotice(LoginNoticeReason.Incomplete, undefined));
    assert.equal(LoginNotice.FromQuery('pragmatic_notice=%3Cscript%3E'), undefined, 'an unknown reason is no notice');
    assert.equal(LoginNotice.FromQuery('client_id=c'), undefined);
    assert.equal(notice.Within(() => false).SourceId, undefined, 'a source the realm does not have is dropped');
    assert.equal(notice.Within(id => id === 'google').SourceId, 'google');
});

test('the notice flag carries only escaped attribute values, never markup', () =>
{
    const page = IdpLoginPage.FromHtml(RefusalFixture.Index);
    assert.ok(page.RenderNotice(new LoginNotice(LoginNoticeReason.Domain, 'google')).includes('<meta name="pragmatic-login" content="notice" data-reason="domain" data-source="google">'));
    assert.ok(page.RenderNotice(new LoginNotice(LoginNoticeReason.Inactive, undefined)).includes('<meta name="pragmatic-login" content="notice" data-reason="inactive">'));
    const crafted = page.RenderNotice(new LoginNotice(LoginNoticeReason.Incomplete, '"><script>alert(1)</script>$&'));
    assert.ok(!crafted.includes('<script>'));
    assert.ok(crafted.includes('data-source="&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;$&amp;"'));
    assert.ok(!crafted.includes('content="ready"'));
});

test('the sign-in app reads the same wire values the service writes', () =>
{
    const app = (file: string): string => readFileSync(new URL('../../idp-login/src/' + file, import.meta.url), 'utf8');
    const bootState = app('login-boot-state.ts');
    for (const [name, value] of Object.entries(LoginNoticeReason))
    {
        assert.ok(bootState.includes(name + " = '" + value + "'"), 'the app knows reason ' + value);
    }
    assert.ok(app('login-page-location.ts').includes("NoticeParam = '" + LoginNotice.MarkerParam + "'"));
});

test('the failure page is static HTML that renders nothing from the request', () =>
{
    const html = SignInFailurePage.Render();
    assert.match(html, /^<!doctype html>/);
    assert.ok(html.includes(SignInFailurePage.Title));
    assert.ok(html.includes(SignInFailurePage.WhatToDo));
    assert.ok(html.includes(SignInFailurePage.Advice));
});

/** Drives a Google round trip of the staff realm by hand (the browser's side). */
class GoogleRoundTrip
{
    public constructor(private readonly host: TenantIdpTestHost, private readonly google: FakeOidcIdp, private readonly http: FakeOidcHttpClient, public readonly Flow: IdpTestFlow)
    {
    }

    /** Begins a sign-in for `request`: the upstream authorize URL and the browser's binding cookie. */
    public async Begin(request: IdpTestRequest): Promise<{ Authorize: URL; Binding: string }>
    {
        const begin = await this.host.Http.Send('GET', this.Flow.Issuer + '/broker/google/login?' + request.Query);
        assert.equal(begin.Status, 302);
        return { Authorize: new URL(begin.Header('location')!), Binding: begin.Cookie()! };
    }

    public Callback(query: Record<string, string>, cookie?: string): Promise<IdpTestReply>
    {
        return this.host.Http.Send('GET', this.Flow.Issuer + '/broker/google/callback?' + new URLSearchParams(query).toString(), { Headers: cookie === undefined ? {} : { cookie } });
    }

    /** Begins, has Google answer with an ID token of `claims`, and returns to the callback in the same browser. */
    public async Answer(request: IdpTestRequest, claims: Record<string, unknown>): Promise<IdpTestReply>
    {
        const { Authorize, Binding } = await this.Begin(request);
        await this.NextToken(Authorize, claims);
        return this.Callback({ code: 'google-code', state: Authorize.searchParams.get('state')! }, Binding);
    }

    public async NextToken(authorize: URL, claims: Record<string, unknown>): Promise<void>
    {
        this.http.NextTokenResponse = this.google.TokenResponse(await this.google.MintIdToken({ aud: RefusalFixture.GoogleClient, nonce: authorize.searchParams.get('nonce'), ...claims }));
    }

    /** The callback sent the browser back to the realm's page for `query`, with the notice, and nothing signed in. */
    public static AssertReturned(reply: IdpTestReply, query: string, reason: LoginNoticeReason): string
    {
        assert.equal(reply.Status, 302);
        assert.equal(reply.Header('cache-control'), 'no-store');
        assert.match(reply.Header('set-cookie') ?? '', /idp_broker=; /, 'the binding is cleared');
        assert.doesNotMatch(reply.Header('set-cookie') ?? '', /idp_sso=[^;]/);
        const location = reply.Header('location')!;
        assert.equal(location, '/realms/staff' + RealmIssuer.AuthorizePath + '?' + query + '&pragmatic_notice=' + reason + '.google');
        return location;
    }
}

describe('the realm sign-in service: an upstream source that signs nobody in', () =>
{
    const F = RefusalFixture;
    const R = GoogleRoundTrip;
    let host: TenantIdpTestHost;
    let googleHttp: FakeOidcHttpClient;
    let flow: IdpTestFlow;
    let trip: GoogleRoundTrip;

    before(async () =>
    {
        const platform = await FakeIdentityPlatform.Create();
        const google = await FakeOidcIdp.Create(GoogleIdentityProfile.GoogleIssuer);
        googleHttp = new FakeOidcHttpClient(google);
        const staff = RealmTestConfiguration.Of(F.Staff, {
            options: {
                google: { clientId: F.GoogleClient, clientSecret: 'secret:realm/google', hostedDomain: F.Domain },
                oidc: { issuer: 'https://other.example', discoveryUrl: 'https://other.example/.well-known/openid-configuration', clientId: 'other-client', clientSecret: 'secret:realm/other' },
            },
        }, { [RealmTestConfiguration.Secret('google', 'clientSecret')]: 'google-secret', [RealmTestConfiguration.Secret('oidc', 'clientSecret')]: 'other-secret' }, 'Pragmatic staff');
        host = await TenantIdpTestHost.Start({ Configurations: [staff], SourceClients: new IdpSourceClients(googleHttp, new FakeIdentityPlatformHttp(platform)) });
        assert.equal((await host.Admin('POST', F.Staff + '/clients', { clientId: F.ClientId, secret: F.Secret, redirectUris: [F.Redirect] })).Status, 200);
        flow = new IdpTestFlow(host, F.Staff, F.ClientId, F.Secret, F.Redirect);
        trip = new GoogleRoundTrip(host, google, googleHttp, flow);
    });

    after(async () =>
    {
        await host.Close();
    });

    it('sends an account of another domain back to the sign-in page with the domain notice', async () =>
    {
        const config = (await host.Http.Send('GET', flow.Issuer + RealmIssuer.LoginConfigPath)).Json();
        const sources = new Map((config.sources as Array<{ id: string; hostedDomain: string | null }>).map(source => [source.id, source.hostedDomain]));
        assert.equal(sources.get('google'), F.Domain, 'the page learns the domain from its config, never from the URL');
        assert.equal(sources.get('oidc'), null);
        const request = flow.Request();
        const location = R.AssertReturned(await trip.Answer(request, { sub: 'gmail-1', email: 'someone@gmail.com', name: 'Someone' }), request.Query, LoginNoticeReason.Domain);
        const page = await host.Http.Send('GET', host.BaseUrl + location);
        assert.equal(page.Status, 200, 'the request with its marker still validates and renders the page');
        assert.match(page.Text, /<meta name="pragmatic-login" content="notice" data-reason="domain" data-source="google">/);
        assert.equal(page.Header('cache-control'), 'no-store');
    });

    it('sends an inactive account back with the inactive notice', async () =>
    {
        const claims = { sub: 'staff-1', email: 'grace@pragmatic-tech.ai', name: 'Grace', hd: F.Domain };
        const first = flow.Request();
        const signedIn = await trip.Answer(first, claims);
        assert.equal(signedIn.Status, 302);
        const accountId = IdpTestFlow.Claims((await flow.Exchange(IdpTestFlow.CodeOf(signedIn.Header('location')!, first), first)).Json().id_token).sub as string;
        assert.equal((await host.Admin('POST', F.Staff + '/accounts/' + accountId + '/disable')).Status, 200);
        const request = flow.Request();
        const location = R.AssertReturned(await trip.Answer(request, claims), request.Query, LoginNoticeReason.Inactive);
        assert.match((await host.Http.Send('GET', host.BaseUrl + location)).Text, /data-reason="inactive" data-source="google"/);
    });

    it('sends a failed code exchange back with the incomplete notice and the original request', async () =>
    {
        const request = flow.Request({ login_hint: 'grace@pragmatic-tech.ai' });
        const { Authorize, Binding } = await trip.Begin(request);
        googleHttp.FailTokenEndpoint = true;
        try
        {
            R.AssertReturned(await trip.Callback({ code: 'google-code', state: Authorize.searchParams.get('state')! }, Binding), request.Query, LoginNoticeReason.Incomplete);
        }
        finally
        {
            googleHttp.FailTokenEndpoint = false;
        }
    });

    it('sends an upstream error answer (no code) back with the incomplete notice, and takes its state', async () =>
    {
        const request = flow.Request();
        const { Authorize, Binding } = await trip.Begin(request);
        const state = Authorize.searchParams.get('state')!;
        R.AssertReturned(await trip.Callback({ error: 'access_denied', state }, Binding), request.Query, LoginNoticeReason.Incomplete);
        const again = await trip.Callback({ error: 'access_denied', state }, Binding);
        assert.equal(again.Status, 401, 'the state works once');
        assert.match(again.Header('content-type') ?? '', /text\/html/);
        assert.ok(again.Text.includes(SignInFailurePage.Title));
        const unknown = await trip.Callback({ error: 'access_denied', state: 'expired-or-never-begun' }, Binding);
        assert.equal(unknown.Status, 401, 'an unknown or expired state on the missing-code path recovers nothing');
        assert.ok(unknown.Text.includes(SignInFailurePage.Title));
    });

    it('answers the failure page, never JSON, when the request cannot be recovered', async () =>
    {
        const replies = [
            await trip.Callback({ code: 'c' }),
            await trip.Callback({ code: 'c', state: '' }),
            await trip.Callback({ code: 'c', state: 'never-begun' }),
            await host.Http.Send('GET', flow.Issuer + '/broker/entra/callback?code=c&state=s'),
            await host.Http.Send('GET', host.Issuer('nope') + '/broker/google/callback?code=c&state=s'),
        ];
        // A browser that did not begin the sign-in (login CSRF) is sent nowhere, not even back to the page.
        const { Authorize } = await trip.Begin(flow.Request());
        await trip.NextToken(Authorize, { sub: 'x', email: 'x@gmail.com' });
        replies.push(await trip.Callback({ code: 'c', state: Authorize.searchParams.get('state')! }));
        for (const reply of replies)
        {
            assert.equal(reply.Status, 401);
            assert.match(reply.Header('content-type') ?? '', /text\/html/);
            assert.equal(reply.Header('cache-control'), 'no-store');
            assert.ok(reply.Text.includes(SignInFailurePage.Title));
            assert.equal(reply.Header('location'), undefined);
        }
    });

    it('never takes the marker as part of the request, nor its text into the page', async () =>
    {
        const injected = await flow.Authorize(flow.Request({ pragmatic_notice: '<script>alert(1)</script>' }));
        assert.equal(injected.Status, 200);
        assert.match(injected.Text, /content="ready"/, 'an unknown reason shows no notice');
        assert.ok(!injected.Text.includes('<script>alert'));
        const crafted = await flow.Authorize(flow.Request({ pragmatic_notice: 'domain."><script>alert(1)</script>' }));
        assert.match(crafted.Text, /<meta name="pragmatic-login" content="notice" data-reason="domain">/, 'a source the realm does not have is dropped');
        assert.ok(!crafted.Text.includes('<script>alert'));
        // A sign-in begun from a page that carried a notice: the marker is not carried, so a second refusal has one.
        const marked = flow.Request({ pragmatic_notice: 'incomplete.google' });
        const stripped = LoginNotice.Strip(marked.Query);
        assert.notEqual(stripped, marked.Query);
        R.AssertReturned(await trip.Answer(marked, { sub: 'gmail-2', email: 'other@gmail.com' }), stripped, LoginNoticeReason.Domain);
    });

    it('asks Google for its account chooser and the hosted domain, so another account is one click away', async () =>
    {
        const { Authorize } = await trip.Begin(flow.Request());
        assert.equal(Authorize.searchParams.get('prompt'), 'select_account');
        assert.equal(Authorize.searchParams.get('hd'), F.Domain);
    });

    it('recovers nothing from a state another source began, and spends it', async () =>
    {
        const { Authorize, Binding } = await trip.Begin(flow.Request());
        const state = Authorize.searchParams.get('state')!;
        const crossed = await host.Http.Send('GET', flow.Issuer + '/broker/oidc/callback?' + new URLSearchParams({ error: 'access_denied', state }).toString(), { Headers: { cookie: Binding } });
        assert.equal(crossed.Status, 401);
        assert.ok(crossed.Text.includes(SignInFailurePage.Title));
        assert.equal(crossed.Header('location'), undefined, 'never a notice naming the wrong source');
        const after = await trip.Callback({ error: 'access_denied', state }, Binding);
        assert.equal(after.Status, 401, 'the state is spent');
        const { Authorize: second, Binding: secondBinding } = await trip.Begin(flow.Request());
        const withCode = await host.Http.Send('GET', flow.Issuer + '/broker/oidc/callback?' + new URLSearchParams({ code: 'c', state: second.searchParams.get('state')! }).toString(), { Headers: { cookie: secondBinding } });
        assert.equal(withCode.Status, 401);
        assert.equal(withCode.Header('location'), undefined);
    });

    it('a sign-in from a marked request reaches the application without the marker', async () =>
    {
        const marked = flow.Request({ pragmatic_notice: 'domain.google' });
        const signedIn = await trip.Answer(marked, { sub: 'staff-2', email: 'ada@pragmatic-tech.ai', name: 'Ada', hd: F.Domain });
        assert.equal(signedIn.Status, 302);
        const location = signedIn.Header('location')!;
        assert.ok(location.startsWith(F.Redirect + '?'));
        assert.ok(!location.includes('pragmatic_notice'));
        assert.ok(IdpTestFlow.CodeOf(location, marked).length > 0);
        const cookie = /idp_sso=[^;,]+/.exec(String(signedIn.Headers['set-cookie']))![0];
        // With the live SSO session a marked request is answered silently, again without the marker.
        const again = flow.Request({ pragmatic_notice: 'incomplete.google' });
        const silent = await flow.Authorize(again, cookie);
        assert.equal(silent.Status, 302);
        assert.ok(silent.Header('location')!.startsWith(F.Redirect + '?'));
        assert.ok(!silent.Header('location')!.includes('pragmatic_notice'));
        assert.ok(IdpTestFlow.CodeOf(silent.Header('location')!, again).length > 0);
    });

    it('a marked prompt=none request without a session answers login_required, without the marker', async () =>
    {
        const request = flow.Request({ prompt: 'none', pragmatic_notice: 'domain.google' });
        const reply = await flow.Authorize(request);
        assert.equal(reply.Status, 302);
        const location = new URL(reply.Header('location')!);
        assert.equal(location.origin + location.pathname, F.Redirect);
        assert.equal(location.searchParams.get('error'), 'login_required');
        assert.equal(location.searchParams.get('state'), request.State);
        assert.equal(location.searchParams.get('pragmatic_notice'), null);
    });
});
