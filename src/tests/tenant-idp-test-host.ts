import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { request } from 'node:https';
import { connect, createServer, isIP, type Server, type Socket } from 'node:net';
import { checkServerIdentity } from 'node:tls';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { ComponentDescriptor } from '@pragmatic-tech-ai/pragmatic-component';
import { PgSession } from '@pragmatic-tech-ai/pragmatic-realm-adapters';
import { SqlTestSessions } from '@pragmatic-tech-ai/pragmatic-realm-adapters/testing';
import type { ISqlSession } from '@pragmatic-tech-ai/todl';
import { DevCa, IdpTlsMaterial } from '@pragmatic-tech-ai/pragmatic-identity-source-oidc';
import { IdpLoginPage } from '../idp-login-page.js';
import type { IdpSourceClients } from '../idp-realm.js';
import { IdpSigningKey } from '../idp-signing-key.js';
import { IdpTlsIdentity } from '../idp-tls-identity.js';
import { RealmIssuer } from '@pragmatic-tech-ai/pragmatic-identity';
import type { RealmConfiguration } from '../realm-configuration-reader.js';
import { TenantIdpDatabase } from '../tenant-idp-database.js';
import type { IRealmSecretsHomeStores } from '../realm-secrets-import.js';
import { TenantIdpService } from '../tenant-idp-service.js';

/** One HTTPS answer of the test client. */
export class IdpTestReply
{
    public constructor(public readonly Status: number, public readonly Headers: Record<string, string | string[] | undefined>, public readonly Text: string)
    {
    }

    public Json(): any
    {
        return JSON.parse(this.Text);
    }

    public Header(name: string): string | undefined
    {
        const value = this.Headers[name.toLowerCase()];
        return Array.isArray(value) ? value.join(', ') : value;
    }

    /** The first Set-Cookie pair (`name=value`), or undefined. */
    public Cookie(): string | undefined
    {
        const raw = this.Headers['set-cookie'];
        const first = Array.isArray(raw) ? raw[0] : raw;
        return first?.split(';')[0];
    }
}

/** A request of the test client: a form or a JSON body, extra headers. */
export interface IdpTestRequest
{
    Form?: Record<string, string>;
    Json?: unknown;
    Headers?: Record<string, string>;
}

/** HTTPS to the service under test, trusting its development CA, never following redirects. */
export class IdpTestHttp
{
    public constructor(private readonly ca: string)
    {
    }

    public Send(method: string, url: string, options: IdpTestRequest = {}): Promise<IdpTestReply>
    {
        const target = new URL(url);
        const headers: Record<string, string> = { ...options.Headers };
        let body: string | undefined;
        if (options.Form !== undefined)
        {
            body = new URLSearchParams(options.Form).toString();
            headers['content-type'] = 'application/x-www-form-urlencoded';
        }
        else if (options.Json !== undefined)
        {
            body = JSON.stringify(options.Json);
            headers['content-type'] = 'application/json';
        }
        if (body !== undefined)
        {
            headers['content-length'] = String(Buffer.byteLength(body));
        }
        return new Promise<IdpTestReply>((resolve, reject) =>
        {
            // The certificate is checked against the URL's host, never a Host header a test overrides.
            const servername = isIP(target.hostname) === 0 ? target.hostname : undefined;
            const req = request({ host: target.hostname, servername, port: target.port, path: target.pathname + target.search, method, ca: this.ca, headers, checkServerIdentity: (_host, cert) => checkServerIdentity(target.hostname, cert) }, res =>
            {
                const chunks: Buffer[] = [];
                res.on('data', (chunk: Buffer) => chunks.push(chunk));
                res.on('end', () => resolve(new IdpTestReply(res.statusCode ?? 0, res.headers, Buffer.concat(chunks).toString('utf8'))));
            });
            req.on('error', reject);
            req.end(body);
        });
    }
}

export interface TenantIdpTestHostOptions
{
    Configurations?: readonly RealmConfiguration[];
    Applications?: readonly ComponentDescriptor[];
    SourceClients?: IdpSourceClients;
    Now?: () => Date;
    /** An existing session (several hosts over one database); default a fresh pg-mem database. */
    Session?: ISqlSession;
    MasterKey?: Buffer;
    /** Where the admin API writes realm secrets; default the service's own sealed store. */
    SecretsHome?: IRealmSecretsHomeStores;
    /**
     * Serve an internal origin too: `https://localhost:<second port>`, a loopback port forwarded to the service (TLS passes
     * through untouched). The development certificate names `localhost` only (pragmatic-shared 0.18.14 on, never an IP), so
     * the second origin differs by port, not by host.
     */
    Internal?: boolean;
}

/** A loopback TCP port that pipes every connection to another, unchanged: a second origin of one listening service. */
export class LoopbackForwarder
{
    private static readonly NoPortMessage = 'the loopback forwarder is not listening on a TCP port';

    private constructor(private readonly server: Server, private readonly sockets: Set<Socket>, public readonly Port: number)
    {
    }

    public static async Open(targetPort: number): Promise<LoopbackForwarder>
    {
        const sockets = new Set<Socket>();
        const server = createServer(inbound =>
        {
            const outbound = connect(targetPort, TenantIdpTestHost.Loopback);
            for (const socket of [inbound, outbound])
            {
                sockets.add(socket);
                socket.on('close', () => sockets.delete(socket));
                socket.on('error', () => { inbound.destroy(); outbound.destroy(); });
            }
            inbound.pipe(outbound).pipe(inbound);
        });
        await new Promise<void>((resolve, reject) =>
        {
            server.once('error', reject);
            server.listen(0, TenantIdpTestHost.Loopback, () => resolve());
        });
        const address = server.address();
        if (typeof address !== 'object' || address === null)
        {
            server.close();
            throw new Error(LoopbackForwarder.NoPortMessage);
        }
        return new LoopbackForwarder(server, sockets, address.port);
    }

    public Close(): Promise<void>
    {
        for (const socket of this.sockets)
        {
            socket.destroy();
        }
        return new Promise<void>(resolve => this.server.close(() => resolve()));
    }
}

/**
 * The realm sign-in service in process for tests: a fresh pg-mem database, a development CA for `localhost`, a free
 * port (so issuers name the real URL), the placeholder login page and one admin token.
 */
export class TenantIdpTestHost
{
    public static readonly AdminToken = 'test-admin-token';
    public static readonly Localhost = 'localhost';
    public static readonly Loopback = '127.0.0.1';
    private static readonly DirPrefix = 'tenant-idp-test-';
    private static readonly AdminPrefix = '/_admin/realms/';

    private constructor(
        public readonly Service: TenantIdpService,
        public readonly BaseUrl: string,
        public readonly Ca: string,
        public readonly Http: IdpTestHttp,
        public readonly Session: ISqlSession,
        public readonly MasterKey: Buffer,
        /** The internal origin when the host was started with one. */
        public readonly InternalUrl: string | undefined,
        private readonly dir: string,
        private readonly forwarder: LoopbackForwarder | undefined)
    {
    }

    public static async Start(options: TenantIdpTestHostOptions = {}): Promise<TenantIdpTestHost>
    {
        const T = TenantIdpTestHost;
        const dir = mkdtempSync(join(tmpdir(), T.DirPrefix));
        const ca = DevCa.EnsureAt(join(dir, 'tls'), T.Localhost);
        const material = IdpTlsMaterial.Load({ certFile: ca.certFile, keyFile: ca.keyFile });
        const port = await T.FreePort();
        const baseUrl = `https://${T.Localhost}:${port}`;
        const forwarder = options.Internal === true ? await LoopbackForwarder.Open(port) : undefined;
        const internalUrl = forwarder === undefined ? undefined : `https://${T.Localhost}:${forwarder.Port}`;
        const session = options.Session ?? new PgSession(SqlTestSessions.MemPool());
        const masterKey = options.MasterKey ?? Buffer.alloc(32, 7);
        const service = await TenantIdpService.Open({
            Database: TenantIdpDatabase.Over(session),
            SigningKey: await IdpSigningKey.LoadOrCreate(join(dir, 'signing-key.pem')),
            MasterKey: masterKey,
            BaseUrl: baseUrl,
            InternalBaseUrl: internalUrl,
            Configurations: options.Configurations ?? [],
            Applications: options.Applications ?? [],
            LoginPage: IdpLoginPage.Placeholder(),
            SecureCookie: true,
            TrustedProxy: false,
            Tls: new IdpTlsIdentity(material.key, material.cert),
            AdminTokens: [T.AdminToken],
            SourceClients: options.SourceClients,
            Now: options.Now,
            SecretsHome: options.SecretsHome,
        });
        await service.Listen(port, T.Loopback);
        const caPem = readFileSync(ca.caFile, 'utf8');
        return new TenantIdpTestHost(service, baseUrl, caPem, new IdpTestHttp(caPem), session, masterKey, internalUrl, dir, forwarder);
    }

    public Issuer(realm: string): string
    {
        return RealmIssuer.Of(this.BaseUrl, realm);
    }

    /** One admin API call under `/_admin/realms/<path>` with the admin token. */
    public Admin(method: string, path: string, body?: unknown): Promise<IdpTestReply>
    {
        return this.Http.Send(method, this.BaseUrl + TenantIdpTestHost.AdminPrefix + path, { Json: body, Headers: { authorization: 'Bearer ' + TenantIdpTestHost.AdminToken } });
    }

    /** Creates a realm, a local account and a client through the admin API. */
    public async Provision(realm: string, account: { email: string; principalId: string; password: string; displayName?: string }, client: { clientId: string; secret: string; redirectUris: string[]; postLogoutRedirectUris?: string[] }): Promise<void>
    {
        await this.Expect(this.Admin('PUT', realm, { displayName: realm }));
        await this.Expect(this.Admin('POST', realm + '/accounts', { ...account, displayName: account.displayName ?? account.email }));
        await this.Expect(this.Admin('POST', realm + '/clients', client));
    }

    public async Close(): Promise<void>
    {
        await this.forwarder?.Close();
        await this.Service.Close();
        rmSync(this.dir, { recursive: true, force: true });
    }

    private async Expect(reply: Promise<IdpTestReply>): Promise<void>
    {
        const answered = await reply;
        if (answered.Status !== 200)
        {
            throw new Error(`admin call failed: ${answered.Status} ${answered.Text}`);
        }
    }

    private static FreePort(): Promise<number>
    {
        return new Promise<number>((resolve, reject) =>
        {
            const probe = createServer();
            probe.once('error', reject);
            probe.listen(0, TenantIdpTestHost.Loopback, () =>
            {
                const address = probe.address();
                const port = typeof address === 'object' && address !== null ? address.port : 0;
                probe.close(() => resolve(port));
            });
        });
    }
}
