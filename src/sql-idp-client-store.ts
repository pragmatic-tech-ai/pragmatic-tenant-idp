import type { ISqlSession, SqlRow } from '@pragmatic-tech-ai/todl';
import { SqlMigrationRunner } from '@pragmatic-tech-ai/pragmatic-realm-adapters';
import { Argon2PasswordHasher } from '@pragmatic-tech-ai/pragmatic-identity-source-local';
import { IdpClientMigrations } from './tenant-idp-migrations.js';
import { SqlJson } from './sql-json.js';
import { OidcClient } from './clients/oidc-client.js';
import { SeededClients } from './clients/seeded-clients.js';

export { OidcClient };

/** A seeded client id was offered for registration (`SeededClients`: properties of the service, never stored). */
export class ReservedClientError extends Error
{
    private static readonly ErrorName = 'ReservedClientError';
    private static readonly Prefix = 'reserved client id: ';

    public constructor(clientId: string)
    {
        super(ReservedClientError.Prefix + clientId);
        this.name = ReservedClientError.ErrorName;
    }
}

/**
 * The clients of every realm: the seeded ones (`SeededClients`, consulted first, so no stored row can shadow them) and
 * the registered confidential ones, in the service's database (one row per (realm, client)). Registering again
 * replaces the client (a rotated secret). The secret is kept as its argon2 hash only.
 */
export class SqlIdpClientStore
{
    private static readonly DummySecret = 'idp-client-store-dummy-secret';
    private static readonly NoSecret = '';
    private static readonly Columns = 'realm_id, client_id, redirect_uris, post_logout_redirect_uris, secret_hash';
    private static readonly UpsertSql = `INSERT INTO tenant_idp_clients (${SqlIdpClientStore.Columns}, updated_at) VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (realm_id, client_id) DO UPDATE SET redirect_uris = EXCLUDED.redirect_uris, post_logout_redirect_uris = EXCLUDED.post_logout_redirect_uris, secret_hash = EXCLUDED.secret_hash, updated_at = EXCLUDED.updated_at`;
    /** The importer never replaces a client registered since. */
    private static readonly RestoreSql = `INSERT INTO tenant_idp_clients (${SqlIdpClientStore.Columns}, updated_at) VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (realm_id, client_id) DO NOTHING`;
    private static readonly FindSql = `SELECT ${SqlIdpClientStore.Columns} FROM tenant_idp_clients WHERE realm_id = $1 AND client_id = $2`;
    private static readonly ListSql = `SELECT ${SqlIdpClientStore.Columns} FROM tenant_idp_clients WHERE realm_id = $1 ORDER BY client_id`;
    private static readonly DeleteSql = 'DELETE FROM tenant_idp_clients WHERE realm_id = $1 AND client_id = $2';

    private readonly hasher = new Argon2PasswordHasher();
    private readonly dummyHash: Promise<string>;

    private constructor(private readonly session: ISqlSession)
    {
        this.dummyHash = this.hasher.Hash(SqlIdpClientStore.DummySecret);
    }

    public static async Open(session: ISqlSession): Promise<SqlIdpClientStore>
    {
        await SqlMigrationRunner.Run(session, new IdpClientMigrations());
        return new SqlIdpClientStore(session);
    }

    /** Registers (or replaces) the client; true when it replaced one whose secret was different (a rotation, after
     *  which what was issued under the old secret should end). */
    public async Register(realmId: string, clientId: string, redirectUris: readonly string[], secret: string, postLogoutRedirectUris: readonly string[] = []): Promise<boolean>
    {
        if (SeededClients.IsSeeded(clientId))
        {
            throw new ReservedClientError(clientId);
        }
        const existing = await this.Find(realmId, clientId);
        const rotated = existing !== undefined && !(await this.hasher.Verify(secret, existing.SecretHash));
        const hash = await this.hasher.Hash(secret);
        await this.session.Execute(SqlIdpClientStore.UpsertSql, [realmId, clientId, SqlJson.Write([...redirectUris]), SqlJson.Write([...postLogoutRedirectUris]), hash, new Date()]);
        return rotated;
    }

    /** Writes a client with an existing secret hash (the importer of pre-A5 registrations); a seeded id is skipped
     *  (false). */
    public async Restore(realmId: string, clientId: string, redirectUris: readonly string[], secretHash: string): Promise<boolean>
    {
        if (SeededClients.IsSeeded(clientId))
        {
            return false;
        }
        await this.session.Execute(SqlIdpClientStore.RestoreSql, [realmId, clientId, SqlJson.Write([...redirectUris]), SqlJson.Write([]), secretHash, new Date()]);
        return true;
    }

    /** The seeded client of that id, else the registered one. */
    public async Find(realmId: string, clientId: string): Promise<OidcClient | undefined>
    {
        const seeded = SeededClients.Of(realmId, clientId);
        if (seeded !== undefined)
        {
            return seeded;
        }
        const rows = await this.session.Query(SqlIdpClientStore.FindSql, [realmId, clientId]);
        return rows.length === 0 ? undefined : SqlIdpClientStore.ToClient(rows[0]);
    }

    /** The registered clients of the realm (the seeded ones are not listed: nothing about them is the realm's). */
    public async List(realmId: string): Promise<readonly OidcClient[]>
    {
        return (await this.session.Query(SqlIdpClientStore.ListSql, [realmId])).map(row => SqlIdpClientStore.ToClient(row)).filter(client => !SeededClients.IsSeeded(client.ClientId));
    }

    /** Removes a registered client; returns whether it existed (a seeded client is never removed). */
    public async Remove(realmId: string, clientId: string): Promise<boolean>
    {
        if (SeededClients.IsSeeded(clientId))
        {
            return false;
        }
        return (await this.session.Execute(SqlIdpClientStore.DeleteSql, [realmId, clientId])) > 0;
    }

    /**
     * The client the token or revocation request authenticates as, by its kind: a public client presents no secret at
     * all (`none`, its id in the form) and presenting one refuses it; a confidential client's secret must match, and no
     * secret refuses it. An unknown client, or a confidential one without a secret, costs the same argon2 verify as a
     * wrong secret. `presented` undefined: the request carried no secret (neither Basic nor `client_secret`).
     */
    public async Authenticate(realmId: string, clientId: string, presented: string | undefined): Promise<OidcClient | undefined>
    {
        const client = clientId === '' ? undefined : await this.Find(realmId, clientId);
        if (client !== undefined && client.IsPublic)
        {
            return presented === undefined ? client : undefined;
        }
        if (client === undefined || presented === undefined)
        {
            await this.hasher.Verify(presented ?? SqlIdpClientStore.NoSecret, await this.dummyHash);
            return undefined;
        }
        return await this.hasher.Verify(presented, client.SecretHash) ? client : undefined;
    }

    private static ToClient(row: SqlRow): OidcClient
    {
        return new OidcClient(String(row.client_id), String(row.realm_id), SqlJson.Strings(row.redirect_uris), SqlJson.Strings(row.post_logout_redirect_uris), String(row.secret_hash));
    }
}
