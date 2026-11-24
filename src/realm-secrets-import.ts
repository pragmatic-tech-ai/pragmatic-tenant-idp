import type { ISqlSession } from '@pragmatic-tech-ai/todl';
import type { ISecretStore } from '@pragmatic-tech-ai/pragmatic-identity';
import { RealmSecretName, SqlMigrationRunner } from '@pragmatic-tech-ai/pragmatic-realm-adapters';
import { IdpRealm } from './idp-realm.js';
import type { TenantIdpDatabase } from './tenant-idp-database.js';
import { IdpRealmSecretsImportMigrations } from './tenant-idp-migrations.js';

/** The realms whose secrets were moved into the realm secrets home, so the move runs once per realm. */
export class SqlRealmSecretsImports
{
    private static readonly CompletedSql = 'SELECT realm_id FROM tenant_idp_realm_secrets_imports WHERE realm_id = $1';
    private static readonly CompleteSql = 'INSERT INTO tenant_idp_realm_secrets_imports (realm_id, moved, completed_at) VALUES ($1, $2, $3) ON CONFLICT (realm_id) DO NOTHING';

    private constructor(private readonly session: ISqlSession)
    {
    }

    public static async Open(session: ISqlSession): Promise<SqlRealmSecretsImports>
    {
        await SqlMigrationRunner.Run(session, new IdpRealmSecretsImportMigrations());
        return new SqlRealmSecretsImports(session);
    }

    public async Completed(realm: string): Promise<boolean>
    {
        return (await this.session.Query(SqlRealmSecretsImports.CompletedSql, [realm])).length > 0;
    }

    public async Complete(realm: string, moved: number): Promise<void>
    {
        await this.session.Execute(SqlRealmSecretsImports.CompleteSql, [realm, moved, new Date()]);
    }
}

/** What the move did for one realm: names only, never a value. */
export class RealmSecretsImportReport
{
    public constructor(
        public readonly RealmId: string,
        /** Copied into the home (it held none under that name). */
        public readonly Copied: readonly string[],
        /** Already in the home: the home's value is kept (the tenant admin console wrote it later). */
        public readonly Kept: readonly string[],
        /** Not realm secret names (a realm secrets home takes one lowercase segment): left in the service's store. */
        public readonly Skipped: readonly string[])
    {
        Object.freeze(this);
    }
}

/** Where a realm's secrets live once a realm secrets home is configured. */
export interface IRealmSecretsHomeStores
{
    RealmStore(realm: string): Promise<ISecretStore>;
    /** Whether that store can hold a secret of this name. */
    AcceptsName(name: string): boolean;
}

/**
 * Moves each realm's configuration secrets (the names its `secret:realm/...` references use) from the service's own
 * sealed store into the realm secrets home, once per realm, in two steps around the start's configuration read: `Copy`
 * writes every realm secret name the old store holds into the home (a name the home already holds keeps the home's
 * value), so the read resolves every reference from the new home; only then `Retire` deletes the copies from the old
 * store and records the realm as done. A start that fails in between copies again next time (idempotent) and leaves the
 * old rows in place. Password hashes (`idp-password/<account>`) are the service's own data, not configuration: they are
 * never moved. Values are never logged; the report names secrets only.
 */
export class RealmSecretsImport
{
    private readonly pending = new Map<string, readonly string[]>();

    public constructor(private readonly database: TenantIdpDatabase, private readonly masterKey: Buffer, private readonly home: IRealmSecretsHomeStores)
    {
    }

    /** Copies the realms' secrets that were not moved yet into the home. */
    public async Copy(realms: readonly string[]): Promise<readonly RealmSecretsImportReport[]>
    {
        const imports = await SqlRealmSecretsImports.Open(this.database.Session);
        const reports: RealmSecretsImportReport[] = [];
        for (const realm of realms)
        {
            if (await imports.Completed(realm)) continue;
            const old = await this.database.RealmSecrets(realm, this.masterKey);
            const target = await this.home.RealmStore(realm);
            const copied: string[] = [];
            const kept: string[] = [];
            const skipped: string[] = [];
            const moved: string[] = [];
            for (const name of await old.References())
            {
                if (name.startsWith(IdpRealm.SecretRefPrefix)) continue;
                if (!RealmSecretName.IsName(name))
                {
                    skipped.push(name);
                    continue;
                }
                const value = await old.Get(name);
                if (value === null) continue;
                if (await target.Get(name) === null)
                {
                    await target.Put(name, value);
                    copied.push(name);
                }
                else
                {
                    kept.push(name);
                }
                moved.push(name);
            }
            this.pending.set(realm, moved);
            reports.push(new RealmSecretsImportReport(realm, copied, kept, skipped));
        }
        return reports;
    }

    /** After the realms' configurations resolved from the home: deletes the copied names from the old store and records
     *  each realm Copy handled as done. */
    public async Retire(): Promise<void>
    {
        const imports = await SqlRealmSecretsImports.Open(this.database.Session);
        for (const [realm, moved] of this.pending)
        {
            const old = await this.database.RealmSecrets(realm, this.masterKey);
            for (const name of moved)
            {
                await old.Delete(name);
            }
            await imports.Complete(realm, moved.length);
        }
        this.pending.clear();
    }
}
