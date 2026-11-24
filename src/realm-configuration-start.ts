import { RealmConfigurationReader, type IRealmSecretsHome, type RealmConfiguration } from './realm-configuration-reader.js';
import { RealmSecretsImport, type IRealmSecretsHomeStores, type RealmSecretsImportReport } from './realm-secrets-import.js';
import { TenantIdpComponent } from './tenant-idp-component.js';
import type { TenantIdpDatabase } from './tenant-idp-database.js';

/** The service's secrets home as the start reads it: the hive realm (when its secrets have a realm home) and its stores. */
export interface IHomeRealmSecrets extends IRealmSecretsHome, IRealmSecretsHomeStores
{
    readonly HomeRealm: string | undefined;
}

/**
 * The service's read of its realms' configurations at start, with the one-time move of the hive realm's secrets into the
 * realm secrets home (2.5) around it: copied before the configurations are read (so their `secret:realm/...` references
 * resolve from the new home), retired from the service's own store only after the hive realm's configuration was read.
 * A read that fails leaves the old rows in place (the next start copies again). What moved is logged by name, never a value.
 */
export class RealmConfigurationStart
{
    private static readonly Prefix = 'realm secrets of ';
    private static readonly Copied = ': copied into the realm secrets home: ';
    private static readonly Kept = '; already there: ';
    private static readonly Differing = '; the home holds another value, which is kept (the service\'s goes): ';
    private static readonly Skipped = '; left in the service\'s own store (not realm secret names; rename each to one lowercase segment and enter it again in the tenant admin console): ';
    private static readonly Separator = ', ';
    private static readonly None = '-';

    public constructor(
        private readonly home: IHomeRealmSecrets,
        private readonly database: TenantIdpDatabase,
        private readonly masterKey: Buffer,
        private readonly log: (line: string) => void)
    {
    }

    /** Every realm configuration of `directory` and, when given, the bootstrap realm file. */
    public async Read(directory: string, bootstrap: string | undefined): Promise<RealmConfiguration[]>
    {
        const realm = this.home.HomeRealm;
        const move = realm === undefined ? undefined : new RealmSecretsImport(this.database, this.masterKey, this.home);
        for (const report of realm === undefined ? [] : await move!.Copy([realm]))
        {
            this.log(RealmConfigurationStart.Line(report));
        }
        const reader = new RealmConfigurationReader(TenantIdpComponent.Descriptor(), this.home);
        const configurations: RealmConfiguration[] = [...await reader.ReadDirectory(directory)];
        if (bootstrap !== undefined)
        {
            configurations.push(await reader.ReadBootstrap(bootstrap));
        }
        await move?.Retire(configurations.map(configuration => configuration.RealmId));
        return configurations;
    }

    private static Line(report: RealmSecretsImportReport): string
    {
        const R = RealmConfigurationStart;
        const list = (names: readonly string[]): string => names.length === 0 ? R.None : names.join(R.Separator);
        return R.Prefix + report.RealmId + R.Copied + list(report.Copied) + R.Kept + list(report.Kept) + R.Differing + list(report.Differing) + R.Skipped + list(report.Skipped);
    }
}
