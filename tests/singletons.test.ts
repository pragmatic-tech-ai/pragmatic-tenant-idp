import assert from 'node:assert/strict';
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';

/**
 * Every installed copy of a package, found by walking node_modules (nested ones included) for package.json names: the
 * engine's module-level singletons and `instanceof` checks break when two copies load in one process.
 */
class InstalledCopies
{
    private static readonly NodeModules = 'node_modules';
    private static readonly PackageJson = 'package.json';
    private static readonly ScopePrefix = '@';
    private static readonly HiddenPrefix = '.';
    private static readonly Utf8 = 'utf8';

    private readonly found = new Map<string, string[]>();

    public constructor(root: string)
    {
        this.Walk(join(root, InstalledCopies.NodeModules));
    }

    public Of(name: string): readonly string[]
    {
        return this.found.get(name) ?? [];
    }

    private Walk(modules: string): void
    {
        if (!existsSync(modules))
        {
            return;
        }
        for (const entry of readdirSync(modules, { withFileTypes: true }))
        {
            if (!entry.isDirectory() || entry.name.startsWith(InstalledCopies.HiddenPrefix))
            {
                continue;
            }
            const path = join(modules, entry.name);
            if (entry.name.startsWith(InstalledCopies.ScopePrefix))
            {
                for (const scoped of readdirSync(path, { withFileTypes: true }))
                {
                    if (scoped.isDirectory())
                    {
                        this.Visit(join(path, scoped.name));
                    }
                }
                continue;
            }
            this.Visit(path);
        }
    }

    private Visit(dir: string): void
    {
        const manifest = join(dir, InstalledCopies.PackageJson);
        if (existsSync(manifest))
        {
            const name = (JSON.parse(readFileSync(manifest, InstalledCopies.Utf8)) as { name?: string }).name;
            if (name !== undefined)
            {
                this.found.set(name, [...(this.found.get(name) ?? []), dir]);
            }
        }
        this.Walk(join(dir, InstalledCopies.NodeModules));
    }
}

class SingletonsFixture
{
    public static readonly Root = join(dirname(fileURLToPath(import.meta.url)), '..');
    public static readonly Singletons: readonly string[] = [
        '@pragmatic-tech-ai/todl-runtime',
        '@pragmatic-tech-ai/todl',
        '@pragmatic-tech-ai/mural',
    ];
}

describe('engine singletons', () =>
{
    const copies = new InstalledCopies(SingletonsFixture.Root);
    for (const name of SingletonsFixture.Singletons)
    {
        it('one installed copy of ' + name, () =>
        {
            assert.equal(copies.Of(name).length, 1, name + ': ' + JSON.stringify(copies.Of(name)));
        });
    }
});
