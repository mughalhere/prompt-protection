/**
 * YAML entry for ATR rule packs. The `yaml` package is an optional peer,
 * loaded on demand so the core stays dependency-free. Multi-document files
 * (`---`) and folded scalars are handled by the real parser on purpose: a
 * subset parser would silently corrupt regex sources.
 */
export async function parseAtrYaml(text: string): Promise<unknown[]> {
  const specifier = 'yaml'; // variable keeps tsc from requiring the peer's types at build time
  const mod = (await import(specifier)) as { parseAllDocuments: (src: string) => Array<{ toJS: () => unknown }> };
  const docs = mod.parseAllDocuments(text);
  const out: unknown[] = [];
  for (const doc of docs) {
    const value = doc.toJS();
    if (Array.isArray(value)) out.push(...(value as unknown[]));
    else if (value !== null && value !== undefined) out.push(value);
  }
  return out;
}
