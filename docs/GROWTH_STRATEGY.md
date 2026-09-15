# prompt-protection — Growth & Product Strategy Plan

> **Status:** Phases 1 & 2 SHIPPED in **v2.0.0** — live on npm (`latest = 2.0.0`, 2026-09-08, PR #19). **v2.0.1 (PR #20, open 2026-09-08)** corrects the benchmark reporting — see "Benchmark integrity" below. Phases 3 & 4 outstanding. One Phase-2 tail item open: **MCP registry submissions (pending, user, due 2026-09-09)** — see the publish note below. Draft dated 2026-09-03; status updated 2026-09-08. Uncommitted working doc.
> Answers four questions: what the package should handle but doesn't, the SEO strategy, the features that drive real adoption, and how to get AI models/agents to install it. Each phase in "Recommended sequencing" is a separate build session.
>
> **Done so far:** SEO v1 (meta/OG/JSON-LD, sitemap, 6 docs pages, og-image) shipped in 1.8.3 (PR #18); the two awesome-list PRs (#298 corca-ai, #83 FonduAI) and profile/README were filed. v2.0 (PR #19) shipped tool-poisoning detection + `scanToolDefinition`, the MCP server (`prompt-protection-mcp`), the Vercel AI SDK adapter, `llms.txt`, the published benchmark, and the perf/ReDoS hardening. Rules 117 → 126. **The v2.0 benchmark number was overstated** — 134 of its 169 input items doubled as test fixtures; v2.0.1 splits it (held-out 75.0% / 93.8% / 6.7%; combined 94.8% / 98.9% / 1.4%).

## Context

The package does ~2,861 downloads/month but has **3 stars, 0 forks, 0 watchers, 0 real dependents**. The user is worried that downloads "keep dropping" after a ~1K/week peak. This deep dive answers four questions: (1) what the package should handle but doesn't, (2) the SEO strategy, (3) features that make users drool, (4) how to get AI models/agents to install it.

**The single most important finding — read this first.** The download number was never adoption. The weekly trend (flat ~10 → spikes of 933/953 → decays to 347) tracks the **publish dates** of 1.8.0 / 1.8.2 / 1.8.3, not user growth. For a package with 3 stars and 0 forks, that traffic is npm mirrors (npmmirror/cnpm), security scanners (Socket/Snyk re-crawl on every publish), and CI caches — automated pulls that burst on release and decay between them. **Chasing the download counter is chasing noise.** The strategy below reorients everything toward the metrics that reflect real adoption — stars, forks, dependents, referrers, GSC impressions — and toward the two things that actually move them in 2026: being where the attacks are (MCP/agentic), and being where the recommendations come from (AI models + listicles).

**The market timing is unusually good, and it is a window, not a permanent state:**
- **LLM Guard — the leading open-source competitor — was archived on 2026-07-09.** Migration guides and "44 alternatives" listicles are being written right now, and it was Python-only, which leaves the JS/TS niche wide open.
- **MCP tool poisoning is the defining 2026 attack** ("the new prompt injection", 60%+ attack-success on real servers per the MCPTox benchmark, NSA/CISA advisory, multiple arXiv papers). prompt-protection has **zero** MCP awareness today. This is the wedge for agentic adoption (ask #4).

Sources for the market claims: appsecsanta.com/llm-guard, mintmcp.com/blog/prompt-injection-detection-tools, safeprompt.dev/blog/best-prompt-injection-detection-tools, grepture.com/blog/llm-guard-archived-migration-guide, infrabase.ai/alternatives/llm-guard, unit42.paloaltonetworks.com/model-context-protocol-attack-vectors, practical-devsecops.com/mcp-security-vulnerabilities.

---

## Part 1 — What's missing (product gaps that matter)

Grounded in a full code audit (`src/patterns/*`, `normalizer.ts`, `scorer.ts`, `output.ts`, `async.ts`, `session.ts`). Prioritized by leverage, not by size.

### Tier A — build these; this is where the market and the attacks are

*Status: items 1, 3 (Vercel only), and 5 SHIPPED in v2.0. Item 2 (RAG API) and item 3's LangChain/CLI adapters and item 4 (streaming) remain → Phase 3.*
1. **✅ MCP tool-poisoning detection + an MCP server. (SHIPPED v2.0)** No `mcp` reference anywhere in `src`. `injection-fake-tool-call` (`src/patterns/injection.ts:151`) catches a fake `tool_calls` blob in *user* input but nothing scans a **poisoned tool/function definition** (description + param docs) — the actual 2026 attack. Ship: a new `src/patterns/tool-poisoning.ts` category, a `scanToolDefinition()` helper, and a `prompt-protection/mcp` server that exposes scanning as MCP tools so agents can call it. New export subpath + `bin`.
2. **⬜ Indirect / RAG injection ergonomics.** Today `analyzeRoles` (`src/messages.ts`) only distinguishes chat roles, not "trusted prompt vs. untrusted retrieved content." Add a first-class channel API — `analyzeContent(text, { source: 'rag' | 'tool' | 'web' })` — that reuses the `analyzePrompt` core (`src/api.ts:53`) with stricter defaults and clear docs. This is the OWASP LLM01 indirect-injection story the guides already describe but the API doesn't make easy.
3. **◐ Framework adapters where agents actually live.** (Vercel AI SDK adapter SHIPPED v2.0; LangChain.js + CLI still to do.) No adapter for **Vercel AI SDK** (`ai` — the default TS agent stack), **LangChain.js**, or a **CLI**. Each is a new `package.json` export subpath + a `tsup.config.ts` entry (mind the entry-per-export gotcha documented in `CLAUDE.md` — the openai subpath bug we just fixed). Vercel AI SDK middleware (`wrapLanguageModel({ middleware: promptProtection() })`) is the highest-leverage of the three.
4. **⬜ Streaming output scan helper.** `analyzeOutput(output: string)` (`src/output.ts:54`) requires the full string; agents stream. Add a chunk-cadence scanner (`analyzeOutputStream`) wrapping the existing scorer.
5. **✅ Benchmark / eval harness + a published catch-rate number. (SHIPPED v2.0; corrected in v2.0.1 — held-out 75.0% recall / 93.8% precision / 6.7% FP, combined 94.8% / 98.9% / 1.4%; `npm run bench`.)** There is **no** labeled-corpus eval anywhere (tests are per-module unit tests) and **no** published precision/recall. Competitors lead with "continuously measured catch rates." This is the credibility unlock — see Parts 3 and 4; a number is what both humans and AI models cite. Add `bench/` with a labeled attack/benign corpus, a runner (`npm run bench`), and the number in the README.

### Tier B — strengthen the core
- **Non-English rules.** Zero today — every pattern is an English literal. A non-English "ignore previous instructions" passes. Add the top injection/jailbreak phrases in ES/FR/DE/PT/ZH — cheap, high-coverage.
- **True multi-turn escalation.** `createProtectionSession` (`src/session.ts:104`) only remembers *blocked* prompts and escalates 3 deferred-reference rules; each turn is still scored independently. Add crescendo / cumulative cross-turn scoring.
- **Encoding coverage.** Missing: spaced-out text ("i g n o r e"), hex/HTML entities, ROT13, Base32/85. Base64 decode requires ≥20 chars and printable-ASCII output (`src/utils/encoding.ts:1,10`), so short/binary payloads slip.
- **Canary-token helper** and **safe block-reason redaction** (`PromptInjectionError` currently leaks `matchedText` slices of raw input — `src/error.ts:11`, `src/scorer.ts:107`).

### Tier C — correctness/perf smells (fold into the credibility phase)

*Status: all three SHIPPED in v2.0.*
- **✅ Cache compiled regexes. (SHIPPED v2.0.)** Was one `new RegExp(rule.pattern.source, 'gi')` per rule per `score()` call. Now a module-level `WeakMap` cache keyed on rule-pattern identity (`src/scorer.ts:31`).
- **✅ `buildIndexMap` was O(n·m), degrading toward O(n²)** on decode-expanded input (`src/normalizer.ts`). Fixed in v2.0 — no longer rescans the tail on decode-appended input. The map remains a lossy heuristic that can mis-position `stripPrompt` spans after base64/percent expansion; that part is still open.
- **✅ ReDoS surface. (SHIPPED v2.0.)** `.{0,N}` bridges in several rules run under a global re-exec loop on attacker input; a `maxInputLength` cap (default 100_000) now guards input and output analysis before scoring.

---

## Part 2 — SEO strategy (v2)

The v1 technical SEO already shipped (meta/OG/JSON-LD/sitemap/docs). v2 is about **intent and the pages that already rank**, not more meta tags.

1. **Get INTO the roundups that already rank.** "Best prompt injection detection tools 2026" lists (MintMCP, SafePrompt, aisecurityandsafety.org) and "LLM Guard alternatives" pages (infrabase.ai) *are* the search results. Submitting/pitching for inclusion beats trying to outrank them. Highest-ROI SEO action available.
2. **Ride the LLM-Guard-archived wave.** A dedicated **"LLM Guard is archived — the zero-dependency TypeScript alternative"** page targets a live, rising, buyer-intent query. New docs page, links to the comparison page already written.
3. **MCP-security content cluster.** "MCP tool poisoning detection", "secure MCP server against prompt injection", "scan MCP tool responses" — high-growth, low-competition queries that map directly to the new Tier-A feature. Write these as the MCP feature ships so page and product reinforce each other.
4. **llms.txt + internal linking + real backlinks.** Add `llms.txt`/`llms-full.txt` (Part 4). The awesome-list and benchmark citations from Parts 1/4 are the backlinks that make the existing pages rank.
5. **Keep measuring the right thing:** GSC impressions/clicks per query and referrers — not the download counter.

---

## Part 3 — Killer features (drool factor)

The features that make a developer star it and pick it:
- **The MCP server** — an agent calls prompt-protection as a tool to vet its own tool calls. This is the headline demo for 2026 and nothing in the JS niche offers it cleanly.
- **A published benchmark with a live leaderboard on the site** — "X% catch rate · Y ms · 0 dependencies" is the shareable screenshot. Turns vague trust into a number.
- **One-line framework wiring** — `wrapLanguageModel({ middleware: promptProtection() })` for Vercel AI SDK. Copy-paste adoption.
- **The live playground, leaned into** — "paste an attack, watch it break" already exists and is genuinely good; make it the hero and add the obfuscation demos (homoglyph/base64) that look like magic.
- **The positioning itself as a feature:** zero-dependency, in-process, browser + edge, no API call, no data leaves. That is the exact opposite of archived-Python LLM Guard and hosted-SaaS Lakera. Make it the tagline.

---

## Part 4 — Push to AI models / agentic adoption (ask #4 — the strategic core)

How a model comes to recommend it, and how an agent comes to install it:
1. **llms.txt + llms-full.txt** at the Pages site root and in the repo — Claude Code, Cursor, and Codex fetch these directly. Cheapest first step.
2. **Ship the MCP server and list it in the MCP registries** — the official registry, mcp.so, PulseMCP, `awesome-mcp-servers`. Agents discover tools there; a security-scanning tool is a natural add to any agent's toolbelt.
3. **First-class Vercel AI SDK / LangChain.js adapters with copy-pasteable snippets.** Models regurgitate the canonical wiring they were trained on; make ours the canonical one, short and correct.
4. **Training-data presence is the long game.** Models recommend the option that is popular, well-documented, and *measured*. Stars + dependents + blog posts + Stack Overflow answers + awesome-list citations + a benchmark leaderboard all feed the next training cut. This is a 6–12 month compounding play — the benchmark number and the awesome-list/registry citations are what tip it.
5. **Be the default in a boilerplate.** A "secure AI chat / secure MCP agent starter" template repo makes every clone a real dependent and a real integration — the opposite of mirror-download noise.
6. **Answer the questions models get asked.** Canonical, linkable answers to "how do I stop prompt injection in a Next.js / LangChain / MCP app" (expand the existing docs cluster). These are what a model retrieves and cites.

---

## Recommended sequencing

- **✅ Phase 1 — credibility + core (SHIPPED v2.0; benchmark reporting corrected in v2.0.1).** Benchmark harness + published catch-rate number; regex caching; `buildIndexMap` fix; ReDoS input-length guard. Done.
- **✅ Phase 2 — agentic wedge (SHIPPED v2.0, except registry listings).** MCP server + `tool-poisoning` rules; Vercel AI SDK adapter; `llms.txt`. **Still to do:** submit the MCP server to the registries (mcp.so, PulseMCP, official MCP registry, `awesome-mcp-servers`) — a non-code outreach step, not yet done.
- **⬜ Phase 3 — coverage + reach.** RAG/indirect `analyzeContent` API; streaming scan (`analyzeOutputStream`); non-English rules; canary tokens; safe block-reason redaction; the "LLM Guard alternative" + MCP-security SEO cluster; listicle-inclusion outreach. Outstanding.
- **⬜ Phase 4 — compounding.** Boilerplate template; blog posts; awesome-list + benchmark citations. Outstanding.

> **✅ Published:** v2.0.0 is live on npm (`latest = 2.0.0`, tag pushed & OIDC publish confirmed 2026-09-08).
>
> **⬜ v2.0.1 — benchmark integrity (PR #20, open 2026-09-08).** Corpus/fixture split, real CI gate, gate-before-write, warm-up, and the stale `117 rules` in the npm description. Merge, then push the `v2.0.1` tag. **The GitHub wiki is a separate repo and still carries the wrong miss-characterisation** — push `docs/wiki/Benchmark.md` there too.
>
> **⬜ PENDING — MCP registry submissions (owner: user, due 2026-09-09).** Submit the MCP server to: mcp.so · PulseMCP · the official MCP registry · `punkpeye/awesome-mcp-servers` (PR). NOT yet done. Leave unchecked until the user confirms here that they've posted; resurface this at the top of any future session in this repo until then.

Each phase is a separate build session; this document is the map, not an implementation.

---

## Files & reuse (for the eventual builds)

- **Reuse the core:** `analyzePrompt`/`score`/`resolveAction` (`src/api.ts`, `src/scorer.ts`, `src/verdict.ts`) — new surfaces (RAG API, streaming, MCP, adapters) wrap these, they don't reimplement scoring.
- **New rule categories** follow the existing pattern-file shape (`src/patterns/*.ts` + the `ALL_RULES` barrel in `src/patterns/index.ts`); add `tool-poisoning` and the non-English rules there.
- **Every new entry point** needs BOTH a `package.json` exports subpath AND a `tsup.config.ts` entry — see `CLAUDE.md`; verify with `ls dist/<subpath>.*` after build (this is the exact class of bug just fixed for the openai adapter).
- **Benchmark** lives in a new top-level `bench/` (excluded from the npm `files` list, like `docs/`).

## Verification / how we'll know it's working

- **Track adoption KPIs, not downloads:** GitHub stars/forks, npm dependents (via libraries.io), GSC impressions/clicks, referrers. Baseline today: 3 stars, 0 forks, 0 dependents, ~2,861 downloads/mo (mostly non-human). Set the download counter aside.
- **Benchmark reproducible** via `npm run bench`; the published number regenerates from the committed corpus. **Read the held-out row, not the combined one** — the runner splits the corpus by set-membership against `tests/__fixtures__/`, so items that double as test assertions are reported separately and cannot inflate the headline. A new corpus case that is not also a fixture stays held out automatically; do not copy one into the fixtures to move the number.
- **MCP server** smoke-tested live in Claude Desktop / Cursor (tool shows up, scans, returns a verdict).
- **Each new adapter/subpath:** `npm run build && ls dist/<subpath>.*` shows all four artifacts; existing 457 tests stay green; new surfaces get their own tests.
