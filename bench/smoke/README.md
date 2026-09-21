# Adapter smoke scripts (manual, not shipped, not CI)

Each script runs the shipped build against a real framework install and shows a tainted tool
result being denied on its way to an exfil tool, with the reason code visible. Install the peer
in a scratch directory first; none of these packages are dev dependencies here.

```
./node_modules/.bin/tsup
node bench/smoke/vercel.mjs          # needs: ai
node bench/smoke/openai-agents.mjs   # needs: @openai/agents
node bench/smoke/langchain.mjs       # needs: langchain @langchain/core
```
