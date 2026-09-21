# Example capability flow

1. Start `passd` interactively.
2. Create an `Agents` vault and an `OpenRouter` item.
3. Create a use-only agent scoped to the vault and `openrouter.ai`.
4. Give the resulting `pda_...` token to the agent, not the OpenRouter key.
5. The agent calls `passd broker-http pass://Agents/OpenRouter/password https://openrouter.ai/...` with `PASSD_AGENT_REASON` set.

The default use-only token cannot call `secret.resolve`, so the plaintext credential is never returned over the RPC protocol.
