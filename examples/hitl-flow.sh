#!/usr/bin/env bash
set -euo pipefail

# Trusted/human side
export PASSD_MASTER_PASSWORD="${PASSD_MASTER_PASSWORD:?set PASSD_MASTER_PASSWORD}"
passd vault create Personal
passd item put-login --vault Personal --title OpenRouter --password-file ./openrouter.key
AGENT_JSON=$(passd agent create hermes --expiration 1d --allow-host openrouter.ai)
echo "$AGENT_JSON"

# Give only the returned pda_... token to the agent.
# Agent side:
#   export PASSD_AGENT_TOKEN='pda_...'
#   export PASSD_AGENT_REASON='Need OpenRouter for current task'
#   passd access request 'pass://Personal/OpenRouter/password' \
#       --capability secret.use --host openrouter.ai --expiration 5m --uses 1
#
# Trusted side:
#   passd access pending
#   passd access approve req_... --expiration 2m --uses 1
#
# Agent side:
#   passd broker-http 'pass://Personal/OpenRouter/password' \
#       'https://openrouter.ai/api/v1/models' --header Authorization --prefix 'Bearer '
