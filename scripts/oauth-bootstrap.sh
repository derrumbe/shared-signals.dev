#!/usr/bin/env bash
# Walks through how an SSF Receiver bootstraps itself against shared-signals.dev, with nothing
# configured in advance: discover the Transmitter, discover its OAuth server, get a token, create a
# stream, receive an event by polling, then clean up and revoke the token.
#
# Usage: scripts/oauth-bootstrap.sh [base-url]      (needs curl and jq)

set -euo pipefail
BASE="${1:-https://shared-signals.dev}"
CLIENT_ID="bootstrap-demo"
CLIENT_SECRET="demo-$(head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n')" # 16+ chars; names a fresh private sandbox

step() { printf '\n\033[1;36m== %s\033[0m\n' "$*"; }
show() { printf '\033[2m$ %s\033[0m\n' "$*"; }

step "1. Discover the Transmitter (SSF §7)"
show "curl $BASE/.well-known/ssf-configuration"
SSF=$(curl -sf "$BASE/.well-known/ssf-configuration")
echo "$SSF" | jq '{issuer, configuration_endpoint, verification_endpoint, delivery_methods_supported, authorization_schemes}'
ISSUER=$(echo "$SSF" | jq -r .issuer)
STREAM_EP=$(echo "$SSF" | jq -r .configuration_endpoint)

step "2. Discover its OAuth authorization server (RFC 8414, same issuer)"
show "curl $ISSUER/.well-known/oauth-authorization-server"
AS=$(curl -sf "$ISSUER/.well-known/oauth-authorization-server")
echo "$AS" | jq '{token_endpoint, revocation_endpoint, grant_types_supported, scopes_supported}'
TOKEN_EP=$(echo "$AS" | jq -r .token_endpoint)
REVOKE_EP=$(echo "$AS" | jq -r .revocation_endpoint)

step "3. Get an access token (client credentials; no registration needed)"
show "curl $TOKEN_EP -u '$CLIENT_ID:<secret>' -d grant_type=client_credentials -d 'scope=ssf.read ssf.manage'"
TOK=$(curl -sf "$TOKEN_EP" -u "$CLIENT_ID:$CLIENT_SECRET" -d grant_type=client_credentials -d 'scope=ssf.read ssf.manage')
echo "$TOK" | jq '.access_token |= .[0:24] + "…"'
TOKEN=$(echo "$TOK" | jq -r .access_token)
AUTH=(-H "Authorization: Bearer $TOKEN")

step "4. Create a poll stream (no delivery given = poll, RFC 8936)"
show "curl -X POST $STREAM_EP -H 'Authorization: Bearer …' -d '{\"description\": …, \"events_requested\": [session-revoked]}'"
STREAM=$(curl -sf "$STREAM_EP" "${AUTH[@]}" -H 'Content-Type: application/json' \
  -d '{"description": "Bootstrap demo", "events_requested": ["https://schemas.openid.net/secevent/caep/event-type/session-revoked"]}')
echo "$STREAM" | jq '{stream_id, aud, delivery, events_delivered}'
SID=$(echo "$STREAM" | jq -r .stream_id)
POLL_EP=$(echo "$STREAM" | jq -r .delivery.endpoint_url)

step "5. Have the Transmitter fire a CAEP session-revoked event (the playground's own API)"
show "curl -X POST $BASE/api/events -H 'Authorization: Bearer …' -d '{\"event_type\": \"session-revoked\", …}'"
curl -sf "$BASE/api/events" "${AUTH[@]}" -H 'Content-Type: application/json' \
  -d "{\"stream_id\": \"$SID\", \"event_type\": \"session-revoked\", \"sub_id\": {\"format\": \"email\", \"email\": \"alice@example.com\"}}" \
  | jq '{event_type, results: [.results[] | del(.set)]}'

step "6. Poll for it as the Receiver"
show "curl -X POST $POLL_EP -H 'Authorization: Bearer …' -d '{\"maxEvents\": 5, \"returnImmediately\": true}'"
POLLED=$(curl -sf "$POLL_EP" "${AUTH[@]}" -H 'Content-Type: application/json' -d '{"maxEvents": 5, "returnImmediately": true}')
JTI=$(echo "$POLLED" | jq -r '.sets | keys[0]')
SET=$(echo "$POLLED" | jq -r ".sets[\"$JTI\"]")
echo "Got SET $JTI. Its decoded payload:"
echo "$SET" | cut -d. -f2 | tr '_-' '/+' | awk '{ while (length($0) % 4) $0 = $0 "="; print }' | base64 -d 2>/dev/null | jq .

step "7. Check it with the SET inspector (signature, claims, CAEP Interop Profile)"
curl -sf "$BASE/api/inspect" -H 'Content-Type: application/json' -d "{\"set\": \"$SET\", \"issuer\": \"$ISSUER\", \"audience\": \"$CLIENT_ID\"}" \
  | jq '{verdict, checks: [.checks[] | "\(.level): \(.message)"]}'

step "8. Acknowledge it, delete the stream, revoke the token (RFC 7009)"
curl -sf "$POLL_EP" "${AUTH[@]}" -H 'Content-Type: application/json' -d "{\"ack\": [\"$JTI\"], \"returnImmediately\": true}" > /dev/null && echo "acknowledged $JTI"
curl -sf -X DELETE "$STREAM_EP?stream_id=$SID" "${AUTH[@]}" -o /dev/null -w 'DELETE stream → %{http_code}\n'
curl -sf "$REVOKE_EP" -d "token=$TOKEN" -o /dev/null -w 'revoke token → %{http_code}\n'
show "curl $STREAM_EP -H 'Authorization: Bearer <revoked token>'"
curl -s "$STREAM_EP" "${AUTH[@]}" -o /dev/null -D - | grep -iE '^(HTTP/[0-9.]+ [0-9]{3}|www-authenticate)' | grep -v 'Connection Established'
