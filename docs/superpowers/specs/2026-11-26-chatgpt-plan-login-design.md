# ChatGPT plan login ("Sign in with ChatGPT") for model profiles

Date: 2026-11-26
Status: approved by the operator ("go ahead and build it"); decisions after the builder check are marked *builder call*

## Intent

The operator wants ARTEX's agents to run on their ChatGPT/Codex subscription instead of a
pay-per-token API key, by signing in with OAuth from the ARTEX console. Success: the operator
clicks "Sign in with ChatGPT" on a model profile, approves in the browser, and tasks then run on
OpenAI models billed to the ChatGPT plan, with tokens refreshed automatically and no manual key
handling.

## Goals

- A new model-profile format, `chatgpt-plan`, authenticated by OAuth instead of an API key.
- The browser sign-in flow from the console, including first-time dynamic registration.
- Automatic access-token refresh (1 h tokens, rotating 30-day refresh tokens), sign-out with
  remote revocation.
- Model list from the signed-in account, so the operator picks a model they are entitled to.
- Every agent path keeps working: streaming turns, and the non-streaming calls (compaction,
  summaries, task LLM calls) that use `Provider.Complete`.
- Clear, actionable errors for plan limits and revoked access.

## Non-goals

- Claude subscription OAuth and Kimi Code OAuth. Both providers only accept their own first-party
  clients and say impersonating them can suspend the account; Kimi Code is used through its API
  key on a normal `openai` profile instead.
- Impersonating the Codex CLI (its client ID, `originator`, User-Agent, ChatGPT `backend-api`
  endpoints) or producing app-attestation headers, as oh-my-pi does. OpenAI's docs say not to use
  `backend-api` endpoints.
- Running the `codex` binary (Codex app-server) as a sidecar.
- Multi-user or hosted deployments: ARTEX is a single-operator, locally run console. A paid or
  remotely hosted product needs OpenAI's partner programme, which is out of scope.
- Upstreaming: CONTRIBUTING forbids vendor-specific auth, so this lives in the operator's fork.

## Anti-goals

- Silently falling back to an API key or another profile when the plan refuses a request (OpenAI
  forbids silent fallback; the existing failover chain must not hide plan errors either, see
  Failover below).
- Tokens in logs, URLs, the UI, API responses or the LLM audit records.

## Constraints (from OpenAI's docs)

Source: developers.openai.com/siwc/token-sharing-open-source (overview, sign-in, models and
inference, token reference, errors and recovery, preview limitations, self-hosted VMs) and
help.openai.com article 20001542, read 2026-11-26.

- Eligible: open-source projects and personal projects that run locally. ARTEX (AGPL, self-hosted
  on 127.0.0.1) fits; a hosted deployment would not.
- Authorization: `https://auth.openai.com/api/accounts/authorize`; token:
  `https://auth.openai.com/api/accounts/oauth/token`; revocation endpoint from
  `https://auth.openai.com/.well-known/openid-configuration`.
- First sign-in uses `client_id=dynamic_agent_client`, `agent_name_hint=ARTEX`, and a stable
  per-installation `ext_agent_host_id`. The callback returns the issued `client_id`
  (`oaiapp_...`), which must be saved before the code exchange and reused for every later
  sign-in and refresh. Never store `dynamic_agent_client` as the issued ID.
- PKCE S256, fresh `state`, `nonce` and verifier per attempt. Scopes: `openid profile email
  offline_access resource.invoke chatgpt.tokens.use.direct`; `resource=https://api.openai.com/v1`
  on authorize, exchange and refresh. No client secret.
- Redirect URI: HTTP loopback on `127.0.0.1` (not `localhost`); later sign-ins may change only
  the port. The documented example is `http://127.0.0.1:1455/auth/callback`.
- Validate the ID token (JWKS signature, `iss`, `aud` = issued client ID, `exp`, `nonce`) and
  require `chatgpt.tokens.use.direct` in the granted scopes.
- Refresh near expiry, serialised per account; rotation returns a new refresh token that must
  replace the old one atomically. Terminal refresh errors (`invalid_grant`,
  `refresh_token_expired`, `refresh_token_reused`, ...) require a new sign-in with the saved
  client ID.
- Inference: `POST https://api.openai.com/v1/responses` with `Authorization: Bearer <access>`,
  `store:false`, `stream:true` always, `input` as an array, system text via `instructions`.
  Must omit `max_output_tokens`, `temperature`, `top_p`, `metadata`, `previous_response_id` and
  the other fields the docs list. Function tools are supported.
- Models: `GET https://api.openai.com/v1/models` returns `models[]`; show entries with
  `visibility == "list"`, use `slug` as the model and `display_name` as the label.
- Errors: `response.failed` (possibly mid-stream) or HTTP errors with codes such as
  `subscription_sharing_usage_limit_exceeded` (429), `subscription_sharing_user_not_eligible`
  (403), `subscription_sharing_usage_unavailable` (503), `subscription_sharing_invalid_user`
  (401). A stream that ends without `response.completed` is a failure.

## Approaches considered

1. **Official Sign in with ChatGPT, implemented natively (chosen).** Browser OAuth from the
   console, tokens stored encrypted in Postgres, a token-injecting HTTP transport in front of the
   existing `openai-responses` wire format. Sanctioned by OpenAI, no new runtime, fits the
   existing `bedrock-gateway` transport pattern.
2. **Codex CLI impersonation (oh-my-pi's approach).** Works without registration but uses the
   Codex CLI's identity and ChatGPT `backend-api` endpoints, which OpenAI's docs rule out, and
   on macOS oh-my-pi also fakes an app-attestation token. Rejected by the operator's choice after
   discussion.
3. **Codex app-server sidecar.** Official, but it is a second agent runtime speaking JSON-RPC;
   bridging it into Norma would be a much larger change. Rejected.

oh-my-pi (MIT) remains a reference for PKCE handling, refresh serialisation and Responses SSE
parsing; no code is copied, so no attribution file is needed.

## Design

### Profile format

- New profile kind `chatgpt-plan` (constant `db.FormatChatGPTPlan`). *Builder call (fork
  compatibility):* the row is stored as format `openai-responses` with the new column
  `llm_profiles.oauth_account_id` set, and the Go layer reports it as `chatgpt-plan`. The
  `llm_profiles_format_check` constraint is not touched and there is no numbered migration: the
  DDL is an idempotent block at the end of `db/schema.sql`. Upstream's schema re-adds the format
  CHECK on every start and its migration runner refuses unknown migration numbers, so either
  change would stop upstream code (merges, `update.sh`, the GHCR image) from starting on this
  database. The FK is `ON DELETE RESTRICT`, so an account cannot be removed while a profile uses
  it.
- For this format the profile has no API key, base URL is fixed to `https://api.openai.com/v1`
  (not editable), `custom_headers` is refused, streaming is forced on, and `max_tokens` /
  `temperature`-style settings are hidden because the endpoint rejects them. Reasoning effort
  stays available (`reasoning.effort` is accepted).
- Saving a `chatgpt-plan` profile requires `oauth_account_id` to reference a signed-in account.

### Account storage

New table `chatgpt_accounts`:

| column | notes |
|---|---|
| `id` | BIGSERIAL |
| `issuer`, `subject` | from the validated ID token; unique together |
| `email` | display only |
| `client_id` | issued `oaiapp_...` ID for this registration |
| `id_token`, `access_token`, `refresh_token` | encrypted with the existing secret box (new `secretColumns` entries, so key rotation and the at-rest checks cover them) |
| `access_expires_at` | `saved_at + expires_in` |
| `scopes` | TEXT[] of granted scopes |
| `status` | `active` / `needs_signin` / `plan_disabled` |
| `last_error` | short, token-free text for the UI |
| `created_at`, `updated_at` | |

Installation-wide settings (existing settings table):

- `chatgpt_host_id`: `urn:uuid:<v4>` generated once, never changed.
- `chatgpt_client_id`: the issued client ID, written as soon as the callback returns it (before
  the code exchange) so a failed exchange never triggers a second registration. Reused for every
  later authorize request (without `agent_name_hint`).

### Sign-in flow

1. Console calls `POST /api/llm/chatgpt/signin` (authenticated). The server creates a pending
   attempt in memory (state, nonce, PKCE verifier, redirect URI, 10-minute expiry, the account
   being re-authorized if any) and returns the authorize URL. The console opens it in a new tab.
2. Redirect URI: `http://127.0.0.1:<port>/auth/callback`, where `<port>` is the port the
   operator's browser uses to reach ARTEX (taken from the request's Host when it is a loopback
   address, else 8787). The route `GET /auth/callback` is registered on the root mux outside
   `/api/` and outside `requireAuth`; it is protected by the single-use `state`.
3. The callback verifies `state`, handles `error=access_denied`, saves the issued `client_id`
   if this was a registration, exchanges the code, validates the ID token against OpenAI's JWKS
   (`golang-jwt/jwt/v5`, already a dependency; JWKS cached for an hour), checks the granted
   scopes, upserts the `chatgpt_accounts` row, and redirects the browser to the console's LLM
   settings page with a success or error flag (no tokens in the URL).
4. If plan usage was not granted, the account is stored with `status=plan_disabled`, and the UI
   offers "Enable plan usage", which repeats the flow with `prompt=consent`.
5. **Fallback when the browser is not on the ARTEX machine** (console reached through a reverse
   proxy or SSH): the redirect to `127.0.0.1` fails in the browser; the dialog then offers
   "Paste the URL from the address bar", and `POST /api/llm/chatgpt/callback-paste` runs the same
   callback logic on the pasted URL.
6. **Port 1455 fallback:** if OpenAI refuses the first registration on a port other than 1455
   (unknown; the docs only show 1455), the server can open a temporary listener on
   `127.0.0.1:1455` for the attempt. Inside Docker that also needs `127.0.0.1:1455:1455`
   published in `docker-compose.yml`. This is only built if testing shows it is needed.

### Token source and refresh

- `server` provides `ChatGPTTokens.AccessToken(ctx, accountID) (string, error)`: returns the
  stored token if it is valid for more than 5 minutes; otherwise refreshes under a per-account
  mutex (re-reading the row after acquiring it, so concurrent callers do not refresh twice),
  stores the rotated token set in one UPDATE, and returns the new access token.
- Terminal refresh errors set `status=needs_signin` and return an error the agent surfaces as
  "ChatGPT sign-in expired: sign in again in System > LLM". Network errors and 5xx are retried
  with bounded backoff.
- Refresh and revocation requests use the profile's LLM proxy setting, like model requests.

### Model requests (agent package)

- `agent.Config` gains `TokenSource func(ctx context.Context) (string, error)`. For
  `FormatChatGPTPlan`, `NewProvider` uses the `openai-responses` wire format with base URL
  `https://api.openai.com/v1`, a placeholder API key, forces streaming, and wraps the quota-aware
  transport with `chatgptPlanTransport` (same pattern as `bedrockGatewayTransport`):
  - sets `Authorization: Bearer <token from TokenSource>` on every request;
  - rewrites the JSON body: removes `max_output_tokens`, `temperature` and any other field on the
    docs' omit list, and sets `stream:true`;
  - **non-streaming bridge:** when the original body had `stream:false` (Norma's
    `Provider.Complete`, used by compaction, summaries and task LLM calls), it sends
    `stream:true`, reads the SSE stream to `response.completed`, and returns a synthetic
    `200 application/json` response whose body is the `response` object from that event, which
    is exactly what Norma's `parseResponsesResponse` reads;
  - maps `response.failed` / `response.incomplete` and the `subscription_sharing_*` codes to HTTP
    errors with readable messages (429 for the usage limit, so the existing quota handling sees a
    rate-limit; 401/403 for sign-in or eligibility problems).
- The User-Agent is left at Go's default, per the operator's preference; OpenAI documents no
  User-Agent rule for this path.

### Failover and plan limits

*Builder call:* plan refusals never move work to another profile, in any path. The transport
returns every `subscription_sharing_*` / `chatpass_*` error (and a `response.failed` carrying one)
as HTTP 403 with the marker `llmpool.NoFailoverMarker` in the message. 403 is not retried by the
same-provider retry rules. `llmpool.shouldFailover` and the task chain in `server/task_llm.go`
(failure-streak escalation and quota advance) check the marker and stay on the plan profile. In
a task, a plan error ends the call as an exhausted chain, so the intent settles as blocked on LLM
quota (the existing state for exhausted credits) instead of re-running until the run budget is
spent. Non-plan failures (network errors, 5xx) keep the normal failover policy the operator
configured. New `chatgpt-plan` profiles also default to `pool_exclude=true`.

### API and UI

- `GET /api/llm/chatgpt/accounts`: list (email, status, scopes, expiry), no tokens.
- `POST /api/llm/chatgpt/signin`, `GET /auth/callback`, `POST /api/llm/chatgpt/callback-paste`.
- `POST /api/llm/chatgpt/accounts/{id}/signout`: revoke the refresh token (retry on 5xx), clear
  the tokens, keep the row and the client ID for a later sign-in; report when remote revocation
  could not be confirmed.
- `GET /api/llm/models` for a `chatgpt-plan` profile lists the account's models.
- `POST /api/llm/test` works for the new format (one short streamed request).
- System > LLM: the format list gains "ChatGPT plan (Sign in with ChatGPT)". For that format the
  dialog replaces base URL / API key with an account picker, a "Sign in with ChatGPT" button,
  the signed-in email and status, "Sign out", and the paste fallback. A banner explains plan
  limits and links to https://chatgpt.com/settings/usage. All strings go through `t()` with
  entries in every locale file, as the repo's i18n test requires.

### Logging and data hygiene

- Authorize URLs are logged without `id_token_hint`; tokens, codes and verifiers are never
  logged. LLM request audit records must not include the Authorization header (verify the
  existing recorder strips it).
- The callback page response sets `Cache-Control: no-store` and `Referrer-Policy: no-referrer`.

## Testing

- Unit: PKCE and authorize-URL construction; callback state handling (unknown, expired, reused,
  `access_denied`, missing or mismatched `client_id`); ID token validation with a test JWKS;
  scope check; refresh serialisation (two concurrent callers refresh once) and rotation; terminal
  refresh errors; body rewriting; the non-streaming bridge against a recorded SSE stream; error
  mapping for each `subscription_sharing_*` code; secret columns are encrypted at rest.
- Integration: an `httptest` fake of the auth and Responses endpoints driving the full sign-in,
  a streamed turn, a `Complete` call and a refresh.
- Manual: a real sign-in with the operator's ChatGPT account, a task run, and sign-out.

## Left to the builder

- Exact file layout (suggested: `server/chatgpt_oauth.go`, `server/chatgpt_tokens.go`,
  `agent/chatgpt_transport.go`, `db/chatgpt_accounts.go`, a new card component in
  `web/src/app/(main)/system/llm/`).
- JWKS cache details, backoff parameters, and the wording of UI messages.
- Whether the 1455 listener is needed (decided by the first real sign-in).
