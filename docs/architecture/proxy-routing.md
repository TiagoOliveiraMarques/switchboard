# Proxy routing (v1)

## Scope

This document defines how the Proxy routes **inbound webhook notifications** (HTTP requests received on the Proxy’s public
ingress endpoint) to the correct authenticated Agent tunnel.

In particular, it specifies how to **correlate** an inbound notification to a **previously observed outbound request**
made by an Agent to a third-party system.

It does **not** define:

- The Agent ↔ Proxy authentication handshake (see `agent-proxy-authentication.md`)
- The tunnel framing protocol (see `tunnel-protocol.md`)
- How Agents capture outbound HTTP traffic (implementation detail; this doc only defines what data the Proxy needs)

## Goals

- Route each inbound webhook notification to the correct `agent_id` (developer machine) when possible.
- Support integration-specific correlation logic (different systems embed IDs in different places).
- Be safe by default: avoid “best guess” routing that could leak another developer’s webhooks.
- Be efficient: correlation should be \(O(1)\) or \(O(\log n)\) per inbound notification, not a scan.
- Be observable: when routing fails, operators can understand why.

## Non-goals (v1)

- Automatic inference of correlation rules.
- Content-based authorization beyond correlation (who is allowed to receive which events).
- Long-term retention of all outbound/inbound payloads (v1 focuses on short TTL correlation).

## Terminology

- **Agent**: Client running on a developer machine; authenticated to the Proxy as an `agent_id`.
- **Proxy**: Public-facing Switchboard service that receives webhooks and routes to Agents.
- **Inbound notification**: A webhook HTTP request received by the Proxy.
- **Outbound observation**: A record of an outbound HTTP request (and optionally response) made by an Agent to a third-party system.
- **Correlation key**: A value computed from inbound and outbound data used to join inbound ↔ outbound.
- **Rule**: A Proxy-side configuration describing (a) which inbound notifications it applies to and (b) how to correlate.

## High-level approach

1. The Proxy receives an inbound notification at ingress.
2. The Proxy selects candidate correlation rules by inbound shape (method/path and optional header constraints).
3. For each candidate rule, the Proxy extracts a correlation key from the inbound notification.
4. The Proxy looks up that key in a time-bounded index of recent outbound observations.
5. If the match is unique, the Proxy routes the inbound notification to the matched `agent_id` via that Agent’s tunnel.

The key idea is that routing is **rule-driven** and relies on a short-lived, indexed store of recent outbound observations,
so the Proxy does not need to scan historical requests.

## Data model (conceptual)

### Inbound notification (normalized view)

When the Proxy receives an inbound HTTP request, it normalizes a subset of fields for rule matching and key extraction:

- `received_at_ms`
- `method`
- `path` (URL path only, excluding query)
- `query` (map of query params; multi-valued params MAY be represented as an array)
- `headers` (case-insensitive map)
- `body` (raw bytes; Proxy MAY also parse JSON or parse XML for selectors when content-type indicates JSON or XML respectively)
- `remote_ip` (for logging/rate-limiting; not for correlation)

### Outbound observation (normalized view)

For correlation, the Proxy needs a subset of outbound request/response information observed from an Agent:

- `agent_id`
- `seen_at_ms`
- `request.method`
- `request.url` (broken down into `host`, `path`, `query`)
- `request.headers` (optional)
- `request.body` (optional; raw bytes and/or parsed JSON when content-type indicates JSON)
- `response.status` (optional)
- `response.headers` (optional)
- `response.body` (optional; often needed because many APIs return IDs only in the response)

Notes:

- If a correlation rule depends on a field that might only exist in the response, the Agent MUST provide response metadata
  for those calls (or correlation will fail for that integration).

## Correlation rule registry

The Proxy maintains a registry of correlation rules. Each rule has:

- An **inbound matcher** that decides whether the rule applies to a given inbound notification.
- A **correlation definition** that specifies how to compute a correlation key for inbound and outbound sides.
- A **TTL** that limits how long outbound observations are eligible for matching.

Routing policy note:

- The Proxy routing policy is **fixed** in v1: matches MUST be **unique**. This behavior is NOT configurable.

### Ruleset updates and orphaning

Rules may change over time (new matchers, new correlation fields, removed rules, etc.). In v1 it is acceptable that a new
ruleset causes some previously stored outbound observations to become **orphaned** (i.e., no inbound notification will
match them under the new ruleset).

Operationally this means:

- The Proxy evaluates inbound notifications against the **current** ruleset only.
- Outbound observations are retained until TTL eviction, but they may become unused for routing after a ruleset update.

### Rule matching (inbound)

Each rule MUST define an inbound matcher with:

- `method` (e.g., `POST`)
- `path` match mode:
  - `exact`: exact string equality
  - `prefix`: path begins with a prefix
  - `regex`: regular expression (use sparingly; can be slower and easier to misconfigure)
- optional `headers` constraints (exact equality on one or more header names)

Rationale:

- Many webhook senders deliver multiple webhook “event types” to the same path; headers are often the discriminator.

### Selectors and extraction

Correlation keys are computed by extracting values from inbound/outbound normalized views.

Selectors SHOULD support:

- `header.<name>` (e.g., `header.X-GitHub-Event`)
- `query.<name>` (e.g., `query.installation_id`)
- `path` or `path_param.<name>` (if the matcher uses a templated path pattern)
- `json.<jsonpath>` from a JSON-parsed body (e.g., `json.$.data.object.customer`)

For v1, it is acceptable to standardize on **JSONPath** (or a restricted subset) for JSON body extraction.

### Correlation definition

A rule computes a **single correlation key** (string) using one or more extracted fields.

Recommended v1 behavior:

- A rule defines a list of `key_parts` (each part extracts one value and stringifies it).
- The correlation key is then `join(":", key_parts)`.

Example:

- `key_parts = [inbound.json.$.repository.full_name]` → `key = "octo-org/octo-repo"`
- `key_parts = [inbound.json.$.account, inbound.header.Stripe-Signature]` → `key = "acct_123:..."`

If any required extraction fails, the rule does not match (treated as no-match for that rule).

### Routing policy

Routing MUST be safe-by-default:

- The Proxy MUST require a **unique** match for an inbound notification.
- If multiple candidate outbound observations match the same key across different `agent_id`s, the Proxy MUST treat the
  inbound notification as **ambiguous** and MUST NOT route it.

This behavior MUST NOT be configurable.

### Example rule (matches your “xyz = abc” idea)

Conceptual YAML (shape only; not a required on-disk format):

```yaml
id: lorem-ipsum-v1
match:
  method: POST
  path:
    mode: exact
    value: /lorem/ipsum
correlate:
  ttl_ms: 86400000 # 24h
  key_parts:
    - source: inbound.json
      path: $.abc
  outbound_key_parts:
    - source: outbound.request.json
      path: $.xyz
```

The computed inbound key is the inbound field `abc`. The computed outbound key is the outbound field `xyz`. A match occurs
when the keys are equal.

## Outbound observation store and index

### Requirements

The Proxy MUST store outbound observations for a bounded time window (TTL) and SHOULD maintain indexes to avoid scanning.

In v1 we assume a PostgreSQL-backed implementation:

- Outbound observations are stored once (canonical source of truth).
- Database indexes are used as accelerators.

### PostgreSQL schema (suggested)

Canonical outbound observations:

- Table: `outbound_observations`
  - Partitioning: range-partitioned by `expires_at` into fixed time slots (e.g., hourly or daily partitions)
  - `observation_id` (UUID, PK)
  - `agent_id` (TEXT)
  - `seen_at` (TIMESTAMPTZ)
  - `expires_at` (TIMESTAMPTZ)
  - `request_method` (TEXT)
  - `request_host` (TEXT)
  - `request_path` (TEXT)
  - `request_query` (JSONB, NULLABLE)
  - `request_headers` (JSONB, NULLABLE)
  - `request_body_json` (JSONB, NULLABLE)
  - `response_status` (INT, NULLABLE)
  - `response_headers` (JSONB, NULLABLE)
  - `response_body_json` (JSONB, NULLABLE)

Recommended baseline indexes (created on the partitioned table, applied per partition):

- `outbound_observations(expires_at)` (partition pruning and TTL management)
- `outbound_observations(seen_at DESC)` (for “recent-only” scan patterns)

### Rule-driven database indexes (on demand)

For a given rule, the Proxy can translate the outbound correlation selector into a PostgreSQL expression and create a
matching index on `outbound_observations`.

Example:

- Rule outbound selector: `outbound.request.body.customer.id`
- Backing column: `request_body_json`
- PostgreSQL expression: `(request_body_json #>> '{customer,id}')`

Suggested index:

- `CREATE INDEX CONCURRENTLY idx_out_obs_req_customer_id ON outbound_observations ((request_body_json #>> '{customer,id}'))`

If queries always include a TTL filter, a multicolumn index can help:

- `CREATE INDEX CONCURRENTLY idx_out_obs_req_customer_id_expires ON outbound_observations ((request_body_json #>> '{customer,id}'), expires_at)`

Notes:

- Expression indexes only help when the query predicate uses the same expression.
- JSONPath/selector features in rules SHOULD be restricted to expressions that can be mapped to PostgreSQL operators like
  `->`, `->>`, and `#>>` (or otherwise expect scans).
- All index builds SHOULD use `CREATE INDEX CONCURRENTLY` to avoid blocking reads/writes.

Each observation reference MUST include at least:

- `agent_id`
- `seen_at_ms` (or equivalent timestamp)
- a stable internal `observation_id` (for debugging and eviction)

### Insert/update

When a new outbound observation arrives:

1. Insert a row into `outbound_observations` with an `expires_at` based on the configured TTL.

Ruleset changes:

- When a new ruleset is activated, the Proxy MAY create new PostgreSQL indexes in the background for the new rules’
  outbound selectors (and it MAY drop indexes that are no longer needed).

### Lookup

When an inbound notification arrives and rule `R` applies:

1. Extract the inbound key using `R.key_parts`.
2. Query `outbound_observations` for matches by translating the rule’s outbound selector(s) into SQL predicates.
   - Example predicate (for `request_body_json.customer.id`):
     - `(request_body_json #>> '{customer,id}') = :inbound_key`
   - The query MUST filter out expired observations, e.g. `expires_at > now()`.
   - If a matching PostgreSQL index exists, it will be used automatically by the query planner.
3. If no suitable index exists (or the predicate cannot be mapped cleanly to SQL), the Proxy MAY fall back to a bounded
   scan (still constrained by `expires_at > now()`).
4. Apply routing policy (must be unique):
   - 0 candidates: no-match
   - 1 distinct `agent_id`: route
   - >1 distinct `agent_id`: ambiguous (do not route)

### TTL and eviction

Outbound observations MUST be evicted after `ttl_ms` to:

- minimize the chance of matching stale configuration
- reduce memory/storage footprint
- reduce risk of key collisions across long time windows

Recommended defaults:

- `ttl_ms = 24h` for integrations where webhook configuration persists and is updated occasionally
- `ttl_ms = 1h` for flows that are expected to be immediate (e.g., quick test runs)

PostgreSQL eviction approach:

- The `outbound_observations` table MUST be partitioned by time.
- TTL eviction SHOULD be done by dropping whole time-slot partitions whose upper bound is fully expired.
  - Example: if partitions are daily by `expires_at`, the retention job drops all partitions where
    `partition.expires_at_to <= now()`.
- This enables fast retention without large delete workloads and reduces table bloat.

Operational notes:

- Partitions SHOULD be created ahead of time (e.g., keep the next N days created) to avoid write failures.
- When using partitioning by `expires_at`, the lookup predicate `expires_at > now()` enables partition pruning.

## Safety and security posture

### No-match behavior

If no rule yields a unique match, the Proxy MUST NOT “guess” the agent.

Recommended behavior:

- Return a non-2xx (e.g., `404`) to the webhook sender, or
- Return `202 Accepted` but record the event for later inspection/replay.

Which one to choose is integration-dependent; some webhook senders retry aggressively on non-2xx, which may be desirable.

### Ambiguous-match behavior

If more than one `agent_id` matches, the Proxy MUST:

- treat as unroutable (do not deliver to any agent)
- emit a structured log/event indicating ambiguity (rule id, key, candidate agent_ids)

Rationale: routing to the wrong developer is a confidentiality bug.

### Isolation / partitioning (recommended)

This design assumes the Proxy has some concept of isolation (e.g., separate ingress endpoints or separate deployments)
so that unrelated teams do not share a correlation database. The specifics are out of scope for this document.

## Observability

The Proxy SHOULD emit structured logs/metrics for:

- `rule_selected` (rule id, method/path, header matches)
- `key_extracted` (rule id, key hash, extraction success/failure)
- `candidates_found` (count)
- `route_success` (agent_id, tunnel id/connection id)
- `route_failure` (no-match vs ambiguous vs delivery failure)

For privacy, logs SHOULD avoid raw payloads; prefer:

- hashed keys (e.g., sha256(key)) plus rule id
- counts/sizes
- redacted header names

## Worked examples

### GitHub webhooks (example)

Inbound:

- `path = /webhook/github`
- body JSON includes `repository.full_name`
- header `X-GitHub-Event` discriminates event types (optional)

Outbound (from Agent):

- call to GitHub API to create a webhook for `owner/repo`
- the outbound request URL path contains `/repos/{owner}/{repo}/hooks`

Correlation key:

- inbound: `json.$.repository.full_name` → `"octo-org/octo-repo"`
- outbound: derive `"{owner}/{repo}"` from request URL path → `"octo-org/octo-repo"`

Result: inbound webhook routes to the unique agent whose outbound observation matches that repo key.
If more than one agent matches within the TTL window, routing is ambiguous and the webhook is not routed.

### Stripe webhooks (example)

Stripe often sends events that reference objects by ID in the body, e.g. `customer`, `subscription`, `invoice`.

If the local app creates the relevant object, outbound observations can capture the returned ID:

- outbound response JSON includes `id = "cus_123"`
- inbound event includes `data.object.customer = "cus_123"`

Correlation key:

- inbound: `json.$.data.object.customer`
- outbound: `response.json.$.id`

This example illustrates why outbound **response** capture can be required for some integrations.

## Open questions (for iteration)

- What is the application-level message format between Agent and Proxy for outbound observations (JSON/CBOR/Protobuf)?
- Which integrations do we support first, and what are their canonical correlation keys?
- Do we need a replay/dead-letter workflow for unroutable inbound webhooks?
- How should multi-tenant isolation be represented in ingress URLs or authentication?
