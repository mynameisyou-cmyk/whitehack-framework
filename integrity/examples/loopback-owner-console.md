# Assurance dashboard — Synthetic loopback owner console

> Generated from `loopback-owner-console.json`. Structural traceability is not a security guarantee.

## At a glance

| Case | Version | Status | Owners | Last reviewed | Authorization |
|------|---------|--------|--------|---------------|---------------|
| IC-LOOPBACK-OWNER-CONSOLE | 1.0.0 | accepted | example-platform-team | 2026-07-16 | not_required |

| Invariant support | Control support | Evidence | Residual risks |
|-------------------|-----------------|----------|----------------|
| 4/4 (100%) | 4/4 (100%) | 4/4 passing | 1 |

## Intention

Let one local owner inspect and change a development service through a browser console without turning the console into a network service.

**Safety properties**

- Only the authenticated local owner can perform state-changing actions.
- A web page from another origin cannot drive the console through the owner's browser.
- Automation clients receive only the minimum explicitly granted capabilities.
- Bootstrap owner credentials are not persisted or exposed to child processes.

**Non-goals**

- Remote or multi-user administration
- Defense after compromise of the owner's operating-system account
- Storage of production secrets

## Authorization boundary

- **Status:** not_required
- **Scope:** Offline analysis of a synthetic example with no live target or network activity.
- **Evidence reference:** public-example:synthetic-loopback-console
- **Expires:** not time-limited
- **Excluded actions:** Network scanning, Testing any third-party service, Use of real credentials or personal data

## Trust boundaries

| ID | From → to | Carrier | Trust change | Entry points | Data |
|----|-----------|---------|--------------|--------------|------|
| B1 | owner-browser → local-service | HTTP over an operating-system loopback socket | An interactive browser request asks the service to mutate owner state. | POST /missions, POST /decisions | Owner session cookie, CSRF token, JSON mutation payload |
| B2 | untrusted-web → local-service | Cross-origin browser request to a loopback address | Internet-controlled content attempts to reach a local privileged service. | All HTTP routes | Attacker-controlled headers and body |
| B3 | automation-client → local-service | HTTP over loopback with a scoped bearer capability | A non-owner process receives authority over a narrow operation set. | POST /feedback, POST /missions | Scoped capability token, JSON request payload |

## Invariant trace

| ID | Priority | Invariant | Threats | Controls | Evidence | State |
|----|----------|-----------|---------|----------|----------|-------|
| I1 | critical | Every state-changing owner route requires a valid owner session. | T1, T2 | C2 | E2:pass | supported |
| I2 | critical | Browser requests with an untrusted Host or Origin cannot reach privileged behavior. | T1 | C1, C3 | E1:pass, E3:pass | supported |
| I3 | high | Each automation token authorizes only its explicit route allowlist. | T2 | C4 | E4:pass | supported |
| I4 | high | The bootstrap owner token exists only in service memory until it is exchanged for a protected cookie. | T3 | C2 | E2:pass | supported |

## Controls and implementation

| ID | Type | Intention | Implementation | Enforces | Limitations |
|----|------|-----------|----------------|----------|-------------|
| C1 | preventive | Keep the console local and reject unexpected authority headers before routing. | src/owner_console/server.py: bind loopback and validate Host | I2 | Loopback binding does not identify the owner by itself. |
| C2 | preventive | Exchange a single-use in-memory bootstrap token for an HttpOnly, SameSite=Strict owner cookie. | src/owner_console/auth.py: bootstrap exchange and session validation | I1, I4 | A compromised owner account can still inspect service memory or control the browser. |
| C3 | preventive | Require an exact trusted Origin, a CSRF token, and JSON content type on browser mutations. | src/owner_console/http_policy.py: mutation request policy | I2 | The policy relies on browser origin semantics and correct proxy exclusion. |
| C4 | preventive | Resolve automation tokens to immutable route scopes and reject every non-allowlisted route. | src/owner_console/capabilities.py: exact route capability map | I3 | The allowed route can still contain an implementation bug. |

## Evidence

| ID | Result | Kind | Claim | Artifact | Verifies | Observed |
|----|--------|------|-------|----------|----------|----------|
| E1 | pass | test | Unexpected Host values and non-loopback binding attempts are rejected. | tests/test_owner_console_boundary.py::test_rejects_untrusted_host | I2, C1 | 2026-07-16 |
| E2 | pass | test | Owner mutations fail before bootstrap exchange and succeed only with the protected session cookie. | tests/test_owner_console_auth.py::test_owner_session_required | I1, I4, C2 | 2026-07-16 |
| E3 | pass | test | Cross-origin, missing-CSRF, and non-JSON mutation requests are rejected. | tests/test_owner_console_boundary.py::test_browser_mutation_policy | I2, C3 | 2026-07-16 |
| E4 | pass | test | A scoped automation token cannot call an owner-only route or a route outside its allowlist. | tests/test_owner_console_capabilities.py::test_scope_is_exact | I3, C4 | 2026-07-16 |

## Residual risk

| ID | Disposition | Risk | Owner | Review by | Next action |
|----|-------------|------|-------|-----------|-------------|
| R1 | accept | Compromise of the owner's operating-system account can bypass the application's local boundary. | local operator | not scheduled | Reassess the architecture before any remote, shared-user, or production-secret use. |

## Decisions

### D1 — Keep the owner surface loopback-only and issue separate capability tokens to automation clients.

- **Context:** The console is an owner tool, while automation needs a small subset of its operations.
- **Rationale:** Separating owner identity from client capabilities makes least privilege explicit and testable.
- **Consequences:** Remote administration is intentionally unsupported., Every new automation route requires an explicit scope decision and test.
