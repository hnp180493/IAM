# IAM Lab — Design Spec

Interactive browser lab for learning Authentication & Authorization.
Inspired by k8sgames.com; mock-only (no backend), real crypto via WebCrypto.

## Decisions

| | |
|---|---|
| Backend | None. Mock auth server in-browser. |
| Crypto | **Real** via WebCrypto: RS256/ES256 sign+verify, PKCE S256, HMAC. Tokens are genuinely valid/invalid. |
| Stack | Vite + TypeScript, SVG/Canvas for flow rendering, no UI framework initially |
| Deploy | Static (any host) |

## Layer model (copied from k8sgames)

All UI is `position: fixed` overlay on a full-bleed stage. No layout flow.

```
z 200  tutorial overlay (per-mode, first run)
z 100  main menu
z  50  http console (bottom, slide-up)
z  40  hud (top, 57px, always visible)
z  30  side panels: inspector (right 384), attack panel (left 320), timeline (bottom 240)
z  20  minimap / timeline scrubber
z   1  flow canvas (stage)
```

Panels live off-viewport when hidden (`translateX(-320px)`) and animate `transform` only.
Never unmount — state survives.

## Stage: flow canvas

Auth is temporal, not spatial. So the stage is a **lane diagram**, not a 3D scene.

- 5 vertical lanes: `Browser | Client App | Auth Server | IdP | Resource API`
- Packets (HTTP request/response) animate horizontally between lanes
- Click a packet -> raw HTTP text in inspector
- Lanes are configurable per level (M2M flow has no Browser lane)

## Core modules

```
src/
  state/       IdentityState  - users, clients, idps, apis, scopes, roles,
                                permissions, policies, sessions, tokens, keys
                                (indexed by id/kind/owner, same pattern as ClusterState)
  crypto/      Jose           - real WebCrypto: keygen, sign, verify, JWKS, PKCE
  engine/      Clock          - fixed timestep; drives exp/nbf, refresh rotation,
                                sliding sessions, key rotation, lockout counters
               FlowEngine     - executes a flow step-by-step, emits packets
               AttackEngine   - spawns attacks (see data/attacks.ts), tracks
                                investigation + resolution (IncidentEngine shape)
               PolicyEngine   - RBAC -> ABAC -> ReBAC evaluation, explainable
               PostureEngine  - scores design 0-100 across 8 categories
  flows/       AuthCodePkce, ClientCredentials, DeviceCode, RefreshRotation,
               Implicit (as anti-pattern), ResourceOwnerPassword (anti-pattern),
               SsoMultiApp, FrontChannelLogout, BackChannelLogout
  ui/          Hud, Stage, Palette, Inspector, HttpConsole, AttackPanel,
               Timeline, TamperDialog, TutorialOverlay
  data/        attacks.ts     ~30 defs (see below)
               levels.ts      6 chapters
               achievements.ts
  modes/       Campaign, RedTeam, Sandbox, Challenges
```

## Attack library (~30)

Same declarative schema as k8sgames IncidentDefs:
`{ id, name, category, severity, description, investigationSteps[], resolutionActions[], autoResolve }`

**Token**: alg=none, signature stripping, HMAC/RSA key confusion, aud confusion,
exp/nbf ignored, kid injection, SSRF via jwks_uri, unrevocable JWT
**Flow**: missing state (CSRF), open redirect_uri, code interception (no PKCE),
PKCE downgrade S256->plain, IdP mix-up, code replay, implicit leak via Referer,
refresh reuse (no rotation)
**Session/SSO**: session fixation, missing SameSite/HttpOnly, XSS token theft from
localStorage, broken back-channel logout (SSO zombie), IdP-initiated login forgery
**Authorization**: IDOR, missing function-level authz, privilege escalation via role
mapping, scope creep, confused deputy, multi-tenant leak, wildcard permission

## Chapters (Campaign)

1. **Basics** - password hashing, session cookie, why cookies != tokens
2. **OAuth2 / OIDC** - code+PKCE, client credentials, device code, refresh, why implicit died
3. **Tokens** - JWT anatomy, JWS vs JWE, claims, JWKS + key rotation, reference vs self-contained
4. **SSO** - multi-app SSO, front/back-channel logout, federation, IdP-initiated
5. **Authorization** - RBAC -> ABAC -> ReBAC, scopes vs permissions, multi-tenant
6. **Hardening** - mTLS, DPoP, token binding, rate limit, audit log, key rotation policy

## Modes

| Mode | What you do |
|---|---|
| Campaign | 6 chapters, guided, objectives + hints |
| Red Team | Endless attacks escalate; you detect and fix. (= Chaos Mode) |
| Sandbox | Free build an IAM topology, Posture Engine scores it |
| Challenges | Timed CTF-ish: "steal admin's data", "fix broken auth in 3 min" |

## Non-negotiable UX details

- **Time scale 1x/2x/4x/60x** in HUD. Token exp is 5 min; without fast-forward you
  cannot observe refresh rotation or key rotation.
- **Tamper & Replay**: edit any packet (token, query param, header) mid-flight and
  re-send. Watch the server accept or reject. This is the strongest teaching moment.
- **Explainable verdicts**: every reject shows *which* check failed and why.
- **1 click from menu to playing.** No setup screen.
