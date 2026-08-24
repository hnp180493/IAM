# IAM Lab

An interactive lab for learning authentication and authorization. Run each OAuth
flow hop by hop, click any hop to see the real HTTP that crossed the wire, then
take a token apart claim by claim — and hand-edit it to see exactly which check
catches you.

**Bilingual (English / Vietnamese)** — the EN/VI button at the top-right of the
menu toggles the entire app and remembers your choice: UI chrome, navigation,
lesson content, challenge briefs, the glossary, console output, packet-flow
notes, server error reasons, and the policy-engine traces are all fully
translated. Protocol parameter names (`code_challenge`, `S256`, `aud`, `exp`)
always stay in English because they are the real strings that travel on the wire.

## Run

```bash
npm install
npm run dev
```

15 of the 16 lessons run entirely in the browser with nothing else needed. Only
"Run on real OpenIddict" needs a real authorization server:

```bash
cd server-dotnet/IamLab.AuthServer
dotnet run --urls http://localhost:5181
```

## Practice

Twenty-two challenges across four tracks, ordered by how much you have to do
yourself, plus an endless Red Team mode.

### 0. Red Team mode — relentless attacks, real-time defense

An endless mode. Every few seconds a defensive setting is switched off, and the
attacks escalate over time. Use `audit` to inspect, `harden <setting> on` to
patch, before your integrity bar hits zero. The faster you patch, the more points.

**20 attack types**, each one flipping a **real** defensive flag — none is a mere
notification, and `audit` re-reads live state (20 checks) so you cannot score
without actually patching.

### 1. Exploit a vulnerability (6) — hack it, then patch it, in one challenge

Each challenge starts with the system already holding a real hole. You have to
exploit it (the API returns `200` for a forged token), then patch it, then
confirm the same token is now rejected.

| Exploit | Mechanism |
|---|---|
| alg-confusion (HS256/RS256) | Re-sign the token with HS256, using the **real public key** from JWKS as the secret. Real crypto — real HMAC. |
| Key embedded in the token (jwk/jku) | Sign the token with **your own key**, embed your public key in the header; a naive server verifies against that exact key |
| Signature verification off | Edit `roles=admin` keeping the old signature; the server never checks, so it accepts |
| Audience confusion | A public-API token calls the internal API's `/payroll` |
| Session fixation | Plant a known sid, the victim logs in, the sid never changes → session takeover |
| Refresh token forever | No rotation → a stolen refresh works indefinitely; turn rotation on and reuse revokes the whole family |

alg-confusion and key-injection are the two most rewarding — both produce a
**genuinely valid signature** using real crypto:

```
$ jwt forge @access --set roles=admin --hs256 <public key>   # HMAC with the public key
$ jwt forge @access --set roles=admin --own-key              # sign with the attacker's key, embed it in the header
$ curl /me --token @forged                                    # 200 OK, roles=admin
$ harden hs256 on   (or: harden jku on)                       # patch → 401
```

### 2. OWASP web (5) — the classics beyond Auth/IAM

The same hack-then-patch loop against a deliberately vulnerable web app, driven
by the `app` command in the console. Each vulnerability has a real defensive flag
in the posture, and the payloads work because they genuinely break the structure
— not because a string matched a known-payload list.

| Exploit | Mechanism | Patch |
|---|---|---|
| SQL injection | `app login "admin'--" x` bypasses auth; `app search "x%' UNION SELECT password FROM users --"` leaks the password table | `harden sqli on` |
| Stored XSS | `app comment "<script>…</script>"` then `app render` executes the payload | `harden xss on` |
| SSRF | `app fetch "http://169.254.169.254/…"` reaches cloud metadata credentials | `harden ssrf on` |
| Path traversal | `app download "../../../etc/passwd"` reads a file outside the web root | `harden traversal on` |
| Command injection | `app ping "8.8.8.8; cat /etc/shadow"` runs a second command (RCE) | `harden cmdi on` |

Each patch flips the app from string-concatenation to the safe primitive
(parameterized queries, output escaping, an SSRF guard on the resolved IP,
canonicalize-then-confine, and array args instead of a shell), and the same
payload is then rejected.

### 3. Hands-on console challenges (6) — no answers to click through

A dedicated console, real commands. Objectives tick right after each command.

```
$ authorize --pkce plain
$ token --code code-xxx --verifier <the string you read off the URL>
$ jwt forge @access --set roles=admin
$ curl /me --token @forged
$ policy eval alice delete doc:42 --model all
```

| Challenge | What you have to do |
|---|---|
| Log in by hand | Type all 3 steps of code + PKCE until the API returns 200 |
| Play the attacker | Steal alice's token via `plain`, then prove `S256` blocks it |
| Make the API accept a fake token | Edit the token 3 ways, note which check each one dies at |
| Diagnose a 403 | Reproduce → read the token to find the cause → fix it to a 200 |
| Find where authorization disagrees | Find a case where all 3 models disagree, and one where they agree |
| Prove sessions revoke instantly | Prove with commands that a session revokes but a JWT does not |

Commands have tab completion, up/down history, and tokens are saved by name and
referenced as `@access` / `@forged`.

### 4. Configuration challenges (5) — the warm-up

Dropdowns, for when the terminology is still new. "Kill the zombie session" has
two switches and **flipping one is not enough**.

| Challenge | Situation |
|---|---|
| Patch the PKCE hole | Someone exchanged a stolen code for a token. Block it, but the real client must still get in. |
| Stop audience confusion | The internal API is returning payroll data for a public-API token. |
| Cut scopes to the minimum | The app only needs to read but is requesting `admin:all`. |
| Kill the zombie session | Logged out, yet App 2 still shows signed in. |
| Investigate: broken login | After a domain change nobody can get in. Find the right `redirect_uri`. |

### 5. Tamper & replay

In "Edit a token to become admin", you hand-edit the claims and fire the forged
token at the real API.

### 6. Fix the C#, then audit

An automated checker attacks your real server:

```bash
npm run audit
```

13 checks, each naming the problem, why it is dangerous, and the line of code to
fix. It **does not read your config file** — it attacks for real and concludes
from the real response, so editing a comment won't fool it. To watch it catch a
bug, introduce a hole yourself:

```bash
LAB_ALLOW_PLAIN_PKCE=1 dotnet run --urls http://localhost:5181
```

The audit drops to 12/13 and points at the exact spot.

## The crypto is real

This is a *network* simulation, not a *cryptography* simulation. Every token is
signed with a 2048-bit RSA key generated right in your browser, and every
rejection is a real check actually failing:

- `code_challenge` is a real SHA-256 hash (RFC 7636)
- tokens are real RS256 JWTs, verified against a real JWKS
- passwords are hashed with real PBKDF2-HMAC-SHA256, 100,000 rounds
- flip one byte in the payload and the signature is wrong, because it genuinely is

So when the lab says an attacker can't redeem a stolen authorization code under
`S256`, that isn't a staged outcome. That is SHA-256 refusing to be reversed.

## 16 lessons

| Chapter | Lesson | What it shows |
|---|---|---|
| 1. Foundations | Session cookies vs tokens | Revoking a session takes effect immediately — the one thing a JWT can't do |
| 2. OAuth 2.0 | A standard login flow | 11 hops of one login, and why it has to be that long |
| | No PKCE: account takeover | An attacker steals the code and exchanges it for a real token |
| | S256 stops the thief | Still steals the code, but gets `400 invalid_grant` |
| | PKCE downgraded to `plain` | PKCE on, yet lost — over one wrong parameter |
| 3. JWT | Take a token apart | 13 claims, 8 checks, hover for the explanation |
| | Token expiry | Fast-forward 60x, watch a 300-second token die in 5 seconds |
| | Edit a token to become admin | You are the attacker: edit a claim and fire it back at the API |
| | Audience confusion | A valid API-A token opens API B |
| 4. Authorization | How 401 differs from 403 | A perfect token still blocked, for a missing scope |
| | RBAC, ABAC, ReBAC | One request, three models, three different answers |
| 5. SSO | One login, two apps | The session lives at the auth server, not the app |
| | Logout is the hard part | Zombie sessions after you click log out |
| 6. OpenIddict | Run on real OpenIddict | Cross-check the mock against a real authorization server |
| | Client Credentials (M2M) | Logging in when there is no user |
| | Refresh rotation on a real server | OpenIddict catches a reused refresh token |

## Tamper & replay

In "Edit a token to become admin", the **Tamper & replay** button on the token
inspector opens a dialog to edit the header and payload directly. The token is
reassembled with the **original signature kept** — exactly what an attacker can
do, since they don't have the private key. Four attacks are prebuilt, and each
dies at a different check:

| Attack | Dies at |
|---|---|
| Raise `roles` to admin | `signature` |
| Change `alg` to `none` | `alg` then `signature` |
| Extend `exp` by 10 years | `signature` |
| Change `aud` to the internal API | `signature` and `aud` |

## What only a real server reveals

The chapter-6 lesson exists to cross-check, and it caught a place where the mock
was wrong.

`RequireProofKeyForCodeExchange()` **only forces PKCE to be present, not that the
method be `S256`**. OpenIddict still advertises `plain` in discovery and still
accepts `plain` at `/connect/token` — verified: `200 OK`. To actually block it,
you have to remove it from the list:

```csharp
options.AllowAuthorizationCodeFlow()
       .RequireProofKeyForCodeExchange();

// This line is the one that actually blocks plain.
options.Configure(o => o.CodeChallengeMethods.Remove(CodeChallengeMethods.Plain));
```

Set `LAB_ALLOW_PLAIN_PKCE=1` and restart the server to re-enable `plain` and
compare.

## Layout

```
src/
  crypto/   jose.ts     RS256 sign/verify, JWKS, verdict as a list of checks
            pkce.ts     S256 derivation and verification
  server/   MockAuthServer.ts  /authorize + /token + SSO session
            ResourceApi.ts     verifies with the public key only
            SessionServer.ts   PBKDF2 + revocable sessions
  engine/   PolicyEngine.ts    RBAC / ABAC / ReBAC, with a reasoning trace
            Posture.ts         every defensive flag, and the audit checks
            WebVulnServer.ts   the vulnerable web app (OWASP track)
            RedTeamEngine.ts   escalating attacks that read live posture
            LabSession.ts      the console command surface
  flows/    authCodePkce · sessionCookie · audConfusion · policyModels
            sso · openiddictReal · openiddictExtra
  ui/       Menu · Tutorial · Stage · Inspector · Hud · TamperDialog · Console
  core/     Clock.ts     simulated time, so you can watch tokens expire
  data/     lessons.ts · glossary.ts · claims.ts · attacks.ts
            challenges.ts · exploitChallenges · consoleChallenges · webChallenges
  i18n/     index.ts (tr/t/pick) · content.ts (EN overlay for large content)

server-dotnet/IamLab.AuthServer/
  Program.cs             OpenIddict 6 on ASP.NET Core 9, SQLite
```

## Why the diagram is 2D

k8sgames draws a Kubernetes cluster — something *spatial*, so a 3D scene earns its
keep. An auth flow is *temporal*: what's worth seeing is the order of the hops and
what each one carries. So the stage here is a sequence diagram, and its vertical
axis is time.

The design and the still-unbuilt parts live in [docs/DESIGN.md](docs/DESIGN.md).
