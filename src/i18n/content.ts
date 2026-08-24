import { getLang } from './index';
import type { Lesson } from '../data/lessons';
import type { Challenge } from '../data/challenges';

/**
 * Lớp phủ tiếng Anh cho nội dung, khoá theo id. Để riêng khỏi data files (vốn
 * là tiếng Việt gốc) nên thêm/sửa bản dịch không đụng tới logic. Thiếu bản dịch
 * thì tự lùi về tiếng Việt.
 */

interface LessonEn {
  title?: string;
  tagline?: string;
  question?: string;
  goal?: string;
  steps?: string[];
  watchFor?: string;
}

interface ChallengeEn {
  title?: string;
  brief?: string;
  hints?: string[];
  debrief?: string;
  /** Keyed by objective id, since matching by array index is fragile. */
  objectives?: Record<string, string>;
  /** Keyed by knob id. */
  knobs?: Record<string, { label?: string; help?: string; options?: Record<string, string> }>;
}

export const CHAPTERS_EN: Record<number, { title: string; blurb: string }> = {
  1: { title: 'Foundations', blurb: 'Why you can’t just roll your own login and be done' },
  2: { title: 'OAuth 2.0 and OIDC', blurb: 'The delegation flow, and where it breaks' },
  3: { title: 'JWT', blurb: 'Take a token apart, then try to forge it' },
  4: { title: 'Authorization', blurb: 'Knowing who you are is not permission to act' },
  5: { title: 'SSO', blurb: 'One login, and the logout problem' },
  6: { title: 'Real OpenIddict', blurb: 'Configure a real authorization server in .NET' },
};

const LESSONS_EN: Record<string, LessonEn> = {
  'pkce-happy': {
    title: 'A standard login flow',
    tagline: 'Authorization Code + PKCE, end to end',
    question: 'How many steps are really behind "Sign in with Google"?',
    goal: 'See all 11 hops of one successful login, and understand why it takes this many steps instead of the app just asking for a password.',
    steps: [
      'Press "Run flow" and watch the diagram draw itself hop by hop.',
      'Notice hop 2: the client generates a code_verifier but only sends the hash of it, code_challenge.',
      'Notice hop 4: the code comes back through the browser address bar — so treat it as public.',
      'Notice hop 8: code_verifier is sent for the first time, over its own channel that never touches the browser.',
      'Click any arrow to read the real HTTP that crossed the wire.',
    ],
    watchFor: 'The user\'s password never goes through the app. The app only ever receives tokens, and only on the back channel. That is the entire reason this flow has this many steps.',
  },
  'pkce-none': {
    title: 'No PKCE: account takeover',
    tagline: 'The thief only needs to read one URL',
    question: 'The code sits in the address bar — so what if someone reads it?',
    goal: 'Watch an attacker take an authorization code straight from a redirect and exchange it for a valid access token belonging to someone else.',
    steps: [
      'Press "Run flow". Notice the red Attacker column appear.',
      'Watch the "Code leaks to the attacker" hop: in real life this is a malicious app on the same device, a proxy log, or a Referer leak.',
      'Watch the "POST /token (stolen code)" hop return 200 OK.',
      'Click that hop and open the Token tab: that is a real access token, really signed, really usable.',
    ],
    watchFor: 'The auth server did nothing wrong. It has no way to tell the thief apart from the real client — both present the exact same code. Without PKCE, a code is cash.',
  },
  'pkce-s256': {
    title: 'S256 stops the thief',
    tagline: 'Still steals the code, but it’s useless',
    question: 'Why does a stolen code still not get them in?',
    goal: 'Understand that PKCE does not protect the code itself — it protects the right to redeem it.',
    steps: [
      'Press "Run flow". The attacker still steals the code, exactly like last time.',
      'But the "POST /token (stolen code)" hop now gets 400 invalid_grant.',
      'Click that 400 and read the server\'s reason.',
      'Compare with the "No PKCE" lesson: the exact same stolen code, one parameter different.',
    ],
    watchFor: 'The attacker would need a string whose SHA-256 equals the code_challenge — that is reversing a hash, which is not feasible. This is real SHA-256 running in your browser right now.',
  },
  'pkce-plain': {
    title: 'PKCE downgraded to plain',
    tagline: 'PKCE on, yet lost — over one wrong setting',
    question: 'You turned PKCE on. Are you safe now?',
    goal: 'See why code_challenge_method=plain turns PKCE on without protecting anything.',
    steps: [
      'Press "Run flow".',
      'Click hop 2 and read the /authorize URL: with plain, code_challenge IS code_verifier, sitting there in plain text.',
      'Watch the attacker read that URL and replay it: 200 OK.',
      'Switch the PKCE dropdown to S256 and run again. Same scenario, now it fails.',
    ],
    watchFor: 'This is a configuration bug, not a protocol flaw. In OpenIddict it corresponds to never calling RequireProofKeyForCodeExchange, or letting the client pick its own method. Always force S256 server-side.',
  },
  'jwt-anatomy': {
    title: 'Dissect a JWT',
    tagline: 'Three blocks, thirteen claims, eight checks',
    question: 'What’s inside that long gibberish string?',
    goal: 'Read every claim in an access token, and know exactly what the API checks before it accepts one.',
    steps: [
      'Press "Run flow" and wait for it to finish.',
      'Click the "GET /me (Bearer)" arrow, then open the Token tab.',
      'The three colored blocks are header, payload, signature — base64url, not encryption. Anyone can read them.',
      'Hover any claim to see what it is for and what breaks if it is dropped.',
      'Scroll down to see all 8 checks the API ran.',
    ],
    watchFor: 'A readable payload does not mean an editable one. The signature covers both header and payload — change one byte and the signature breaks. But readable does mean: never put secret data in a JWT.',
  },
  'jwt-exp': {
    title: 'Token expiry',
    tagline: 'Fast-forward 60x to watch it die',
    question: 'Why does an access token live only 5 minutes?',
    goal: 'Understand that exp is the only revocation a self-contained token has, and why lifetimes must stay short.',
    steps: [
      'Press "Run flow" — the "expires in" box up top shows 300s.',
      'Speed is already set to 60x, so the simulated clock runs 60 times faster.',
      'Watch for about 5 real seconds: 300 simulated seconds pass and the token dies.',
      'Click the GET /me hop, Token tab, and look at the exp claim next to its absolute time.',
    ],
    watchFor: 'Fire someone, and their token still works until exp passes. There is no way to call it back. Anything that needs instant revocation must be checked live, never read from a claim.',
  },
  'jwt-tamper': {
    title: 'Edit a token to become admin',
    tagline: 'Editable payload, unforgeable signature',
    question: 'The payload is readable — so can you set roles to admin?',
    goal: 'Edit a claim by hand and fire it at the real API to see exactly which check catches it. This is the one lesson where you are the attacker.',
    steps: [
      'Press "Run flow" and wait for it to finish.',
      'Click the "GET /me (Bearer)" hop, open the Token tab, and press "Tamper & replay".',
      'Press "Escalate roles to admin", then "Replay against the API".',
      'Now try "Switch alg to none" and "Extend exp by 10 years".',
      'Read carefully which check turns red for each attack.',
    ],
    watchFor: 'The signature is reassembled from the original, because the attacker has no private key. That is why every payload edit dies at the signature check. alg=none alone dies at the alg check — and if a server trusts the header to pick how to verify, that exact attack gets through.',
  },
  'jwt-aud': {
    title: 'Audience confusion',
    tagline: 'A valid token, just not for you',
    question: 'What if API A’s real token is used on API B?',
    goal: 'See how skipping exactly one aud check opens the door for a low-privilege service to call a high-privilege one.',
    steps: [
      'Press "Run flow". In this lesson the internal API has the aud check turned OFF.',
      'First hop: a token is issued with aud = api.example.com.',
      'Middle hop: calling that exact API — 200 OK. Normal.',
      'Last hop: the same token calls the internal API — and it returns payroll data.',
      'Click the last hop, Token tab: the signature is still green. Nothing about the signature is wrong.',
    ],
    watchFor: 'A signature only proves who issued a token, never who it was issued for. Skipping the aud check turns every token from one issuer into a master key for every API.',
  },
  'authz-401-403': {
    title: 'How 401 differs from 403',
    tagline: 'A perfect token, still blocked',
    question: 'Logged in and still getting a permission error?',
    goal: 'Tell authentication (who are you) apart from authorization (what may you do), and see that scope is not a permission system.',
    steps: [
      'This lesson presets "API requires" to admin:everything — a scope the token doesn\'t carry.',
      'Press "Run flow". The last hop returns 403 Forbidden, not 401.',
      'Click that hop: all 8 signature checks are still green. Nothing wrong with the token.',
      'Change "API requires" to read:reports and run again: 200 OK.',
    ],
    watchFor: 'Returning 401 where it should be 403 makes a client think its token is broken and refresh in a pointless loop. 401 means "log in again". 403 means "logging in again changes nothing".',
  },
  'authz-rbac': {
    title: 'RBAC, ABAC, ReBAC',
    tagline: 'One request, three models, three answers',
    question: 'Is a role in the token enough for authorization?',
    goal: 'See exactly where three authorization models disagree, and why that gap is an IDOR vulnerability.',
    steps: [
      'Scenario: alice (role writer) wants to delete doc:42, but that document belongs to bob.',
      'Press "Run flow" and read the three evaluation hops in sequence.',
      'RBAC allows it — it only looks at role, not who owns the document.',
      'ABAC also allows it — same department, during business hours.',
      'ReBAC denies it — alice has no relationship to doc:42.',
      'Click each hop to read the full reasoning trace in the body.',
    ],
    watchFor: 'A role answers "who are you". A relationship answers "is this actually yours". Most real authorization bugs live in that second question, and plain RBAC has no place to even ask it.',
  },
  'basics-session': {
    title: 'Session cookies vs tokens',
    tagline: 'State on the server, or in the client’s hand',
    question: 'How did people log in before OAuth?',
    goal: 'See the one thing a self-contained JWT cannot do: revoking a session takes effect on the very next request.',
    steps: [
      'Press "Run flow". Notice the password goes straight into the app — very unlike OAuth.',
      'The "PBKDF2 100,000 rounds" hop: this is real PBKDF2-HMAC-SHA256 running in your browser.',
      'The cookie only holds a meaningless sid. The entire session lives on the server.',
      'The "Admin revokes the session" hop: an employee is let go.',
      'The very next request: 401. No waiting for expiry at all.',
    ],
    watchFor: 'This is exactly what you trade away when you move to JWTs. Dropping server state means no database lookup per request, but also no revocation. Compare with the "Token expiry" lesson in the JWT chapter to see it clearly.',
  },
  'sso-two-apps': {
    title: 'One login, two apps',
    tagline: 'The second app never asks for a password',
    question: 'Why does the second app not ask you to log in again?',
    goal: 'See that the login session lives at the auth server, not at any app, and every app just asks that one place.',
    steps: [
      'Press "Run flow". The first half is App 1 logging in, with a password form.',
      'Notice the login form belongs to id.example.com, not the app.',
      'The second half opens App 2 — a completely different domain, no shared cookies or database.',
      'The "302 + code (NO password prompt)" hop: that is the entire SSO trick.',
    ],
    watchFor: 'SSO has no magic to it: several apps ask the same place, and that place has a cookie that remembers you. The SSO session cookie belongs to the auth server\'s domain, so any app that redirects there benefits from it.',
  },
  'sso-logout': {
    title: 'Logout is the hard part',
    tagline: 'Zombie sessions after you click log out',
    question: 'You log out of one app — do the others know?',
    goal: 'See why logout only takes effect where it is announced, and how a zombie session appears.',
    steps: [
      'Press "Run flow". Back-channel logout is currently ON.',
      'App 1 declared a backchannel_logout_uri, so it gets notified.',
      'App 2 never declared one, so the auth server has no way to tell it.',
      'Last hop: reopen App 2 and it is still signed in. That is a zombie session.',
    ],
    watchFor: 'On a shared machine, a zombie session means the next person to open App 2 gets into alice\'s account. And even when every app closes its session, an access token already issued stays valid until exp — logging out cannot revoke a JWT.',
  },
  'openiddict-server': {
    title: 'Running on real OpenIddict',
    tagline: 'No more mock: ASP.NET Core 9 on port 5181',
    question: 'Does the mock tell the truth about a real server?',
    goal: 'Run the same chapter-2 flow through a real authorization server and cross-check every step against the mock. Wherever they differ, the mock oversimplified.',
    steps: [
      'Open a terminal: cd server-dotnet/IamLab.AuthServer && dotnet run --urls http://localhost:5181',
      'Press Run flow. The first hop is /lab/config, showing what the server currently enforces.',
      'Read the discovery hop: code_challenge_methods_supported is generated by OpenIddict from its own config.',
      'Tick "Attacker steals the code" to send a wrong code_verifier and watch OpenIddict reject it itself.',
      'Switch PKCE to plain: OpenIddict blocks it right at /authorize with 400.',
      'Click the GET /api/me hop, Token tab: the lab\'s verifier runs against a real token that OpenIddict actually signed.',
    ],
    watchFor: 'There is one point the mock got wrong, and only running the real server reveals it: RequireProofKeyForCodeExchange() only forces PKCE to be PRESENT — it does not force the method to be S256. OpenIddict still advertises and accepts plain. You must remove plain from CodeChallengeMethods to actually block it. See the comment in Program.cs.',
  },
  'openiddict-m2m': {
    title: 'Client Credentials (machine-to-machine)',
    tagline: 'Logging in when there is no user',
    question: 'How does a cron job or microservice "log in"?',
    goal: 'See a real client_credentials flow: a service fetches its own token with a client_id + secret — no /authorize, no user, no PKCE.',
    steps: [
      'Requires the real server running on :5181 (see the previous lesson).',
      'Press Run flow. Only 2 hops: POST /token, then a call to /api/service.',
      'Click the token hop, Token tab: the access token\'s sub is "service-worker" — the client itself, not a person.',
      'Notice there is no redirect or code step at all: a confidential client can keep a secret, so it authenticates directly.',
    ],
    watchFor: 'Client credentials is ONLY for machine-to-machine calls. Never use it for a flow with a human user — that must be authorization code + PKCE, because a client like a SPA cannot keep a secret. Confusing the two is a very common architecture mistake.',
  },
  'openiddict-refresh': {
    title: 'Refresh rotation on a real server',
    tagline: 'OpenIddict catches a reused refresh token',
    question: 'Does a real server detect a stolen refresh token?',
    goal: 'See real refresh token rotation and reuse detection, plus a mock-vs-real gotcha: OpenIddict defaults to a leeway window for the old token, and you must set leeway to zero to catch reuse immediately.',
    steps: [
      'Requires the real server running on :5181.',
      'Press Run flow. The real client refreshes once (the old token gets rotated out).',
      'Red hop: the attacker reuses the OLD, already-rotated token — OpenIddict revokes the entire chain.',
      'Last hop: the real client\'s new refresh token dies too — the price of reuse detection.',
    ],
    watchFor: 'The point only a real server can teach: OpenIddict rotates refresh tokens by default BUT allows roughly a 30s leeway for the old one (to tolerate concurrent requests). Inside that window, reuse is not caught. This lab sets SetRefreshTokenReuseLeeway(TimeSpan.Zero) to be strict — production has to weigh safety against flaky-network tolerance.',
  },
};

const CHALLENGES_EN: Record<string, ChallengeEn> = {
  'ex-algconf': {
    title: 'Exploit: alg-confusion',
    brief: 'This server accepts both HS256 and RS256 and trusts the alg field. Get an admin token by re-signing your own token with HS256, using the public key as the secret. Land a 200, then patch it.',
    objectives: {
      'have-token': 'Hold a real access token for alice',
      exploited: 'Use a forged HS256 token (roles=admin) and get a 200 from the API',
      patched: 'Patch the hole, and the same forged token then gets rejected',
    },
    hints: [
      'authorize, token to get @access. Then pubkey to grab the public key.',
      'jwt forge @access --set roles=admin --hs256 <public key>  then  curl /me --token @forged',
      'Patch: harden hs256 on. Then curl again with @forged — it must now be 401.',
    ],
    debrief: 'The real fix is not picking HS256 or RS256 correctly — it is never letting the token choose its own algorithm. The server must pin exactly one algorithm and reject everything else. In any JWT library, always pass the allowed algorithm list to verify — never let it be inferred from the header.',
  },
  'ex-nosig': {
    title: 'Exploit: signature verification off',
    brief: 'A misconfig left the resource server not verifying signatures. Edit the payload to admin and call the API. Exploit, then patch.',
    objectives: {
      'have-token': 'Hold a real access token',
      exploited: 'A hand-edited token (old signature kept) is still accepted by the API (200)',
      patched: 'Turn signature verification back on; the forged token gets rejected',
    },
    hints: [
      'authorize, token. Then jwt forge @access --set roles=admin (no --hs256 needed, since the server isn\'t verifying anyway).',
      'curl /me --token @forged  -> 200, because the signature is never checked.',
      'Patch: harden signature on. curl again -> 401.',
    ],
    debrief: 'This is a simple config mistake with maximum consequences: skip signature verification and a JWT becomes a piece of paper anyone can write on. In ASP.NET Core that\'s forgetting AddValidation or setting ValidateSignature=false. Never turn it off.',
  },
  'ex-audconf': {
    title: 'Exploit: audience confusion',
    brief: 'The internal /payroll API skips the aud check. Use your ordinary token (aud points to the public API) to read payroll data. Exploit, then patch.',
    objectives: {
      'have-token': 'Hold a real access token',
      exploited: 'Call the internal API with a token that isn\'t meant for it and get a 200',
      patched: 'Turn on the aud check; the same token is now rejected by the internal API',
    },
    hints: [
      'authorize, token to get @access.',
      'curl /payroll --api internal --token @access  -> 200, because the internal API never compares aud.',
      'Patch: harden aud-internal on. curl again -> 401.',
    ],
    debrief: 'Your token has aud=api.example.com, but the internal API accepts it anyway. Every resource server must check aud matches itself. This is how a low-privilege service escalates into a high-privilege one, using nothing but its own valid token.',
  },
  'ex-jku': {
    title: 'Exploit: key embedded in the token',
    brief: 'This server trusts the verification key embedded in the token header (jku/jwk). Sign an admin token with YOUR OWN key and embed your public key — the server verifies with it. Exploit, then patch.',
    objectives: {
      'have-token': 'Hold a real access token for alice',
      exploited: 'A token signed with your own key (roles=admin) is accepted by the API (200)',
      patched: 'Patch the hole, and the key-embedded token then gets rejected',
    },
    hints: [
      'authorize, token to get @access.',
      'jwt forge @access --set roles=admin --own-key  (generates an attacker keypair, embeds the public key in the header)',
      'curl /me --token @forged  -> 200. Then harden jku on, curl again -> 401.',
    ],
    debrief: 'A matching signature does not mean a trustworthy token — it only matches a key the attacker supplied themselves. A server must only verify against a key it already knows (a pre-configured JWKS), never a key taken from the token itself. This is the jwk/jku header injection family, and the jku variant also comes with SSRF when the server fetches a URL found inside the token.',
  },
  'ex-fixation': {
    title: 'Exploit: session fixation',
    brief: 'The server doesn’t regenerate the sid after login. As the attacker, plant a known sid, let the victim (alice) log in with it, then use that sid to access her account. Exploit, then patch.',
    objectives: {
      'victim-login': 'alice logs in with an sid you planted in advance (sid-attacker-1)',
      exploited: 'Use the planted sid to access alice\'s session (200)',
      patched: 'Patch the hole; logging in again no longer keeps the planted sid',
    },
    hints: [
      'login alice correct-horse-battery-staple --sid sid-attacker-1  (plant a known sid)',
      'profile --sid sid-attacker-1  -> 200, because the server kept that exact sid for alice\'s session.',
      'Patch: harden session on. Then log in again with --sid sid-attacker-1 — this time the server issues a fresh one.',
    ],
    debrief: 'Session fixation: the attacker doesn\'t need to guess an sid, they IMPOSE one in advance and wait for the victim to log in. The only fix is to always issue a fresh sid right after a successful login, invalidating any sid that existed before.',
  },
  'ex-refresh': {
    title: 'Exploit: refresh token forever',
    brief: 'The server doesn’t rotate refresh tokens. Prove a stolen refresh token works many times. Then turn rotation on and show the second reuse revokes the whole family.',
    objectives: {
      'have-refresh': 'Obtain a refresh token',
      reused: 'Successfully use the SAME refresh token at least twice',
      patched: 'Turn rotation on, then reusing an already-rotated refresh gets rejected',
    },
    hints: [
      'authorize, token. The refresh token is saved automatically — type: refresh (several times).',
      'While the hole is open, refreshing with the same token always returns 200.',
      'Patch: harden refresh on. Type refresh (rotates once), then refresh --reuse to replay the old one -> the whole family gets revoked.',
    ],
    debrief: 'A refresh token lives long, which makes it a fat target. Rotation turns it into use-once; and when an already-rotated one is reused, the server cannot tell if that\'s the real client or a thief, so it revokes the whole family — forcing a re-login but stopping the thief.',
  },
  'cc-manual': {
    title: 'Log in by hand',
    brief: 'No "Run flow" button here. Type each step of Authorization Code + PKCE yourself until you can call the API. Type help to begin.',
    objectives: {
      authorized: 'Obtain an authorization code with PKCE S256',
      'got-token': 'Exchange the code for an access token',
      'called-api': 'Successfully call the API (200)',
    },
    hints: [
      'Three commands, in order: authorize, token, curl.',
      'authorize already defaults to S256. token automatically uses the latest code and verifier. curl /me --token @access',
    ],
    debrief: 'That is the entire flow, typed by hand. Notice you never computed SHA-256 or assembled a JWT yourself — the client library did that. But you had to know code_verifier exists and had to hold onto it.',
  },
  'cc-steal': {
    title: 'Play the attacker',
    brief: 'You are the attacker and read the /authorize URL from a proxy log. Get alice’s access token yourself. Then show the same approach fails under S256.',
    objectives: {
      'plain-win': 'Get a token while the server uses code_challenge_method=plain',
      's256-fail': 'Under S256, present a made-up verifier and get rejected by the server',
    },
    hints: [
      'authorize --pkce plain then read code_challenge in the URL. With plain, the challenge IS the verifier.',
      'token --code <code> --verifier <the string you read from the URL>',
      'Part two: authorize (S256) then token --verifier with something made up. Read the server\'s rejection reason carefully.',
    ],
    debrief: 'With plain, the so-called secret sits right in the URL, so it protects nothing. With S256 you\'d need to find a string whose SHA-256 equals the challenge — reversing a hash. That is the entire difference between the two values.',
  },
  'cc-forge': {
    title: 'Make the API accept a fake token',
    brief: 'You have a valid access token. Edit it to escalate and make the API accept it. Try at least three approaches and note which check each dies at.',
    objectives: {
      'have-token': 'Hold a real access token as a base',
      forged: 'Created at least 3 different forged tokens',
      'three-checks': 'Blocked by at least 3 different checks',
    },
    hints: [
      'jwt forge @access --set roles=admin then curl /me --token @forged',
      'Then try: --set-header alg=none, --set exp=9999999999, --set aud=https://api-internal.example.com',
      'jwt verify @forged prints every check individually — easier to read than just the error code from curl.',
    ],
    debrief: 'There is no way to win, and that is the correct outcome: the signature covers both header and payload, and only the auth server holds the private key. What\'s worth learning is exactly WHERE each attack dies: editing a claim dies at signature, alg=none dies at alg. A server missing either of those two checks is a server that gets taken over.',
  },
  'cc-diagnose': {
    title: 'Diagnose a 403',
    brief: 'Users report the API returns 403 right after logging in. Reproduce it, find the cause by reading the token, then fix it to a 200. Follow the process: reproduce, diagnose, fix.',
    objectives: {
      reproduce: 'Reproduce the 403',
      inspect: 'Read the token to see which scopes it carries',
      fixed: 'Then call again and get a 200',
    },
    hints: [
      'Reproduce: authorize --scope "openid profile" then token then curl /me.',
      '403 differs from 401: the token is valid but lacks a permission. Read the scope claim with jwt decode @access.',
      'Fix by requesting the right scope: authorize --scope "openid profile read:reports", then token, then curl again.',
    ],
    debrief: 'A 403 is not fixed by logging in again — you must request the right scope from the start. If your code sees a 403 and goes refresh the token, it will loop pointlessly, because the new token is missing that exact same scope too.',
  },
  'cc-escalation': {
    title: 'Find where authorization disagrees',
    brief: 'The three authorization models sometimes answer differently, and that gap is the vulnerability. Find a case where all three DISAGREE, and one where they AGREE. doc:42 belongs to bob.',
    objectives: {
      disagree: 'Find a scenario where the three models disagree',
      agree: 'Find a scenario where the three models agree',
      explored: 'Try at least 3 different scenarios',
    },
    hints: [
      'policy eval alice delete doc:42 --model all',
      'Change the action (read, delete), change the user (alice, bob), change --hour to touch ABAC\'s business-hours rule.',
      'Disagreement happens when role allows it but ownership doesn\'t. So for all three to agree, find someone whose role AND ownership both line up — doc:42 belongs to bob.',
    ],
    debrief: 'RBAC asks "who are you". ReBAC asks "is this actually yours". When the two answers differ and the system only listens to the first one, that is IDOR. ABAC sits in between: stricter, but still doesn\'t know who owns what.',
  },
  'cc-revoke': {
    title: 'Prove sessions revoke instantly',
    brief: 'Prove with commands: a server-side session revokes immediately, but a JWT does not. alice’s password is correct-horse-battery-staple.',
    objectives: {
      'logged-in': 'Log in with a password and receive an sid',
      'profile-ok': 'Successfully access it while the session is alive',
      'revoked-then-401': 'After revoking, be blocked right on the very next request',
      'jwt-contrast': 'For contrast: get a JWT access token and read its exp claim',
    },
    hints: [
      'login alice correct-horse-battery-staple then profile.',
      'revoke then profile again. Notice it blocks immediately, not after waiting for expiry.',
      'For contrast: authorize then token then jwt decode @access. The exp claim is the only thing that ever ends that token.',
    ],
    debrief: 'A server-side session: one row in a table, delete it and it\'s done. A self-contained JWT: once issued, it cannot be called back — only wait for exp. That is why access tokens must be short-lived, and anything needing instant revocation must be checked live, never read from a claim.',
  },
  'ch-pkce': {
    title: 'Patch the PKCE hole',
    brief: 'Security team report: someone lifted an authorization code from a proxy log and exchanged it for someone else’s access token. The PKCE config is wrong. Fix it so the attacker fails, but the real client can still log in.',
    objectives: {
      'attacker-blocked': 'The attacker does NOT manage to exchange the stolen code for a token',
      'client-works': 'The real client still gets a token normally',
      'api-works': 'The API still returns 200 for the real client',
    },
    hints: [
      'The attacker reads the /authorize URL. With which method does that URL contain everything it needs?',
      'PKCE does not protect the code itself. It protects the right to redeem it — and only when the challenge cannot be reversed.',
    ],
    debrief: 'S256 is the only value to use. plain only still exists in RFC 7636 for compatibility with ancient devices. In OpenIddict, remember that RequireProofKeyForCodeExchange() does NOT remove plain by itself — you must remove it from CodeChallengeMethods.',
    knobs: {
      pkce: {
        label: 'code_challenge_method',
        help: 'How the client hashes code_verifier before sending it at the /authorize step.',
        options: { none: 'none — no PKCE at all', plain: 'plain — send the raw original string', S256: 'S256 — SHA-256 hash' },
      },
    },
  },
  'ch-aud': {
    title: 'Stop audience confusion',
    brief: 'The internal /payroll API returns payroll data for a token issued to the public API. The signature is perfectly valid so nobody noticed. Block it — without breaking the public API.',
    objectives: {
      'internal-blocked': 'The internal API rejects a token not meant for it (401)',
      'public-ok': 'The public API still works (200)',
    },
    hints: [
      'A signature answers "who issued this token". It does not answer "who was it issued for".',
      'The aud claim exists exactly to solve this. The question is whether anyone reads it.',
    ],
    debrief: 'Every resource server must check that aud matches itself exactly. Skip that step and every token from the same issuer becomes a master key, letting a low-privilege service escalate to a high-privilege one using its own token.',
    knobs: {
      audCheck: {
        label: 'Internal API checks the aud claim',
        help: 'Whether it compares the token\'s aud against its own identity.',
        options: { off: 'Off — only verify the signature', on: 'On — compare aud against itself' },
      },
    },
  },
  'ch-scope': {
    title: 'Cut scopes to the minimum',
    brief: 'Permission review: the dashboard app requests far too many scopes, including admin:all. It only needs to read reports. Cut it to the minimum that still works.',
    objectives: {
      'api-200': 'The API still returns 200 — the app can still do its job',
      'no-admin': 'No admin scope requested at all',
      'no-write': 'No write permission requested — this app only reads',
    },
    hints: [
      'Cut everything and the API returns 403. Cut correctly and it\'s exactly 200.',
      'Read the 403 message: it states exactly which scope the endpoint needs.',
    ],
    debrief: 'Least privilege: an app should only request the scopes it actually uses. Scope doesn\'t grant the user extra power, but a broad scope means a compromised app can cause broad damage.',
    knobs: {
      scope: {
        label: 'Scope the app requests',
        help: 'Scope is authority the user delegates to the app. Requesting more than needed is self-inflicted damage the moment the app is compromised.',
      },
    },
  },
  'ch-zombie': {
    title: 'Kill the zombie session',
    brief: 'A user reports: they logged out of App 1, but App 2 still shows them signed in. On the shared front-desk machine, the next person gets into their account. Fix it.',
    objectives: {
      'wiki-notified': 'App 2 receives the logout notification',
      'wiki-relogin': 'Reopening App 2 forces a fresh login — no more zombie session',
    },
    hints: [
      'There are two switches, and turning on just one is not enough.',
      'The auth server cannot call an endpoint the client never declared.',
    ],
    debrief: 'Logout only takes effect where it is announced, and announcing it needs both sides: the server must turn back-channel logout on, and the client must declare an endpoint to receive it. What still isn\'t solved: an access token already issued stays valid until exp — that\'s why access tokens must be short-lived.',
    knobs: {
      backChannel: {
        label: 'Back-channel logout',
        help: 'Whether the auth server proactively calls each app to announce the session closed.',
        options: { off: 'Off', on: 'On' },
      },
      wikiUri: {
        label: 'App 2 declares backchannel_logout_uri',
        help: 'Turning on back-channel logout at the server isn\'t enough: each client must declare an endpoint to receive the notification.',
        options: { no: 'Not declared', yes: 'Declared' },
      },
    },
  },
  'ch-redirect': {
    title: 'Investigate: broken login',
    brief: 'After a domain change, nobody can log in. The auth server returns 400 at the very first step. Find the right redirect_uri. Note: only one value is accepted, and the reason matters.',
    objectives: {
      'authorize-302': '/authorize returns 302 with a code',
      'api-200': 'The flow runs to completion and the API returns 200',
    },
    hints: [
      'redirect_uri matching is an exact string comparison. No normalization, no case-insensitivity, no ignoring a trailing slash.',
      'Look at the last option: that domain starts with a valid string but isn\'t it. If the server matched by prefix, that would be account takeover.',
    ],
    debrief: 'The exact-match rule looks rigid and causes plenty of deployment headaches, but it is intentional: any loosening (prefix matching, wildcards, URL normalization) turns redirect_uri into an open redirect, and an open redirect in OAuth means the code gets handed straight to an attacker.',
    knobs: {
      redirect: {
        label: 'redirect_uri the app sends',
        help: 'Where the auth server will send the user back with the authorization code.',
        options: {
          'https://spa.example.com/callback/': 'https://spa.example.com/callback/  (trailing slash)',
          'https://spa.example.com/Callback': 'https://spa.example.com/Callback  (capital C)',
          'https://spa.example.com/callback': 'https://spa.example.com/callback',
          'https://spa.example.com.evil.co/callback': 'https://spa.example.com.evil.co/callback',
        },
      },
    },
  },
};

const CH_SECTION_EN: Record<string, string> = {
  ex: 'Exploit a vulnerability',
  cc: 'Hands-on console challenges',
  ch: 'Configuration challenges',
};

export function lessonTitle(l: Lesson): string {
  return getLang() === 'en' ? LESSONS_EN[l.id]?.title ?? l.title : l.title;
}
export function lessonTagline(l: Lesson): string {
  return getLang() === 'en' ? LESSONS_EN[l.id]?.tagline ?? l.tagline : l.tagline;
}
export function lessonQuestion(l: Lesson): string {
  return getLang() === 'en' ? LESSONS_EN[l.id]?.question ?? l.question : l.question;
}
export function lessonGoal(l: Lesson): string {
  return getLang() === 'en' ? LESSONS_EN[l.id]?.goal ?? l.goal : l.goal;
}
export function lessonSteps(l: Lesson): string[] {
  return getLang() === 'en' ? LESSONS_EN[l.id]?.steps ?? l.steps : l.steps;
}
export function lessonWatch(l: Lesson): string {
  return getLang() === 'en' ? LESSONS_EN[l.id]?.watchFor ?? l.watchFor : l.watchFor;
}
export function challengeTitle(c: Challenge): string {
  return getLang() === 'en' ? CHALLENGES_EN[c.id]?.title ?? c.title : c.title;
}
export function challengeBrief(c: Challenge): string {
  return getLang() === 'en' ? CHALLENGES_EN[c.id]?.brief ?? c.brief : c.brief;
}
export function challengeHints(c: Challenge): string[] {
  return getLang() === 'en' ? CHALLENGES_EN[c.id]?.hints ?? c.hints : c.hints;
}
export function challengeDebrief(c: Challenge): string {
  return getLang() === 'en' ? CHALLENGES_EN[c.id]?.debrief ?? c.debrief : c.debrief;
}
export function objectiveText(challengeId: string, objectiveId: string, fallback: string): string {
  return getLang() === 'en' ? CHALLENGES_EN[challengeId]?.objectives?.[objectiveId] ?? fallback : fallback;
}
export function knobLabel(challengeId: string, knobId: string, fallback: string): string {
  return getLang() === 'en' ? CHALLENGES_EN[challengeId]?.knobs?.[knobId]?.label ?? fallback : fallback;
}
export function knobHelp(challengeId: string, knobId: string, fallback: string): string {
  return getLang() === 'en' ? CHALLENGES_EN[challengeId]?.knobs?.[knobId]?.help ?? fallback : fallback;
}
export function knobOption(challengeId: string, knobId: string, value: string, fallback: string): string {
  return getLang() === 'en' ? CHALLENGES_EN[challengeId]?.knobs?.[knobId]?.options?.[value] ?? fallback : fallback;
}
export function chapterTitle(id: number, fallback: string): string {
  return getLang() === 'en' ? CHAPTERS_EN[id]?.title ?? fallback : fallback;
}
export function chapterBlurb(id: number, fallback: string): string {
  return getLang() === 'en' ? CHAPTERS_EN[id]?.blurb ?? fallback : fallback;
}
export function challengeSectionTitle(prefix: string, fallback: string): string {
  return getLang() === 'en' ? CH_SECTION_EN[prefix] ?? fallback : fallback;
}
