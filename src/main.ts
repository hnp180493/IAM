import { Clock } from './core/Clock';
import { tr } from './i18n';
import { MockAuthServer } from './server/MockAuthServer';
import { ResourceApi } from './server/ResourceApi';
import { SessionServer } from './server/SessionServer';
import { runAuthCodePkce } from './flows/authCodePkce';
import { runSessionCookie } from './flows/sessionCookie';
import { runAudConfusion } from './flows/audConfusion';
import { runPolicyModels } from './flows/policyModels';
import { runSsoTwoApps, runSsoLogout } from './flows/sso';
import { runOpenIddictReal } from './flows/openiddictReal';
import { runOpenIddictM2M, runOpenIddictRefresh } from './flows/openiddictExtra';
import type { FlowResult } from './flows/kit';
import { Stage } from './ui/Stage';
import { Inspector } from './ui/Inspector';
import { Hud } from './ui/Hud';
import { Menu } from './ui/Menu';
import { Tutorial } from './ui/Tutorial';
import { TamperDialog } from './ui/TamperDialog';
import { ChallengePanel } from './ui/ChallengePanel';
import { Console } from './ui/Console';
import { LabSession } from './engine/LabSession';
import { Posture } from './engine/Posture';
import { RedTeamEngine } from './engine/RedTeamEngine';
import { RedTeamPanel } from './ui/RedTeamPanel';
import type { Challenge } from './data/challenges';
import type { FlowId, Lesson } from './data/lessons';
import type { Lane } from './core/types';
import { lessonTitle, challengeTitle } from './i18n/content';
import { onLangChange } from './i18n';

const clock = new Clock();
const authServer = new MockAuthServer(clock);
const publicApi = new ResourceApi(clock, 'https://api.example.com', authServer.config.issuer, () => authServer.jwks());
const internalApi = new ResourceApi(clock, 'https://api-internal.example.com', authServer.config.issuer, () => authServer.jwks(), true, undefined, undefined, 'checkAudienceInternal');
const sessions = new SessionServer(clock);
const posture = new Posture();
// Chỉ Red Team mode gắn posture vào server; các bài khác luôn chạy trạng thái siết.
authServer.posture = posture;
publicApi.posture = posture;
internalApi.posture = posture;
publicApi.publicKeyMaterial = () => authServer.publicKeyMaterial();
internalApi.publicKeyMaterial = () => authServer.publicKeyMaterial();

const el = (id: string) => document.getElementById(id)!;
document.body.insertAdjacentHTML('afterbegin', Stage.defs());

const hud = new Hud(el('hud'));
const stage = new Stage(el('stage'));
const inspector = new Inspector(el('inspector'));
const menu = new Menu(el('menu'));
const tutorial = new Tutorial(el('tutorial'));
const tamper = new TamperDialog(el('tamper'));
const challengePanel = new ChallengePanel(el('challenge'));
const session = new LabSession(clock, authServer, publicApi, internalApi, sessions, posture);
const consoleUi = new Console(el('console'), session);
const redTeamPanel = new RedTeamPanel(el('redteam'));
const redTeam = new RedTeamEngine(posture);
redTeam.onUpdate = (s) => redTeamPanel.render(s);

let currentLesson: Lesson | null = null;
let currentChallenge: Challenge | null = null;
let running = false;
/**
 * Số hiệu lượt chạy. Đổi bài hay bấm Xoá giữa lúc đang phát lại thì lượt cũ
 * phải dừng - nếu không nó tiếp tục vẽ chặng và ghi kết quả của bài trước lên
 * bài mới.
 */
let runId = 0;

function cancelRun(): void {
  runId += 1;
  running = false;
  hud.setRunning(false);
  challengePanel.setRunning(false);
}

stage.onSelect = (packet) => inspector.show(packet, packet.verification ?? null);

/** Bắn lại một token đã bị sửa vào API thật, và trả về đúng phán quyết của nó. */
inspector.onTamper = (token) => {
  tamper.open(token, async (forged) => {
    const res = await publicApi.request('/me', forged, hud.state.requiredScope);
    return {
      token: forged,
      status: res.status,
      statusText: res.statusText,
      reason: res.reason,
      checks: res.verification?.checks ?? [],
      valid: res.verification?.valid ?? false,
    };
  });
};

const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** Lane nào hiện lên là tuỳ luồng - luồng M2M không cần cột Browser. */
function lanesFor(flow: FlowId, intercept: boolean): Lane[] {
  switch (flow) {
    case 'session':
      return ['browser', 'client'];
    case 'aud-confusion':
      return ['client', 'authserver', 'api', 'api2'];
    case 'policy':
      return ['client', 'api'];
    case 'sso-login':
    case 'sso-logout':
      return ['browser', 'client', 'client2', 'authserver'];
    case 'openiddict':
      return intercept
        ? ['browser', 'client', 'authserver', 'api', 'attacker']
        : ['browser', 'client', 'authserver', 'api'];
    case 'openiddict-m2m':
      return ['client', 'authserver', 'api'];
    case 'openiddict-refresh':
      return ['browser', 'client', 'authserver', 'attacker'];
    default:
      return intercept
        ? ['browser', 'client', 'authserver', 'api', 'attacker']
        : ['browser', 'client', 'authserver', 'api'];
  }
}

function flowOf(lesson: Lesson | null): FlowId {
  if (currentChallenge) return currentChallenge.flow;
  return lesson?.flow ?? 'authcode';
}

function showMenu(): void {
  cancelRun();
  redTeam.stop();
  posture.reset();
  document.body.classList.remove('in-console', 'in-redteam');
  redTeamPanel.close();
  tamper.close();
  challengePanel.close();
  currentChallenge = null;
  document.body.classList.remove('in-challenge');
  menu.render();
  menu.show();
  document.body.classList.remove('in-lab');
}

function enterLab(lesson: Lesson): void {
  cancelRun();
  redTeam.stop();
  posture.reset();
  redTeamPanel.close();
  document.body.classList.remove('in-console', 'in-redteam');
  currentChallenge = null;
  challengePanel.close();
  document.body.classList.remove('in-challenge');
  currentLesson = lesson;
  menu.hide();
  document.body.classList.add('in-lab');
  if (lesson.preset) hud.applyPreset({ ...lesson.preset }, lessonTitle(lesson));
  else hud.setLessonName(lessonTitle(lesson));
  hud.setFlow(flowOf(lesson));
  clock.timeScale = hud.state.timeScale;
  stage.setLanes(lanesFor(flowOf(lesson), hud.state.interceptCode));
  hud.setStats({
    activeTokens: 0,
    expiresIn: null,
    outcome: tr(`${lessonTitle(lesson)} — bấm "Chạy luồng" để bắt đầu.`, `${lessonTitle(lesson)} — click "Run flow" to start.`),
    tone: 'idle',
  });
}

function enterChallenge(challenge: Challenge): void {
  cancelRun();
  redTeam.stop();
  posture.reset();
  redTeamPanel.close();
  document.body.classList.remove('in-redteam');
  currentLesson = null;
  currentChallenge = challenge;
  menu.hide();
  document.body.classList.add('in-lab', 'in-challenge');
  challengePanel.open(challenge);
  const isConsole = challenge.mode === 'console';
  document.body.classList.toggle('in-console', isConsole);
  if (isConsole) {
    posture.reset();
    challenge.setupPosture?.((name, value) => posture.harden(name, value));
    consoleUi.reset();
    setTimeout(() => consoleUi.focus(), 50);
  }
  hud.setLessonName(challengeTitle(challenge));
  hud.setFlow('challenge'); // ẩn hết núm của HUD: núm nằm trong panel thử thách
  stage.setLanes(lanesFor(challenge.flow, challenge.flow === 'authcode'));
  hud.setStats({ activeTokens: 0, expiresIn: null, outcome: tr('Sửa cấu hình bên trái rồi bấm "Chạy kiểm tra".', 'Adjust the config on the left, then click "Run check".'), tone: 'idle' });
}

/** Thử thách gõ tay: mục tiêu tick ngay sau mỗi lệnh, không cần bấm chạy. */
consoleUi.onAfterCommand = () => {
  if (document.body.classList.contains('in-redteam')) {
    redTeamPanel.render(redTeam.snapshot);
    return;
  }
  if (!currentChallenge || currentChallenge.mode !== 'console') return;
  challengePanel.report({ packets: [], outcome: 'success', values: {}, log: session.log });
  if (challengePanel.isSolved(currentChallenge.id)) menu.markSolved(currentChallenge.id);
};

challengePanel.onResetConsole = () => {
  consoleUi.reset();
  if (currentChallenge) challengePanel.open(currentChallenge);
  consoleUi.focus();
};

function enterRedTeam(): void {
  cancelRun();
  currentLesson = null;
  currentChallenge = null;
  challengePanel.close();
  menu.hide();
  document.body.classList.add('in-lab', 'in-console', 'in-redteam');
  redTeamPanel.open();
  consoleUi.reset(false);
  consoleUi.print([
    { text: tr('Red Team mode. audit để soi, harden để vá, status để xem toàn bộ cờ.', 'Red Team mode. audit to inspect, harden to patch, status to see every flag.'), tone: 'warn' },
  ]);
  hud.setLessonName('Red Team');
  hud.setFlow('challenge');
  setTimeout(() => consoleUi.focus(), 50);
}

menu.onPickRedTeam = () => enterRedTeam();
redTeamPanel.onBack = () => {
  redTeam.stop();
  posture.reset();
  showMenu();
};
redTeamPanel.onStart = () => {
  consoleUi.reset(false);
  consoleUi.print([{ text: tr('Bắt đầu. Chúc may mắn.', 'Starting. Good luck.'), tone: 'warn' }]);
  redTeam.start();
  consoleUi.focus();
};

menu.onPickChallenge = (challenge) => enterChallenge(challenge);
challengePanel.onBack = () => showMenu();
challengePanel.onRun = () => void run();
challengePanel.onChange = () => {
  if (currentChallenge) stage.setLanes(lanesFor(currentChallenge.flow, currentChallenge.flow === 'authcode'));
};

tutorial.onStart = () => currentLesson && enterLab(currentLesson);
tutorial.onBack = () => showMenu();
menu.onPick = (lesson) => {
  currentLesson = lesson;
  tutorial.show(lesson);
};

/** Gọi đúng luồng của bài học đang mở. */
async function dispatch(flow: FlowId): Promise<FlowResult> {
  let o = (currentLesson?.flowOpts ?? {}) as Record<string, unknown>;

  // Trong thử thách, cấu hình đến từ các núm của panel chứ không từ HUD.
  if (currentChallenge) {
    const plan = currentChallenge.toRun(challengePanel.knobValues);
    o = plan.flowOpts ?? {};
    if (plan.hud) Object.assign(hud.state, plan.hud);
  }
  switch (flow) {
    case 'session':
      return runSessionCookie(clock, sessions, {
        username: 'alice',
        password: 'correct-horse-battery-staple',
        revokeMidway: o['revokeMidway'] !== false,
      });
    case 'aud-confusion':
      return runAudConfusion(clock, authServer, publicApi, internalApi, {
        checkAudienceOnInternal: o['checkAudienceOnInternal'] === true,
        requiredScope: hud.state.requiredScope,
      });
    case 'policy':
      return runPolicyModels(clock, { atHour: typeof o['atHour'] === 'number' ? o['atHour'] : 14 });
    case 'sso-login':
      return runSsoTwoApps(clock, authServer);
    case 'sso-logout':
      return runSsoLogout(clock, authServer, {
        backChannel: o['backChannel'] !== false,
        registerWikiLogout: o['registerWikiLogout'] === true,
      });
    case 'openiddict':
      return runOpenIddictReal(clock, {
        pkceMethod: hud.state.pkceMethod,
        sendWrongVerifier: hud.state.interceptCode,
        requiredScope: hud.state.requiredScope,
      });
    case 'openiddict-m2m':
      return runOpenIddictM2M(clock);
    case 'openiddict-refresh':
      return runOpenIddictRefresh(clock);
    default:
      return runAuthCodePkce(clock, authServer, publicApi, {
        pkceMethod: hud.state.pkceMethod,
        interceptCode: hud.state.interceptCode,
        scope: hud.state.scope,
        requiredScope: hud.state.requiredScope,
        username: 'alice',
        // Thử thách "Điều tra: đăng nhập hỏng" đổi giá trị này.
        ...(typeof o['redirectUri'] === 'string' ? { redirectUri: o['redirectUri'] } : {}),
      });
  }
}

async function run(): Promise<void> {
  if (running) return;
  running = true;
  const myRun = ++runId;
  hud.setRunning(true);
  challengePanel.setRunning(true);

  const flow = flowOf(currentLesson);
  authServer.reset();
  publicApi.reset();
  internalApi.reset();
  sessions.reset();
  publicApi.setAudienceCheck(true);
  stage.setLanes(lanesFor(flow, hud.state.interceptCode));
  clock.timeScale = hud.state.timeScale;

  const result = await dispatch(flow);

  // Luồng được tính trước rồi phát lại từng chặng cho dễ theo dõi. Tốc độ ảnh
  // hưởng cả tốc độ phát lại, nên ở 60x thì không phải ngồi đợi.
  const step = Math.max(60, 520 / hud.state.timeScale);
  for (const packet of result.packets) {
    if (myRun !== runId) return; // đã đổi bài hoặc bấm Xoá giữa lúc phát lại
    stage.addPacket(packet);
    await wait(step);
  }
  if (myRun !== runId) return;

  const tone = result.outcome === 'success' ? 'success' : result.outcome === 'attacker-won' ? 'danger' : 'failed';
  hud.setStats({
    activeTokens: authServer.activeTokenCount() + sessions.activeCount(),
    expiresIn: authServer.soonestExpiry(),
    outcome: result.summary,
    tone,
  });

  if (currentChallenge) {
    challengePanel.report({ packets: result.packets, outcome: result.outcome, values: challengePanel.knobValues, log: session.log });
    if (challengePanel.isSolved(currentChallenge.id)) menu.markSolved(currentChallenge.id);
  }

  // Mở sẵn chặng quan trọng nhất: bài học chỉ định, hoặc chặng đã định đoạt kết quả.
  const wanted = currentLesson?.focusHop
    ? result.packets.find((p) => p.label === currentLesson!.focusHop)
    : undefined;
  const decisive =
    wanted ??
    result.packets.filter((p) => p.tone === 'danger' || p.tone === 'blocked').pop() ??
    result.packets.filter((p) => p.tokens?.length).pop();
  if (decisive) stage.select(decisive.id);

  running = false;
  hud.setRunning(false);
  challengePanel.setRunning(false);
}

onLangChange(() => {
  if (currentLesson) hud.setLessonName(lessonTitle(currentLesson));
  else if (currentChallenge) hud.setLessonName(challengeTitle(currentChallenge));
});

hud.onRun = () => void run();
hud.onMenu = () => showMenu();
hud.onReset = () => {
  cancelRun();
  authServer.reset();
  publicApi.reset();
  internalApi.reset();
  sessions.reset();
  stage.setLanes(lanesFor(flowOf(currentLesson), hud.state.interceptCode));
  hud.setStats({ activeTokens: 0, expiresIn: null, outcome: tr('Đã xoá. Chưa phát token nào.', 'Cleared. No tokens issued yet.'), tone: 'idle' });
};
hud.onChange = () => {
  clock.timeScale = hud.state.timeScale;
  stage.setLanes(lanesFor(flowOf(currentLesson), hud.state.interceptCode));
};

// Đồng hồ mô phỏng đẩy ô "hết hạn sau", nên ở 60x xem được token 5 phút chết
// trong 5 giây thật.
clock.start(() => {
  const out = el('h-outcome');
  hud.setStats({
    activeTokens: authServer.activeTokenCount() + sessions.activeCount(),
    expiresIn: authServer.soonestExpiry(),
    outcome: out.textContent ?? '',
    tone: (out.className.split('tone-')[1] ?? 'idle') as 'idle' | 'success' | 'danger' | 'failed',
  });
});

async function boot(): Promise<void> {
  await authServer.init();
  await sessions.addUser('alice', 'correct-horse-battery-staple');
  stage.setLanes(lanesFor('authcode', false));
  showMenu();
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      tamper.close();
      showMenu();
    }
    if (e.key === 'Enter' && !running && document.body.classList.contains('in-lab')) void run();
  });
}

void boot();
