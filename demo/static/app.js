/* Security Triage Agent demo. Every value shown comes from the local API (demo/server.py),
   which reads the repository's real data and runs the real code. */

// ---------- icons (Lucide, ISC license) ----------
const ICONS = {
  shield: '<path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1zm-8-5v4m0 4h.01"/>',
  bug: '<path d="M12 20v-9m2-4a4 4 0 0 1 4 4v3a6 6 0 0 1-12 0v-3a4 4 0 0 1 4-4zm.12-3.12L16 2"/><path d="M21 21a4 4 0 0 0-3.81-4M21 5a4 4 0 0 1-3.55 3.97M22 13h-4M3 21a4 4 0 0 1 3.81-4M3 5a4 4 0 0 0 3.55 3.97M6 13H2M8 2l1.88 1.88M9 7.13V6a3 3 0 1 1 6 0v1.13"/>',
  database: '<ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M3 5v14a9 3 0 0 0 18 0V5"/><path d="M3 12a9 3 0 0 0 18 0"/>',
  siren: '<path d="M7 18v-6a5 5 0 1 1 10 0v6M5 21a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1v-1a2 2 0 0 0-2-2H7a2 2 0 0 0-2 2zm16-9h1m-3.5-7.5L18 5M2 12h1m9-10v1M4.929 4.929l.707.707M12 12v6"/>',
  server: '<rect width="20" height="8" x="2" y="2" rx="2" ry="2"/><rect width="20" height="8" x="2" y="14" rx="2" ry="2"/><path d="M6 6h.01M6 18h.01"/>',
  book: '<path d="M12 5v16m8.001-2A2 2 0 0 0 22 17V5a2 2 0 0 0-1.999-2L16 3.002A5 5 0 0 0 12 5a5 5 0 0 0-4-2H4a2 2 0 0 0-2 2v12a2 2 0 0 0 1.999 2H8a5 5 0 0 1 4 2a5 5 0 0 1 4-2z"/>',
  wrench: '<path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.106-3.105c.32-.322.863-.22.983.218a6 6 0 0 1-8.259 7.057l-7.91 7.91a1 1 0 0 1-2.999-3l7.91-7.91a6 6 0 0 1 7.057-8.259c.438.12.54.662.219.984z"/>',
  workflow: '<rect width="8" height="8" x="3" y="3" rx="2"/><path d="M7 11v4a2 2 0 0 0 2 2h4"/><rect width="8" height="8" x="13" y="13" rx="2"/>',
  play: '<path d="M5 5a2 2 0 0 1 3.008-1.728l11.997 6.998a2 2 0 0 1 .003 3.458l-12 7A2 2 0 0 1 5 19z"/>',
  flask: '<path d="M14 2v6a2 2 0 0 0 .245.96l5.51 10.08A2 2 0 0 1 18 22H6a2 2 0 0 1-1.755-2.96l5.51-10.08A2 2 0 0 0 10 8V2M6.453 15h11.094M8.5 2h7"/>',
  check: '<circle cx="12" cy="12" r="10"/><path d="m16 9l-5.5 5.5L8 12"/>',
  usercheck: '<path d="m16 11l2 2l4-4m-6 12v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/>',
  alert: '<path d="m21.73 18l-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3M12 9v4m0 4h.01"/>',
  x: '<circle cx="12" cy="12" r="10"/><path d="m15 9l-6 6m0-6l6 6"/>',
  gauge: '<path d="m12 14l4-4M3.34 19a10 10 0 1 1 17.32 0"/>',
  building: '<path d="M10 12h4m-4-4h4m0 13v-3a2 2 0 0 0-4 0v3"/><path d="M6 10H4a2 2 0 0 0-2 2v7a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2V9a2 2 0 0 0-2-2h-2"/><path d="M6 21V5a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v16"/>',
  scale: '<path d="M12 3v18m7-13l3 8a5 5 0 0 1-6 0zV7"/><path d="M3 7h1a17 17 0 0 0 8-2a17 17 0 0 0 8 2h1M5 8l3 8a5 5 0 0 1-6 0zV7m2 14h10"/>',
  bot: '<path d="M12 8V4H8"/><rect width="16" height="12" x="4" y="8" rx="2"/><path d="M2 14h2m16 0h2m-7-1v2m-6-2v2"/>',
  terminal: '<path d="M12 19h8M4 17l6-6l-6-6"/>',
  sparkles: '<path d="M11.017 2.814a1 1 0 0 1 1.966 0l1.051 5.558a2 2 0 0 0 1.594 1.594l5.558 1.051a1 1 0 0 1 0 1.966l-5.558 1.051a2 2 0 0 0-1.594 1.594l-1.051 5.558a1 1 0 0 1-1.966 0l-1.051-5.558a2 2 0 0 0-1.594-1.594l-5.558-1.051a1 1 0 0 1 0-1.966l5.558-1.051a2 2 0 0 0 1.594-1.594zM20 2v4m2-2h-4"/><circle cx="4" cy="20" r="2"/>',
};
const icon = (n) => `<svg class="i" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${ICONS[n] || ''}</svg>`;

// ---------- helpers ----------
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = (v) => String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const dec = (d) => `<span class="dec dec-${d ? esc(d) : 'none'}">${d === 'INSUFFICIENT_EVIDENCE' ? 'INSUFFICIENT EVIDENCE' : esc(d || 'NO RATING')}</span>`;
const mode = (m) => m ? `<span class="mode mode-${esc(m)}">${esc(m)}</span>` : '';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const md = (text) => (window.marked ? marked.parse(text) : `<pre>${esc(text)}</pre>`);
const api = {
  async get(url) { const r = await fetch(url); const j = await r.json(); if (!r.ok) throw new Error(j.error || r.status); return j; },
  async post(url, body) { const r = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body || {}) }); const j = await r.json(); if (!r.ok) throw new Error(j.error || r.status); return j; },
};
const cache = {};
const once = (key, fn) => (cache[key] ??= fn());
const DEC_COLOR = { High: 'var(--high)', Medium: 'var(--medium)', Low: 'var(--low)', INSUFFICIENT_EVIDENCE: 'var(--insuf)' };
const PRIO_COLOR = { P1: 'var(--high)', P2: 'var(--medium)', P3: 'var(--low)' };

function modal(title, html) {
  $('#modal-title').innerHTML = title;
  $('#modal-body').innerHTML = html;
  $('#modal').classList.remove('hidden');
}
$('#modal-close').onclick = () => $('#modal').classList.add('hidden');
$('#modal').onclick = (e) => { if (e.target.id === 'modal') $('#modal').classList.add('hidden'); };
async function openDoc(name, title) {
  const d = await api.get(`/api/doc?name=${name}`);
  modal(`${esc(title || d.path)} <span class="muted mono" style="font-size:12px">${esc(d.path)}</span>`, `<div class="md">${md(d.text)}</div>`);
}
window.openDoc = openDoc;

function callText(name, args) {
  if (!args || typeof args !== 'object') return `${name}(${esc(JSON.stringify(args))})`;
  if (name === 'lookup_environment') return `${args.action || '?'} "${args.query ?? ''}"${args.limit !== undefined ? ` limit=${JSON.stringify(args.limit)}` : ''}${args.target ? ` target=${args.target}` : ''}`;
  if (name === 'submit_findings') return `submit_findings (${(args.findings || []).length} findings)`;
  return `${name}(${Object.entries(args).map(([k, v]) => `${k}=${JSON.stringify(v)}`).join(', ')})`;
}

// ---------- scenes ----------
const TEAM = {
  1: { name: 'Paul Prommark', short: 'PP', color: 'var(--accent)', role: 'Part 1 · A + B' },
  2: { name: 'Supawich Puengdang', short: 'SP', color: 'var(--accent-2)', role: 'Part 2 · C + D' },
};

const SCENES = [
  { id: 'intro', part: 1, icon: 'shield', kicker: 'Overview', title: 'The question we answer', render: renderIntro,
    notes: ['Hi, we are Paul Prommark and Supawich Puengdang. I did parts A and B: the case, the environment, the rating policy and the tools. Supawich did parts C and D: the agent, validation, testing and this demo.', 'Our question: a known Windows bug, CVE-2026-85880, is out there. Does it matter for our company, which machines does it hit, how risky is each one for us, and what should we do?', 'The pipeline on screen: we give the agent only the bug ID. The AI decides what to look up, code checks its work and applies our rulebook, and a human signs off.', 'The table at the bottom is the plain-language version: it works like a hospital triage.'] },
  { id: 'threat', part: 1, icon: 'bug', kicker: 'Threat intelligence 101', title: 'CVE, NVD, CVSS and KEV', render: renderThreat,
    notes: ['Four public sources, four different jobs.', 'CVE is just the name: a unique ID for one bug. It is run by MITRE with funding from CISA, and Microsoft assigned this one.', 'NVD, run by NIST, adds the details we need, most importantly the first fixed build for each product. On Windows Server 2016 the fix is build 9512; anything lower is vulnerable.', 'CVSS is a 0 to 10 severity score: 7.8, High. The vector tells us the attacker needs local access with a normal user account: AV:L and PR:L.', 'KEV, from CISA, says this bug is being exploited in real attacks right now. It was added on September 8 and the federal due date has already passed.', 'Key point: 7.8 is the same for every company in the world. Our job is local risk, which is different per machine.'] },
  { id: 'company', part: 1, icon: 'building', kicker: 'Environment', title: 'Northbridge Services (simulated)', render: renderCompany,
    notes: ['This is Northbridge Services, the fictional company the course gave us: 1,000 staff and 48 asset records in 14 network zones. Everything here is simulated.', 'I adapted it to version 1.1. I added build numbers, data sensitivity, exposure and whether normal users can log on, and wrote down 15 assumptions. The button at the top shows every change.', 'Click W15, the legacy payroll servers: Windows Server 2016 on the July patch, so build 9339. Payroll operators log on with normal accounts, it holds payroll and bank data for 1,000 people, and office laptops can reach it.', 'The snapshot dropdown shows our four test variants. Each one changes exactly one thing about W15.'] },
  { id: 'policy', part: 1, icon: 'scale', kicker: 'Rating policy', title: 'The rulebook: applicability × impact', render: renderPolicy,
    notes: ['The naive approach is to sort by CVSS. Then all 23 affected Windows records would be High, even the ones that are already patched.', 'Our rulebook asks three questions. First, can it actually work here? Right product, unpatched build, and a normal user can log on. If not, it\'s Low. If we don\'t know, we say so instead of guessing.', 'Second, how bad would it be here? That depends on how sensitive the data is and who can reach the machine, which gives priority P1, P2 or P3. Identity servers are always P1.', 'Third, how severe is the bug in general? That\'s CVSS. A matrix combines the answers, then we add one level if the bug is on KEV, and drop one if it only partly applies.', 'Result for the same bug: 1 High, 1 Medium, 1 needs review, and 20 Low.'] },
  { id: 'playground', part: 1, icon: 'gauge', kicker: 'Rating policy', title: 'Policy playground (runs the real policy code)', render: renderPlayground,
    notes: ['This panel calls the real policy code, the same function the agent uses.', 'W15 with the base facts comes out High: P1 times High is High, and KEV adds one level but it\'s already at the cap.', 'Patch it, which is check 1, and it drops to Low. Make it hold no personal data and sit internal only, which is check 2, and it becomes Medium.', 'Remove the build number, or let two sources disagree, and the answer is INSUFFICIENT EVIDENCE. The policy never guesses.', 'The offline root CA is vulnerable, but it\'s powered off and nobody can log on, so it only partly applies: Medium.'] },
  { id: 'tools', part: 1, icon: 'wrench', kicker: 'Tools', title: 'What the agent can call', render: renderTools,
    notes: ['An AI model can only write text. A tool call means the AI writes a request, our Python code runs it, and the result goes back to the AI.', 'I wrote three lookup tools from scratch: NVD, KEV and the company inventory. Every result says where it came from, when, and whether it\'s live, cached or simulated.', 'Try it runs the real tool right now. If NVD is down, the tool retries once, then uses a cached copy and labels it as cached.', 'And if the AI asks for a tool that doesn\'t exist, the call is rejected before anything runs. Now Supawich will show how the agent uses these tools.'] },
  { id: 'architecture', part: 2, story: "<b>Where we are:</b> Paul showed the ingredients: the bug, the company, the rulebook and the tools. Now: how an AI uses them, and why we never take its word for anything.", icon: 'workflow', kicker: 'Design', title: 'How the agent works', render: renderArchitecture,
    notes: ['Thanks Paul. My roles C and D: make the pieces run end to end, then test whether we can trust the output', '3 options for where the model sits: does everything (non-deterministic, unauditable) / no model (brittle, fails the requirement) / model investigates + code decides (chosen)', 'Model is useful for: choosing searches, matching names (windows_10_22h2 vs \'Windows 10 Enterprise 22H2\'). The model NEVER picks the rating (correct Paul\'s slip)', 'Animate: tool menu + submit_findings; code validates and runs each call; evidence ledger R1..Rn with source, time, live/cached/simulated', 'Own loop (~150 lines) instead of LangGraph: visible, logged, testable offline. gpt-oss:120b on Ollama Cloud: allowed, free tier, reliable tool calling, temperature 0', 'Red boxes = stop rules: better to stop and say why than to guess'] },
  { id: 'live', part: 2, story: "<b>One real run, start to finish.</b> We give the agent only the bug ID and watch what it decides to do. <span style='color:#c4a7ff'>Purple</span> = the AI deciding · <span style='color:var(--low)'>green</span> = a tool answering · <span style='color:var(--medium)'>orange</span> = code checking the AI's work.", icon: 'play', kicker: 'Demonstration', title: 'Complete run', render: renderLive,
    notes: ['Only input is the CVE ID: analysts start from an advisory, so the agent must find the affected machines itself', 'Click the NVD card: CVSS 7.8, 9 affected product families + fixed builds; then KEV confirms exploitation', 'Queries like \'Windows Server 2016\' were built by the model from the NVD answer = the model-driven decision', 'It fetches S03/S07/S08 because evidence can contradict the asset record (the conflict test)', 'Validator card: the first submission is rejected with the exact problems; this happened in every live run', 'Bottom line: 23 affected records → 1 High (W15), 1 Medium (offline root CA, partial), 12 stale laptops insufficient, 20 Low; CVSS-only would flag all 23', 'W15: build 9339 < 9512, payroll operators log on, P1 × High = High, KEV capped; confidence Medium because the facts come from S07/S08', '8b: NVD down, no cache → stops in seconds, insufficient evidence, names lookup_vulnerability; with a cache it continues as cached + Medium confidence'] },
  { id: 'validator', part: 2, story: "<b>Why we don't trust the AI:</b> its first answer was incomplete in every run. This is the check that catches it.", icon: 'check', kicker: 'Output validation', title: 'The validator: trust, but verify', render: renderValidator,
    notes: ['First live run: 3 of 23 machines submitted; in all 7 completed check runs the first submission was incomplete', 'A forgotten machine looks identical to a safe one = the worst failure for triage', '6 checks against the ledger: real machines, matching facts, code redoes the comparison, cited evidence fetched, full coverage, code-side conflict scan', '2 correction rounds (one usually suffices, the cap prevents endless loops); still failing → insufficient evidence, never a silent Low', 'Honest: the policy reads tool data anyway, so completeness is the critical part; \'model proposes, code verifies\' (OWASP improper output handling)'] },
  { id: 'tests', part: 2, story: "<b>Does it work beyond one case?</b> We wrote down the expected answers first, then changed one thing at a time and compared.", icon: 'flask', kicker: 'Testing', title: 'Expected vs actual', render: renderTests,
    notes: ['Expected results written before any run (Paul, Oct 11, before the agent existed; git proves it)', 'One change per check: patched → Low (gate only); no PII, internal only → P3 → Medium via KEV; missing / conflict → insufficient, naming both sources', 'Failures: NVD down + cache → High, cached, Medium; no cache → stop; fake tool injected because the model refused to call one when asked', 'Run pytest: 120 offline tests; policy code = Paul\'s reference on 48 machines × 5 snapshots = 240 cases', 'Live runs changed the design: prompt fix for get_evidence, retries for Ollama 500s'] },
  { id: 'review', part: 2, story: "<b>The last check is a person.</b> We compared every claim behind the W15 rating with the original sources.", icon: 'usercheck', kicker: 'Human review', title: 'Human review of the evidence', render: renderReview,
    notes: ['Required by the assignment; we compared every claim with the original sources, not the agent\'s report', 'A1: 9339 in the asset record, in S08 and in the agent output. A2: fix 9512 in raw NVD and on Microsoft\'s advisory', '18 of 19 confirmed; A11 flagged: step 3 misreads \'patch approval recorded 60 days before snapshot\'. The rating is unaffected (code decides) → this is why a human signs off', 'Baseline = frozen inputs, settings, code version, outputs for Assignment 4'] },
  { id: 'limits', part: 2, story: "<b>Being honest:</b> what this can't do yet, and what comes next.", icon: 'alert', kicker: 'Wrap-up', title: 'Limitations and next steps', render: renderLimits,
    notes: ['Simulated environment → confidence Medium; real use needs a live inventory', 'The model\'s steps vary between runs, the ratings didn\'t; one model tested', 'The applicability check is written for local privilege escalation; internet-exploitable CVEs need another prerequisite', 'Narrow code-side conflict detection; flaky free tier; the agent recommends only', 'Answer: yes, specifically W15, patch now. The model investigates, code verifies and decides, a human signs. Next: tracing and evaluation in Assignment 4. Thank you'] },
];

let current = 0;

function buildNav() {
  let html = '';
  for (const part of [1, 2]) {
    html += `<div class="nav-part"><span>Part ${part}</span><b>${TEAM[part].name.split(' ')[0]}</b></div>`;
    SCENES.forEach((s, i) => {
      if (s.part !== part) return;
      html += `<div class="nav-item" data-i="${i}"><span class="nav-num">${String(i + 1).padStart(2, '0')}</span>${icon(s.icon)}<span>${esc(s.title.split(' (')[0])}</span></div>`;
    });
  }
  $('#nav').innerHTML = html;
  $$('.nav-item').forEach((el) => (el.onclick = () => go(+el.dataset.i)));
  $('#progress').innerHTML = SCENES.map((s) => `<span class="${s.part === 2 ? 'p2' : ''}"></span>`).join('');
  $('#brand-icon').innerHTML = icon('shield');
}

async function go(i) {
  current = Math.max(0, Math.min(SCENES.length - 1, i));
  const s = SCENES[current];
  location.hash = s.id;
  $$('.nav-item').forEach((el) => el.classList.toggle('active', +el.dataset.i === current));
  $$('#progress span').forEach((el, j) => el.classList.toggle('on', j <= current));
  $('#scene-kicker').textContent = `${String(current + 1).padStart(2, '0')} · ${s.kicker}`;
  $('#scene-title').textContent = s.title;
  const t = TEAM[s.part];
  $('#scene-narrator').innerHTML = `<span class="muted">${t.role} · narrated by</span> <b>${t.name}</b> <span class="avatar" style="background:${t.color}">${t.short}</span>`;
  $('#notes-body').innerHTML = `<ul>${s.notes.map((n) => `<li>${esc(n)}</li>`).join('')}</ul>`;
  updatePresenter();
  const story = $('#scene-story');
  story.innerHTML = s.story || '';
  story.classList.toggle('hidden', !s.story);
  $('#prev').disabled = current === 0;
  $('#next').disabled = current === SCENES.length - 1;
  const el = $('#scene');
  el.scrollTop = 0;
  el.innerHTML = '<div class="status-line"><span class="spin"></span> Loading…</div>';
  try { await s.render(el); } catch (e) { el.innerHTML = `<div class="callout bad">Could not load this scene: ${esc(e.message)}</div>`; console.error(e); }
}

$('#prev').onclick = () => go(current - 1);
$('#next').onclick = () => go(current + 1);
document.addEventListener('keydown', (e) => {
  if (['INPUT', 'TEXTAREA', 'SELECT'].includes(document.activeElement.tagName)) return;
  if (e.key === 'ArrowRight') go(current + 1);
  else if (e.key === 'ArrowLeft') go(current - 1);
  else if (e.key.toLowerCase() === 'n') $('#notes').classList.toggle('hidden');
  else if (e.key.toLowerCase() === 'f') document.body.classList.toggle('focus');
  else if (e.key.toLowerCase() === 'p') openPresenter();
  else if (e.key === 'Escape') { $('#modal').classList.add('hidden'); $('.drawer')?.remove(); }
});

// ---------- presenter window (keep it outside the recorded area) ----------
let presenter = null;
function openPresenter() {
  presenter = window.open('', 'triage-presenter', 'width=520,height=720');
  if (!presenter) { alert('Allow pop-ups for this page to open the presenter window.'); return; }
  presenter.document.title = 'Presenter notes';
  presenter.document.body.style.cssText = 'font:16px/1.55 -apple-system,sans-serif;background:#fff8e1;color:#2b2410;margin:0;padding:18px 22px';
  presenter.onkeydown = (e) => { if (e.key === 'ArrowRight') go(current + 1); if (e.key === 'ArrowLeft') go(current - 1); };
  updatePresenter();
}
function updatePresenter() {
  if (!presenter || presenter.closed) return;
  const s = SCENES[current], next = SCENES[current + 1];
  presenter.document.body.innerHTML = `<div style="font-size:12px;letter-spacing:1px;text-transform:uppercase;color:#7a6a3c">Scene ${current + 1} / ${SCENES.length} · narrated by ${esc(TEAM[s.part].name)}</div>
    <h2 style="margin:4px 0 12px">${esc(s.title)}</h2><ol style="padding-left:20px">${s.notes.map((n) => `<li style="margin-bottom:10px">${esc(n)}</li>`).join('')}</ol>
    <div style="margin-top:18px;font-size:13px;color:#7a6a3c">Next: ${next ? esc(next.title) + (next.part !== s.part ? ' · hand over to ' + esc(TEAM[next.part].name) : '') : 'end'} · ← → work in this window too</div>`;
}

// ---------- 01 intro ----------
async function renderIntro(el) {
  el.innerHTML = `
  <div class="hero">
    <div class="muted" style="text-transform:uppercase;letter-spacing:1.4px;font-size:12px">CVE-2026-85880 × Northbridge Services</div>
    <h2>Does this Windows bug put our company at risk?</h2>
    <p class="lead" style="margin:0">Give the agent <b>one known bug ID</b>. It finds <b>every machine</b> the bug affects, rates each one
      <span class="dec dec-High">High</span> <span class="dec dec-Medium">Medium</span> <span class="dec dec-Low">Low</span> or
      <span class="dec dec-INSUFFICIENT_EVIDENCE">INSUFFICIENT EVIDENCE</span> with our policy, cites where every fact came from, and recommends what to do.</p>
    <div class="pipeline">
      <div class="pipe"><div class="who who-code">Input</div><b>CVE ID</b><div class="muted">CVE-2026-85880</div></div>
      <div class="pipe"><div class="who who-llm">AI model</div><b>Plans lookups</b><div class="muted">chooses tools and queries</div></div>
      <div class="pipe"><div class="who who-tool">Tools</div><b>NVD · KEV · Inventory</b><div class="muted">live + simulated data</div></div>
      <div class="pipe"><div class="who who-code">Code</div><b>Validator</b><div class="muted">checks every fact</div></div>
      <div class="pipe"><div class="who who-code">Code</div><b>Policy</b><div class="muted">decides the rating</div></div>
      <div class="pipe"><div class="who who-human">Human</div><b>Analyst review</b><div class="muted">signs off</div></div>
    </div>
  </div>
  <div class="grid g2" style="margin-top:16px">
    ${[1, 2].map((p) => `<div class="card"><div class="row"><span class="avatar" style="background:${TEAM[p].color}">${TEAM[p].short}</span><div><b>${TEAM[p].name}</b><div class="muted" style="font-size:13px">${TEAM[p].role}</div></div></div>
      <p class="muted" style="font-size:14px;margin-top:10px">${p === 1
        ? '<b>A:</b> case selection, environment v1.1, assumptions, rating policy, expected results. <b>B:</b> NVD and KEV clients, environment lookups, tool registry, caching and fallback.'
        : '<b>C:</b> agent loop, prompts, output validation, policy code, assessment output. <b>D:</b> workflow diagram, tests and controlled failures, evidence review, baseline, this demo.'}</p></div>`).join('')}
  </div>
  <div class="card" style="margin-top:16px">
    <h3>${icon('sparkles')} In plain words: a hospital triage</h3>
    <table class="analogy"><tbody>
      <tr><td>A named disease</td><td><b>CVE</b>: the official ID of one known bug</td></tr>
      <tr><td>The encyclopedia entry: who gets it, which medicine cures it</td><td><b>NVD</b>: affected products and the first fixed version</td></tr>
      <tr><td>"How dangerous is this disease in general?"</td><td><b>CVSS</b>: 0–10 severity, the same for everyone</td></tr>
      <tr><td>Outbreak alert: it is spreading right now</td><td><b>KEV</b>: confirmed exploited in real attacks</td></tr>
      <tr><td>Patient files</td><td><b>Environment snapshot</b>: 48 machine records of a fictional company</td></tr>
      <tr><td>Triage protocol</td><td><b>Rating policy</b>: our rulebook, applied by code</td></tr>
      <tr><td>Nurse fills the chart, senior nurse double-checks, doctor signs</td><td><b>AI agent</b> → <b>validator</b> → <b>human review</b></td></tr>
    </tbody></table>
  </div>`;
}

// ---------- 02 threat ----------
const VEC = {
  AV: { L: ['Attack vector: Local', 'The attacker must already be able to run code on the machine', true], N: ['Attack vector: Network', 'Exploitable over the network', false] },
  AC: { L: ['Attack complexity: Low', 'No special conditions needed', false], H: ['Attack complexity: High', '', false] },
  PR: { L: ['Privileges required: Low', 'A normal (non-admin) user account is enough', true], N: ['Privileges required: None', '', false], H: ['Privileges required: High', '', false] },
  UI: { N: ['User interaction: None', 'No victim has to click anything', false], R: ['User interaction: Required', '', false] },
  S: { U: ['Scope: Unchanged', 'Impact stays on the vulnerable machine', false], C: ['Scope: Changed', '', false] },
  C: { H: ['Confidentiality: High', 'Can read everything (SYSTEM)', false] },
  I: { H: ['Integrity: High', 'Can change everything', false] },
  A: { H: ['Availability: High', 'Can shut things down', false] },
};
async function renderThreat(el) {
  const t = await once('threat', () => api.get('/api/threat'));
  const n = t.nvd, cv = n.cvss_v31 || {}, k = t.kev;
  const parts = (cv.vector || '').split('/').slice(1).map((p) => p.split(':'));
  el.innerHTML = `
  <p class="lead">Four public sources, four different jobs. Our agent uses them for <b>${esc(n.cve_id)}</b>.</p>
  <div class="grid g2">
    <div class="card src-card"><div class="tag">CVE</div><div class="by">CVE Program · run by MITRE, funded by CISA · this ID assigned by Microsoft (a "CNA")</div>
      <b>What it is</b><p class="muted">A unique ID for one publicly known bug, so everyone means the same thing.</p>
      <h4>Ours</h4><p><span class="mono">${esc(n.cve_id)}</span>: ${esc(n.description)}</p><p class="muted" style="font-size:13px">Published ${esc((n.published || '').slice(0, 10))} · ${esc((n.cwe || []).join(', '))}</p></div>
    <div class="card src-card"><div class="tag">NVD</div><div class="by">National Vulnerability Database · NIST (U.S. government)</div>
      <b>What it adds</b><p class="muted">Affected products and the <b>first fixed version</b>, plus the severity score. Anything below the fixed build is vulnerable.</p>
      <h4>Affected products → fixed build</h4>
      <table class="products"><tbody>${t.products.map((p) => `<tr><td class="mono">${esc(p.product)}</td><td class="mono">${esc(p.fixed_build || 'not given')}</td></tr>`).join('')}</tbody></table></div>
    <div class="card src-card"><div class="tag">CVSS</div><div class="by">Common Vulnerability Scoring System · FIRST</div>
      <b>What it is</b><p class="muted">A 0–10 technical severity, <b>identical for every company</b> in the world.</p>
      <div class="row" style="margin:8px 0"><div class="big-num" style="color:var(--high)">${esc(cv.base_score)}</div><div><b>${esc(cv.base_severity)}</b><div class="muted" style="font-size:12px">${esc(cv.source)} (${esc(cv.type)}; NVD has no own score)</div></div></div>
      <div class="vector">${parts.map(([m, v]) => { const d = (VEC[m] || {})[v] || [`${m}:${v}`, '', false]; return `<div class="vec ${d[2] ? 'hot' : ''}" title="${esc(d[1])}"><b>${esc(m)}:${esc(v)}</b>${esc(d[0])}${d[1] ? `<div class="muted" style="font-size:12px">${esc(d[1])}</div>` : ''}</div>`; }).join('')}</div></div>
    <div class="card src-card"><div class="tag">KEV</div><div class="by">Known Exploited Vulnerabilities catalog · CISA (U.S. government)</div>
      <b>What it is</b><p class="muted">Bugs confirmed to be <b>used in real attacks</b>. U.S. federal agencies must patch them by a due date. Not on KEV ≠ safe.</p>
      <h4>Ours</h4><div class="kv compact"><div>Listed</div><div><b style="color:var(--high)">Yes</b></div><div>Added</div><div>${esc(k.dateAdded)}</div><div>Due date</div><div>${esc(k.dueDate)} <span class="muted">(already passed at snapshot date)</span></div><div>Ransomware use</div><div>${esc(k.knownRansomwareCampaignUse)}</div></div>
      <p class="muted" style="font-size:12px">${esc(k.vulnerabilityName || '')}</p></div>
  </div>
  <div class="callout" style="margin-top:18px"><b>Severity ≠ risk.</b> CVSS says this bug is 7.8 for everyone. Our job is <b>local risk</b>: the same bug is
    ${dec('High')} on an unpatched payroll server that normal users log on to, and ${dec('Low')} on a patched DHCP server.</div>`;
}

// ---------- 03 company ----------
const ZONE_ORDER = ['LEGACY', 'IDENTITY', 'APPS', 'DATA', 'USERS', 'ADMIN', 'MGMT', 'BACKUP', 'DMZ', 'CLOUD', 'DEV', 'STORAGE', 'IOT'];
let companyState = { snapshot: 'environment/northbridge-v1.1.json', color: 'cve' };
async function renderCompany(el) {
  const meta = await once('meta', () => api.get('/api/meta'));
  const env = await once(`env:${companyState.snapshot}`, () => api.get(`/api/environment?snapshot=${encodeURIComponent(companyState.snapshot)}`));
  const zones = Object.fromEntries(env.zones.map((z) => [z.zone_id, z]));
  const byZone = {};
  env.assets.forEach((a) => (byZone[a.record.zone] ||= []).push(a));
  const variant = companyState.snapshot !== meta.snapshots[0].path;
  const colorOf = (a) => companyState.color === 'cve' ? DEC_COLOR[a.policy.decision] : companyState.color === 'prio' ? PRIO_COLOR[a.priority] :
    ({ restricted_pii: 'var(--high)', pii: 'var(--medium)' }[a.record.data_classification] || 'var(--none)');
  const legend = companyState.color === 'cve'
    ? `<span style="--c:var(--high)">High</span><span style="--c:var(--medium)">Medium</span><span style="--c:var(--low)">Low (incl. not affected)</span><span style="--c:var(--insuf)">Insufficient evidence</span>`
    : companyState.color === 'prio' ? `<span style="--c:var(--high)">P1</span><span style="--c:var(--medium)">P2</span><span style="--c:var(--low)">P3</span>`
      : `<span style="--c:var(--high)">Restricted PII</span><span style="--c:var(--medium)">PII</span><span style="--c:var(--none)">No PII</span>`;
  el.innerHTML = `
  <div class="row" style="margin-bottom:12px">
    <div class="card tight"><b>${esc(env.organization.name)}</b> <span class="muted">· ${env.organization.staff.toLocaleString()} staff · ${env.assets.length} asset records · ${env.zones.length} network zones · ${env.flows.length} allowed flows · snapshot ${esc(env.snapshot_date)}</span>
      <span class="mode mode-simulated" style="margin-left:6px">simulated</span></div>
    <span class="spacer"></span>
    <label class="field">Snapshot<select id="snap">${meta.snapshots.map((s) => `<option value="${s.path}" ${s.path === companyState.snapshot ? 'selected' : ''}>${esc(s.label)}</option>`).join('')}</select></label>
    <label class="field">Color by<select id="colorby"><option value="cve">CVE-2026-85880 result</option><option value="prio">Machine priority (impact)</option><option value="data">Data sensitivity</option></select></label>
    <button class="btn ghost small" onclick="openDoc('changes','What we changed from the course scenario')">What Paul changed (v1.0 → v1.1)</button>
  </div>
  ${variant ? `<div class="callout warn"><b>Test variant:</b> ${esc(env.variant_change)}. Only W15 differs from the base snapshot.</div>` : ''}
  <div class="legend" style="margin-bottom:10px">${legend}<span class="muted" style="margin-left:auto">Click any machine for its full record</span></div>
  <div class="zones">${ZONE_ORDER.filter((z) => byZone[z]).map((z) => `
    <div class="zone"><div class="zone-head"><span class="zone-name">${esc(z)}</span><span class="zone-net">${esc(zones[z]?.hq_subnet || (z === 'CLOUD' ? 'Microsoft cloud' : ''))}</span></div>
      <div class="muted" style="font-size:12px;margin:-4px 0 8px">${esc(zones[z]?.purpose || 'Vendor-managed cloud services')}</div>
      <div class="assets">${byZone[z].map((a) => `<div class="asset ${variant && a.record.asset_id === 'W15' ? 'changed' : ''}" data-i="${a.index}" style="border-left-color:${colorOf(a)}">
        <span class="aid">${esc(a.record.asset_id)}</span> ${esc(a.record.instance)}<div class="os">${esc(a.record.os?.name || '')} ${a.record.os?.build ? '· ' + esc(a.record.os.build) : ''}</div></div>`).join('')}</div></div>`).join('')}
  </div>`;
  $('#colorby').value = companyState.color;
  $('#snap').onchange = (e) => { companyState.snapshot = e.target.value; renderCompany(el); };
  $('#colorby').onchange = (e) => { companyState.color = e.target.value; renderCompany(el); };
  $$('.asset', el).forEach((t) => (t.onclick = () => assetDrawer(env, env.assets[+t.dataset.i])));
}

function assetDrawer(env, a) {
  $('.drawer')?.remove();
  const r = a.record, os = r.os || {};
  const flows = env.flows.filter((f) => f.to === r.zone || f.from === r.zone);
  const d = document.createElement('div');
  d.className = 'drawer';
  d.innerHTML = `
    <div class="row"><div><div class="muted mono" style="font-size:12px">${esc(a.locator)} · ${esc(r.source_mode)}</div><h2 style="margin:2px 0">${esc(r.asset_id)} ${esc(r.instance)}</h2><div class="muted">${esc(r.role)}</div></div><span class="spacer"></span><button class="btn ghost small" id="dclose">Close ✕</button></div>
    <div class="card tight" style="margin:14px 0"><div class="row">${dec(a.policy.decision)}<span class="muted" style="font-size:13px">${esc(a.policy.applicability)}: ${esc(a.policy.applicability_reason)}</span></div>
      <div class="muted mono" style="font-size:12px;margin-top:6px">${esc(a.policy.rule)}</div>
      ${a.agent ? `<div style="font-size:13px;margin-top:6px">Agent's baseline run: ${dec(a.agent.decision)}</div>` : ''}</div>
    <div class="kv">
      <div>Zone</div><div>${esc(r.zone)}</div><div>Count</div><div>${esc(r.count ?? '—')}</div>
      <div>OS</div><div>${esc(os.name)} ${esc(os.version || '')}</div><div>Build</div><div class="mono">${os.build ? esc(os.build) : '<span style="color:var(--insuf)">unknown (null)</span>'}</div>
      <div>Last update</div><div>${esc(os.last_cumulative_update ?? '—')} ${esc(os.last_update_kb ?? '')}</div>
      <div>CVE product</div><div class="mono">${esc(a.cpe_label ?? '—')} ${a.affected ? `<span class="chip" style="color:var(--high)">affected · fixed ${esc(a.fixed_build)}</span>` : '<span class="chip">not affected</span>'}</div>
      <div>Low-priv logon</div><div>${r.low_priv_local_access === null ? '<span style="color:var(--insuf)">unknown</span>' : esc(r.low_priv_local_access)}</div>
      <div>Data</div><div>${esc(r.data_classification)} / ${esc(r.data_protection)}</div><div>Exposure</div><div>${esc(r.exposure)}</div>
      <div>Priority</div><div><b style="color:${PRIO_COLOR[a.priority] || 'inherit'}">${esc(a.priority ?? '?')}</b> <span class="muted">${esc(a.priority_reason)}</span></div>
      <div>Business service</div><div>${esc(r.business_service ?? '—')}</div>
    </div>
    ${r.notes ? `<h4 class="muted">Notes</h4><p>${esc(r.notes)}</p>` : ''}
    ${r.config && Object.keys(r.config).length ? `<h4 class="muted">Config</h4><pre class="json">${esc(JSON.stringify(r.config, null, 2))}</pre>` : ''}
    <h4 class="muted">Evidence records</h4><div class="row">${(r.evidence_ids || []).map((id) => `<button class="btn ghost small ev-btn" data-id="${id}">${id}</button>`).join('')}</div><div id="evbox"></div>
    ${a.assumptions.length ? `<h4 class="muted">Group assumptions</h4><ul>${a.assumptions.map((x) => `<li style="font-size:13px">${esc(x)}</li>`).join('')}</ul>` : ''}
    <h4 class="muted">Network flows touching ${esc(r.zone)}</h4>${flows.length ? `<table><tbody>${flows.map((f) => `<tr><td class="mono">${esc(f.flow_id)}</td><td>${esc(f.from)} → ${esc(f.to)}</td><td class="muted">${esc(f.purpose)}</td></tr>`).join('')}</tbody></table>` : '<p class="muted">None listed (default deny)</p>'}`;
  document.body.appendChild(d);
  $('#dclose', d).onclick = () => d.remove();
  $$('.ev-btn', d).forEach((b) => (b.onclick = () => {
    const ev = env.evidence.find((e) => e.evidence_id === b.dataset.id);
    $('#evbox', d).innerHTML = ev ? `<div class="card tight" style="margin-top:8px"><b>${esc(ev.evidence_id)} · ${esc(ev.title)}</b> <span class="muted">(${esc(ev.origin)}, ${esc(ev.date)})</span><ul>${ev.facts.map((f) => `<li style="font-size:13px">${esc(f)}</li>`).join('')}</ul><div class="muted" style="font-size:12px">${esc(ev.limitations || '')}</div></div>` : '';
  }));
}

// ---------- 04 policy ----------
async function renderPolicy(el) {
  const base = await once('baseline', () => api.get('/api/run?path=baseline/main_run'));
  const counts = base.assessment.overall.counts;
  const total = base.assessment.assessments.length;
  const rated = await api.post('/api/rate', { asset: {}, threat: {} }).catch(() => null);
  const pm = rated?.matrices?.priority || {}, fm = rated?.matrices?.final || {};
  const prow = [['pii_unprotected', 'PII without protection'], ['pii_protected', 'PII with protection'], ['no_pii', 'No PII']];
  const pcol = [['internet', 'Internet'], ['intranet', 'Intranet'], ['internal_only', 'Internal']];
  el.innerHTML = `
  <div class="grid g2">
    <div class="card"><h3>${icon('x')} Naive approach: sort by CVSS</h3><p class="muted">"7.8 is High, so every affected machine is High."</p>
      <div class="row"><div class="big-num" style="color:var(--high)">${total}</div><div class="muted">affected Windows records would all be <b>High</b>, including ones that are already patched.</div></div></div>
    <div class="card"><h3>${icon('check')} Our policy: applicability × impact</h3><p class="muted">Same CVE, same ${total} records, rated by what is true <b>here</b>:</p>
      <div class="row">${Object.entries(counts).map(([d, c]) => `<div class="card tight" style="text-align:center"><div class="big-num" style="font-size:30px;color:${DEC_COLOR[d]}">${c}</div>${dec(d)}</div>`).join('')}</div></div>
  </div>
  <div class="steps" style="margin-top:16px">
    <div class="step"><span class="n">STEP 1</span><b>Applicability gate</b><span class="muted" style="font-size:13px">Can it work here? Right product, build below the fixed build, a normal user can log on. No → <b>Low</b>. Unknown or conflicting → <b>Insufficient evidence</b>.</span></div>
    <div class="step"><span class="n">STEP 2</span><b>Machine priority</b><span class="muted" style="font-size:13px">How bad would it be here? Data sensitivity × who can reach it → P1/P2/P3. Identity, control planes and 4-hour-RTO services are always P1.</span></div>
    <div class="step"><span class="n">STEP 3</span><b>Severity band</b><span class="muted" style="font-size:13px">CVSS 9+ Critical, 7–8.9 High, 4–6.9 Medium, below 4 Low.</span></div>
    <div class="step"><span class="n">STEP 4</span><b>Final matrix</b><span class="muted" style="font-size:13px">Priority × severity → High / Medium / Low.</span></div>
    <div class="step"><span class="n">STEP 5</span><b>Modifiers</b><span class="muted" style="font-size:13px">On KEV: +1 level. Only partly applicable (e.g. isolated): −1 level. Never above High or below Low.</span></div>
  </div>
  <div class="grid g3" style="margin-top:16px">
    <div class="card"><h3>Step 2 · Priority matrix</h3><table class="matrix"><thead><tr><th></th>${pcol.map((c) => `<th>${c[1]}</th>`).join('')}</tr></thead>
      <tbody>${prow.map((r) => `<tr><th>${r[1]}</th>${pcol.map((c) => { const v = pm[`${r[0]}|${c[0]}`]; return `<td class="cell v-${v}">${v}</td>`; }).join('')}</tr>`).join('')}</tbody></table>
      <p class="muted" style="font-size:12px">"Unknown protection" counts as unprotected, so missing evidence never lowers a rating.</p></div>
    <div class="card"><h3>Step 4 · Final matrix</h3><table class="matrix"><thead><tr><th></th>${['Critical', 'High', 'Medium', 'Low'].map((b) => `<th>${b}</th>`).join('')}</tr></thead>
      <tbody>${['P1', 'P2', 'P3'].map((p) => `<tr><th>${p}</th>${['Critical', 'High', 'Medium', 'Low'].map((b) => { const v = fm[`${p}|${b}`]; return `<td class="cell v-${v}">${v}</td>`; }).join('')}</tr>`).join('')}</tbody></table>
      <p class="muted" style="font-size:12px">A P1 machine with a confirmed flaw is never Low.</p></div>
    <div class="card"><h3>Is it valid?</h3>
      <p style="font-size:14px"><b>Implemented correctly:</b> <span class="muted">the agent's policy code matches Paul's reference script on all 48 records × 5 snapshots.</span></p>
      <p style="font-size:14px"><b>Sensible:</b> <span class="muted">follows CVSS's own guidance (base score ≠ your risk), CISA's "prioritize KEV", and the spirit of CISA's SSVC decision model.</span></p>
      <p style="font-size:14px"><b>A judgment call:</b> <span class="muted">matrix cells and "KEV +1" are our choices, justified one by one in the policy document.</span></p>
      <button class="btn ghost small" onclick="openDoc('rating_policy','Rating policy')">${icon('book')} Open the full policy</button></div>
  </div>`;
}

// ---------- 05 playground ----------
const PRESETS = {
  'W15 · base snapshot': { affected: 'yes', os_build: '10.0.14393.9339', fixed_build: '10.0.14393.9512', low: 'yes', exposure: 'intranet', data: 'restricted_pii', prot: 'unprotected', override: '', conflict: false, cvss: 7.8, kev: 'yes' },
  'Check 1 · W15 patched (applicability change)': { affected: 'yes', os_build: '10.0.14393.9512', fixed_build: '10.0.14393.9512', low: 'yes', exposure: 'intranet', data: 'restricted_pii', prot: 'unprotected', override: '', conflict: false, cvss: 7.8, kev: 'yes' },
  'Check 2 · W15 no PII, internal only (impact change)': { affected: 'yes', os_build: '10.0.14393.9339', fixed_build: '10.0.14393.9512', low: 'yes', exposure: 'internal_only', data: 'none', prot: 'n/a', override: '', conflict: false, cvss: 7.8, kev: 'yes' },
  'Check 3a · W15 build unknown': { affected: 'yes', os_build: '', fixed_build: '10.0.14393.9512', low: 'yes', exposure: 'intranet', data: 'restricted_pii', prot: 'unprotected', override: '', conflict: false, cvss: 7.8, kev: 'yes' },
  'Check 3b · W15 sources disagree': { affected: 'yes', os_build: '10.0.14393.9339', fixed_build: '10.0.14393.9512', low: 'yes', exposure: 'intranet', data: 'restricted_pii', prot: 'unprotected', override: '', conflict: true, cvss: 7.8, kev: 'yes' },
  'W02 CA-ROOT01 · offline root CA': { affected: 'yes', os_build: '10.0.20348.5256', fixed_build: '10.0.20348.5622', low: 'no', exposure: 'isolated', data: 'none', prot: 'n/a', override: 'Tier-0 identity', conflict: false, cvss: 7.8, kev: 'yes' },
  'W01 DC01-DC04 · domain controllers (patched)': { affected: 'yes', os_build: '10.0.20348.5622', fixed_build: '10.0.20348.5622', low: 'no', exposure: 'internal_only', data: 'none', prot: 'n/a', override: 'Tier-0 identity', conflict: false, cvss: 7.8, kev: 'yes' },
  'E01 · Windows 11 laptops (not affected)': { affected: 'no', os_build: '10.0.26100.9445', fixed_build: '', low: 'yes', exposure: 'intranet', data: 'none', prot: 'n/a', override: '', conflict: false, cvss: 7.8, kev: 'yes' },
};
let pg = { ...PRESETS['W15 · base snapshot'] }, pgPreset = 'W15 · base snapshot';
const tri = (v) => (v === 'yes' ? true : v === 'no' ? false : null);
async function renderPlayground(el) {
  const sel = (id, label, opts) => `<label class="field">${label}<select id="${id}">${opts.map(([v, t]) => `<option value="${v}" ${String(pg[id]) === String(v) ? 'selected' : ''}>${t}</option>`).join('')}</select></label>`;
  const yn = [['yes', 'Yes'], ['no', 'No'], ['unknown', 'Unknown (null)']];
  el.innerHTML = `
  <div class="grid" style="grid-template-columns: 420px minmax(0,1fr)">
    <div class="card">
      <label class="field">Preset<select id="preset">${Object.keys(PRESETS).map((k) => `<option ${k === pgPreset ? 'selected' : ''}>${esc(k)}</option>`).join('')}</select></label>
      <h4>Applicability facts</h4>
      <div class="form-grid">
        ${sel('affected', 'Affected product?', yn)}
        ${sel('low', 'Normal user can log on?', yn)}
        <label class="field">OS build<input id="os_build" value="${esc(pg.os_build)}" placeholder="unknown"></label>
        <label class="field">Fixed build (NVD)<input id="fixed_build" value="${esc(pg.fixed_build)}" placeholder="unknown"></label>
        <label class="field" style="flex-direction:row;align-items:center;gap:8px;grid-column:1/-1"><input type="checkbox" id="conflict" ${pg.conflict ? 'checked' : ''}> Evidence S08 disagrees with the asset record</label>
      </div>
      <h4>Impact facts</h4>
      <div class="form-grid">
        ${sel('data', 'Data', [['restricted_pii', 'Restricted PII'], ['pii', 'PII'], ['none', 'No PII']])}
        ${sel('prot', 'Protection', [['unprotected', 'Unprotected / undocumented'], ['protected', 'Protected'], ['n/a', 'n/a']])}
        ${sel('exposure', 'Who can reach it', [['internet', 'Internet'], ['intranet', 'Intranet (users)'], ['internal_only', 'Internal only'], ['isolated', 'Isolated']])}
        ${sel('override', 'P1 override', [['', 'None'], ['Tier-0 identity', 'Tier-0 identity'], ['Control plane or remote-access gateway', 'Control plane'], ['Service with 4-hour RTO', '4-hour RTO service']])}
      </div>
      <h4>Threat facts</h4>
      <div class="form-grid">
        <label class="field">CVSS score<input id="cvss" type="number" step="0.1" min="0" max="10" value="${pg.cvss}"></label>
        ${sel('kev', 'On CISA KEV?', yn)}
      </div>
    </div>
    <div id="pg-out"></div>
  </div>`;
  $('#preset').onchange = (e) => { if (!PRESETS[e.target.value]) return; pgPreset = e.target.value; pg = { ...PRESETS[pgPreset] }; renderPlayground(el); };
  ['affected', 'low', 'data', 'prot', 'exposure', 'override', 'kev'].forEach((id) => ($('#' + id).onchange = (e) => { pg[id] = e.target.value; computePg(); }));
  ['os_build', 'fixed_build', 'cvss'].forEach((id) => ($('#' + id).oninput = (e) => { pg[id] = id === 'cvss' ? e.target.value : e.target.value.trim(); computePg(); }));
  $('#conflict').onchange = (e) => { pg.conflict = e.target.checked; computePg(); };
  computePg();
}
let pgTimer;
function computePg() {
  clearTimeout(pgTimer);
  pgTimer = setTimeout(async () => {
    const asset = { affected: tri(pg.affected), os_build: pg.os_build || null, fixed_build: pg.fixed_build || null,
      low_priv_local_access: tri(pg.low), exposure: pg.exposure, data_classification: pg.data, data_protection: pg.prot,
      priority_override: pg.override || null, conflicts: pg.conflict ? ['S08 states a different build than the asset record'] : [] };
    if (asset.os_build && !/^\d+(\.\d+)*$/.test(asset.os_build)) return;
    if (asset.fixed_build && !/^\d+(\.\d+)*$/.test(asset.fixed_build)) return;
    const r = await api.post('/api/rate', { asset, threat: { cvss_score: pg.cvss === '' ? null : +pg.cvss, in_kev: tri(pg.kev) } });
    const m = /matrix: (\w+) x (\w+)/.exec(r.priority_reason || '');
    const gateStop = ['Not applicable', 'Unknown', 'Conflict'].includes(r.applicability);
    const prow = [['pii_unprotected', 'PII, unprotected'], ['pii_protected', 'PII, protected'], ['no_pii', 'No PII']];
    const pcol = [['internet', 'Internet'], ['intranet', 'Intranet'], ['internal_only', 'Internal']];
    const pm = r.matrices.priority, fm = r.matrices.final;
    const bands = [['Critical', 'Crit'], ['High', 'High'], ['Medium', 'Med'], ['Low', 'Low']];
    $('#pg-out').innerHTML = `
      <div class="result-big">${dec(r.decision)}<div><div class="mono" style="font-size:14px">${esc(r.rule)}</div>
        <div class="muted" style="font-size:13px">Confidence: ${esc(r.confidence ?? 'n/a')}${r.confidence_reason ? ' · ' + esc(r.confidence_reason) : ''}</div></div></div>
      <div class="trail">
        <div class="t"><span class="k">1 · Gate</span><span><b>${esc(r.applicability)}</b> · ${esc(r.applicability_reason)}${gateStop ? ' <span class="chip">stops here</span>' : ''}</span></div>
        <div class="t" style="${gateStop ? 'opacity:.45' : ''}"><span class="k">2 · Priority</span><span><b>${esc(r.priority ?? 'unknown')}</b> · ${esc(r.priority_reason)}</span></div>
        <div class="t" style="${gateStop ? 'opacity:.45' : ''}"><span class="k">3 · Severity</span><span><b>${esc(r.severity_band ?? 'unknown')}</b> from CVSS ${esc(pg.cvss)}</span></div>
        <div class="t" style="${gateStop ? 'opacity:.45' : ''}"><span class="k">4–5 · Matrix</span><span class="mono">${esc(r.rule)}</span></div>
      </div>
      <div class="grid g2" style="margin-top:12px">
        <div class="card tight"><b>Priority matrix</b><table class="matrix"><thead><tr><th></th>${pcol.map((c) => `<th>${c[1]}</th>`).join('')}</tr></thead><tbody>
          ${prow.map((rw) => `<tr><th>${rw[1]}</th>${pcol.map((c) => { const v = pm[`${rw[0]}|${c[0]}`]; return `<td class="cell v-${v} ${m && m[1] === rw[0] && m[2] === c[0] ? 'hit' : ''}">${v}</td>`; }).join('')}</tr>`).join('')}</tbody></table>
          ${pg.override ? `<div class="muted" style="font-size:12px">Override applies: ${esc(pg.override)} → P1</div>` : ''}</div>
        <div class="card tight" style="${gateStop ? 'opacity:.45' : ''}"><b>Final matrix</b> <span class="muted" style="font-size:12px">priority × severity, before modifiers</span><table class="matrix"><thead><tr><th></th>${bands.map((b) => `<th>${b[1]}</th>`).join('')}</tr></thead><tbody>
          ${['P1', 'P2', 'P3'].map((p) => `<tr><th>${p}</th>${bands.map(([b]) => { const v = fm[`${p}|${b}`]; return `<td class="cell v-${v} ${!gateStop && r.priority === p && r.severity_band === b ? 'hit' : ''}">${v === 'Medium' ? 'Med' : v}</td>`; }).join('')}</tr>`).join('')}</tbody></table></div>
      </div>
      <p class="muted" style="font-size:12px;margin-top:10px">Computed by <span class="mono">src/policy.py</span>, the same function the agent uses after validation.</p>`;
  }, 120);
}

// ---------- 06 tools ----------
const TOOL_INFO = {
  lookup_vulnerability: { src: 'NVD CVE API 2.0 (NIST)', mode: 'live', by: 'Paul · src/sources/nvd.py', out: 'CVSS score + vector, affected products, first fixed build per product, NVD\'s KEV fields', fail: 'Retry once → cached copy (labeled cached) → error, never invented', args: { cve_id: 'CVE-2026-85880' } },
  lookup_kev: { src: 'CISA KEV JSON feed', mode: 'live', by: 'Paul · src/sources/kev.py', out: 'Listed or not, date added, due date, required action', fail: 'Retry once → cached feed → error. Not listed ≠ safe', args: { cve_id: 'CVE-2026-85880' } },
  lookup_environment: { src: 'Northbridge snapshot (JSON file)', mode: 'simulated', by: 'Paul · src/tools/environment.py', out: 'Machine records, evidence S01–S08, network flows, documented absences, business services (6 actions)', fail: 'Null stays null and is listed as unknown. "Not found" does not prove absence', args: { action: 'search_assets', query: 'Windows Server 2016' } },
};
async function renderTools(el) {
  const meta = await once('meta', () => api.get('/api/meta'));
  el.innerHTML = `
  <div class="card" style="margin-bottom:16px"><h3>${icon('bot')} How a tool call works</h3>
    <div class="pipeline" style="margin-top:6px">
      <div class="pipe"><div class="who who-llm">AI model writes</div><span class="mono" style="font-size:12px">{"name": "lookup_kev", "arguments": {"cve_id": "CVE-2026-85880"}}</span></div>
      <div class="pipe"><div class="who who-code">Code checks</div>known tool? arguments valid?</div>
      <div class="pipe"><div class="who who-tool">Code runs it</div>calls NVD / CISA / reads the snapshot</div>
      <div class="pipe"><div class="who who-code">Code returns</div>result + source + time + live / cached / simulated</div>
    </div>
    <p class="muted" style="font-size:13px;margin-bottom:0">Written from scratch in plain Python; no agent framework. The AI never touches the internet or files directly.</p></div>
  <div class="grid g3">${meta.tools.map((t) => { const i = TOOL_INFO[t.name]; return `
    <div class="card"><div class="row"><span class="tool-name">${t.name}</span>${mode(i.mode)}</div>
      <div class="muted" style="font-size:12px">${esc(i.by)}</div>
      <div class="io"><div>Source</div><div>${esc(i.src)}</div><div>Returns</div><div>${esc(i.out)}</div><div>On failure</div><div>${esc(i.fail)}</div></div>
      <label class="field">Arguments (JSON)<textarea id="args-${t.name}">${esc(JSON.stringify(i.args))}</textarea></label>
      <div class="row" style="margin-top:8px"><button class="btn small" data-tool="${t.name}">${icon('play')} Try it</button><span class="muted" id="pv-${t.name}" style="font-size:12px"></span></div>
      <div id="out-${t.name}"></div></div>`; }).join('')}</div>
  <div class="grid g2" style="margin-top:16px">
    <div class="card"><h3><span class="tool-name">submit_findings</span> <span class="chip">built by Supawich</span></h3>
      <p class="muted" style="font-size:14px">The AI's "hand in your answer" tool: one entry per machine with the facts it extracted. Code validates it before anything is rated (scene 9).</p></div>
    <div class="card"><h3>${icon('x')} An invalid request</h3><p class="muted" style="font-size:14px">What happens if the AI asks for a tool that does not exist?</p>
      <button class="btn ghost small" id="bad">Call <span class="mono">scan_network {"target": "W15"}</span></button><div id="out-bad"></div></div>
  </div>`;
  $$('button[data-tool]', el).forEach((b) => (b.onclick = async () => {
    const name = b.dataset.tool;
    let args;
    try { args = JSON.parse($(`#args-${name}`).value); } catch { $(`#out-${name}`).innerHTML = '<div class="callout bad">Arguments are not valid JSON</div>'; return; }
    b.disabled = true; $(`#pv-${name}`).innerHTML = '<span class="spin"></span>';
    const r = await api.post('/api/tool', { name, args });
    b.disabled = false;
    $(`#pv-${name}`).innerHTML = `${mode(r.result.source_mode || r.result.status)} ${esc(r.preview)}`;
    $(`#out-${name}`).innerHTML = `<pre class="json">${esc(JSON.stringify(r.result, null, 2))}</pre>`;
  }));
  $('#bad').onclick = async () => {
    const r = await api.post('/api/tool', { name: 'scan_network', args: { target: 'W15' } });
    $('#out-bad').innerHTML = `<pre class="json">${esc(JSON.stringify(r.result, null, 2))}</pre><p class="muted" style="font-size:13px">Rejected before anything runs. The AI reads this error and continues; after 3 rejected calls the run stops without a rating.</p>`;
  };
}

// ---------- 07 architecture ----------
const DG_NODES = {
  input: { x: 20, y: 205, w: 120, h: 58, kind: 'code', t: ['Input', 'CVE ID'], d: 'You type one command: python -m src.main --cve CVE-2026-85880 (or press Run on the next scene). That is the only input.' },
  intake: { x: 165, y: 205, w: 120, h: 58, kind: 'code', t: ['1 · Intake', 'code'], d: 'Checks the CVE ID format, loads the environment snapshot, records its SHA-256, the model, prompt and code version, so the run can be reproduced.' },
  llm: { x: 330, y: 55, w: 190, h: 70, kind: 'llm', t: ['2 · AI model', 'picks the next tool + query'], d: 'gpt-oss:120b on Ollama Cloud. Sees the tool menu and the results so far, then decides what to look up next and with which query (e.g. search_assets "Windows Server 2016"). This is the model-driven decision the assignment requires.' },
  reg: { x: 330, y: 200, w: 190, h: 66, kind: 'code', t: ['registry.execute', 'checks + runs the call'], d: 'Rejects unknown tools and invalid arguments before anything runs. Runs the lookup, retries external sources once, falls back to the cached copy, and wraps every result with its source, time and live / cached / simulated.' },
  ledger: { x: 330, y: 340, w: 190, h: 66, kind: 'code', t: ['Evidence ledger', 'R1, R2, … + blinding'], d: 'Every tool result gets a reference (R1, R2, …). The model gets a copy with the snapshot name hidden, so a test file name cannot leak the answer. Citations in the report point back to these refs.' },
  nvd: { x: 565, y: 160, w: 160, h: 50, kind: 'tool', t: ['NVD', 'live'], d: 'NIST database: CVSS score and the first fixed build for every affected product.' },
  kev: { x: 565, y: 228, w: 160, h: 50, kind: 'tool', t: ['CISA KEV', 'live'], d: 'Is the CVE being exploited in the wild? Date added and due date.' },
  env: { x: 565, y: 296, w: 160, h: 50, kind: 'tool', t: ['Northbridge snapshot', 'simulated'], d: 'The fictional company inventory: machines, builds, data, exposure, logon access, evidence S01–S08.' },
  val: { x: 790, y: 55, w: 170, h: 70, kind: 'code', t: ['3 · Validator', 'every fact == tool data?'], d: 'Checks each fact the model submitted against the ledger, and that every affected product was searched and every affected machine included. Problems go back to the model (2 chances).' },
  policy: { x: 790, y: 185, w: 170, h: 66, kind: 'code', t: ['4 · Policy', 'decides the rating'], d: 'src/policy.py applies the rulebook to the validated tool data: gate → priority → severity → matrix → KEV +1 / Partial −1. The model never chooses the rating.' },
  action: { x: 790, y: 315, w: 170, h: 66, kind: 'llm', t: ['5 · Action text', 'AI drafts next steps'], d: 'The model writes the recommended action and what evidence would change the decision. It cannot change the rating; Low machines get fixed template text.' },
  save: { x: 1010, y: 315, w: 160, h: 66, kind: 'code', t: ['6 · Save', 'report + full trace'], d: 'assessment.json, report.md, trace.jsonl, tool_results.json, messages.json, config.json: everything needed to audit or replay the run.' },
  human: { x: 1010, y: 185, w: 160, h: 66, kind: 'human', t: ['7 · Analyst', 'reviews + signs off'], d: 'A person checks the decision and every citation against the primary sources, and resolves every INSUFFICIENT_EVIDENCE machine.' },
  stop: { x: 40, y: 350, w: 190, h: 58, kind: 'stop', t: ['STOP', 'no rating'], d: 'Three rejected tool calls, the model service down, or the turn/tool budget used up: the run stops and says why, instead of guessing.' },
  stop2: { x: 565, y: 380, w: 160, h: 50, kind: 'stop', t: ['STOP · INSUFFICIENT', 'names failed lookup'], d: 'NVD unreachable and no cached copy: affected products and fixed builds are unknown, so the run stops with INSUFFICIENT_EVIDENCE and names lookup_vulnerability.' },
};
const DG_EDGES = [
  ['input', 'intake'], ['intake', 'llm'], ['llm', 'reg', 'tool call'], ['reg', 'nvd'], ['reg', 'kev'], ['reg', 'env'],
  ['env', 'ledger', 'every result', 'M 565 330 C 545 345 545 373 520 373', '', [560, 362]],
  ['ledger', 'llm', 'result back to AI', 'M 330 373 C 292 373 292 90 330 90', '', [302, 318]],
  ['llm', 'val', 'submit_findings'], ['val', 'llm', 'errors → fix (max 2)', 'M 820 55 C 780 12 560 12 510 55', '', [665, 22]],
  ['val', 'policy', 'accepted'], ['policy', 'action'], ['action', 'save'], ['save', 'human'],
  ['reg', 'stop', '3 rejected · model down', 'M 330 255 C 250 280 180 310 150 350', 'stop', [205, 300]],
  ['nvd', 'stop2', 'down, no cache', 'M 725 185 C 770 230 770 380 725 405', 'stop', [790, 300]],
];
const DG_SEQ = ['input', 'intake', 'llm', 'reg', 'nvd', 'ledger', 'llm', 'reg', 'kev', 'ledger', 'llm', 'reg', 'env', 'ledger', 'llm', 'val', 'llm', 'val', 'policy', 'action', 'save', 'human'];
const DG_SEQ_NOTE = { 15: 'Validator: first submission incomplete → sent back', 17: 'Validator: second submission passes' };

function clip(a, b) {
  const ax = a.x + a.w / 2, ay = a.y + a.h / 2, bx = b.x + b.w / 2, by = b.y + b.h / 2;
  const dx = bx - ax, dy = by - ay;
  const ta = Math.min(Math.abs(a.w / 2 / (dx || 1e-9)), Math.abs(a.h / 2 / (dy || 1e-9)));
  const tb = Math.min(Math.abs(b.w / 2 / (dx || 1e-9)), Math.abs(b.h / 2 / (dy || 1e-9)));
  return [ax + dx * ta, ay + dy * ta, bx - dx * tb, by - dy * tb];
}
function diagramSvg() {
  const fill = { llm: 'rgba(196,167,255,.14)', code: 'rgba(122,162,255,.12)', tool: 'rgba(61,220,151,.12)', human: 'rgba(255,181,71,.14)', stop: 'rgba(255,93,108,.12)' };
  const stroke = { llm: '#c4a7ff', code: '#7aa2ff', tool: '#3ddc97', human: '#ffb547', stop: '#ff5d6c' };
  const edges = DG_EDGES.map(([f, t, label, path, kind, lpos]) => {
    const a = DG_NODES[f], b = DG_NODES[t];
    let d = path, lx, ly;
    if (!d) { const [x1, y1, x2, y2] = clip(a, b); d = `M ${x1} ${y1} L ${x2} ${y2}`; lx = (x1 + x2) / 2; ly = (y1 + y2) / 2; }
    else { const n = d.match(/-?\d+(\.\d+)?/g).map(Number); lx = (n[0] + n[n.length - 2]) / 2; ly = (n[1] + n[n.length - 1]) / 2 - 8; }
    if (lpos) [lx, ly] = [lpos[0], lpos[1] + 4];
    return `<path class="dg-edge ${kind === 'stop' ? 'dg-stop' : ''}" d="${d}" marker-end="url(#arr${kind === 'stop' ? 's' : ''})"/>${label ? `<text class="dg-label" x="${lx}" y="${ly - 4}">${esc(label)}</text>` : ''}`;
  }).join('');
  const nodes = Object.entries(DG_NODES).map(([id, n]) => `<g class="dg-node" data-id="${id}"><rect x="${n.x}" y="${n.y}" width="${n.w}" height="${n.h}" rx="12" fill="${fill[n.kind]}" stroke="${stroke[n.kind]}"/>
    <text x="${n.x + n.w / 2}" y="${n.y + n.h / 2 - 4}" class="dg-t1">${esc(n.t[0])}</text><text x="${n.x + n.w / 2}" y="${n.y + n.h / 2 + 15}" class="dg-t2">${esc(n.t[1])}</text></g>`).join('');
  return `<svg viewBox="0 0 1190 445" class="dg">
    <defs><marker id="arr" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0 0L10 5L0 10z" fill="#8d9ab5"/></marker>
      <marker id="arrs" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0 0L10 5L0 10z" fill="#ff5d6c"/></marker></defs>
    <rect x="305" y="30" width="440" height="410" rx="16" class="dg-group"/><text x="320" y="48" class="dg-group-t">EVIDENCE-GATHERING LOOP</text>
    ${edges}${nodes}</svg>`;
}

async function renderArchitecture(el) {
  const base = await once('baseline', () => api.get('/api/run?path=baseline/main_run'));
  const a = base.assessment, act = a.agent_activity;
  const secs = base.events.length ? base.events[base.events.length - 1].t : 0;
  el.innerHTML = `
  <div class="card" style="padding:12px 14px">
    <div class="row" style="margin-bottom:6px"><span class="legend"><span style="--c:#c4a7ff">AI model</span><span style="--c:#7aa2ff">Code</span><span style="--c:#3ddc97">Tools</span><span style="--c:#ffb547">Human</span><span style="--c:#ff5d6c">Stops instead of guessing</span></span>
      <span class="spacer"></span><button class="btn small" id="dg-play">${icon('play')} Animate a run</button><button class="btn ghost small" id="dg-png">Original diagram</button></div>
    ${diagramSvg()}
  </div>
  <div class="grid g2" style="margin-top:14px">
    <div class="card" id="dg-info"><h3>${icon('workflow')} Click any box</h3><p class="muted">Each box explains what that step does and who does it: the AI, code, a tool, or a person.</p></div>
    <div class="card"><h3>${icon('gauge')} The baseline run in numbers</h3>
      <div class="row">${[[act.tool_calls, 'tool calls chosen by the AI'], [act.rejected_tool_calls, 'invalid call rejected'], [act.submissions, 'submissions (1 sent back)'], [Math.round(secs) + ' s', 'end to end'], [a.assessments.length, 'machines rated']]
        .map(([v, l]) => `<div class="card tight" style="text-align:center;min-width:110px"><div class="big-num" style="font-size:28px">${v}</div><div class="muted" style="font-size:12px">${l}</div></div>`).join('')}</div>
      <button class="btn ghost small" style="margin-top:10px" onclick="openDoc('architecture','Architecture and design')">${icon('book')} Full design document</button></div>
  </div>`;
  const info = $('#dg-info');
  $$('.dg-node', el).forEach((g) => (g.onclick = () => {
    $$('.dg-node', el).forEach((x) => x.classList.toggle('on', x === g));
    const n = DG_NODES[g.dataset.id];
    info.innerHTML = `<h3>${esc(n.t[0])} <span class="chip">${esc({ llm: 'AI model', code: 'code', tool: 'tool', human: 'human', stop: 'stop rule' }[n.kind])}</span></h3><p>${esc(n.d)}</p>`;
  }));
  $('#dg-png').onclick = () => modal('Workflow diagram (docs/workflow.png)', '<img src="/workflow.png" style="width:100%;background:#fff;border-radius:12px">');
  $('#dg-play').onclick = async () => {
    const btn = $('#dg-play'); btn.disabled = true;
    for (let i = 0; i < DG_SEQ.length; i++) {
      if (!document.body.contains(btn)) return;
      const id = DG_SEQ[i];
      $$('.dg-node', el).forEach((x) => x.classList.toggle('on', x.dataset.id === id));
      const n = DG_NODES[id];
      info.innerHTML = `<h3>Step ${i + 1} / ${DG_SEQ.length} · ${esc(n.t[0])}</h3><p>${esc(DG_SEQ_NOTE[i] || n.d)}</p>`;
      await sleep(1300);
    }
    btn.disabled = false;
  };
}

// ---------- 08 live run ----------
let liveState = { tab: 'live', snapshot: 'environment/northbridge-v1.1.json', fault: '', replayPath: 'baseline/main_run', speed: 2, busy: false, token: 0 };
async function renderLive(el) {
  const meta = await once('meta', () => api.get('/api/meta'));
  const runs = await api.get('/api/runs');
  el.innerHTML = `
  <div class="live-wrap">
    <div class="card">
      <div class="row" style="margin-bottom:10px"><button class="btn small ${liveState.tab === 'live' ? '' : 'ghost'}" id="tab-live">Run live</button><button class="btn small ${liveState.tab === 'replay' ? '' : 'ghost'}" id="tab-replay">Replay saved run</button></div>
      <div id="pane-live" class="${liveState.tab === 'live' ? '' : 'hidden'}">
        <label class="field">Environment<select id="lv-snap">${meta.snapshots.map((s) => `<option value="${s.path}" ${s.path === liveState.snapshot ? 'selected' : ''}>${esc(s.label)}</option>`).join('')}</select></label>
        <label class="field" style="margin-top:10px">Controlled failure<select id="lv-fault"><option value="">None</option>
          <option value="nvd-down">NVD unreachable (cache present)</option><option value="nvd-down-no-cache">NVD unreachable, no cache</option>
          <option value="kev-down">KEV unreachable (cache present)</option><option value="bad-tool">Model requests a fake tool</option><option value="llm-down">Model service down</option></select></label>
        <button class="btn" id="lv-run" style="margin-top:14px;width:100%;justify-content:center">${icon('play')} Run the agent</button>
        <p class="muted" style="font-size:12px">Real run: Ollama Cloud model + live NVD and KEV. About 40–90 seconds. Saved to outputs/demo_runs/.</p>
      </div>
      <div id="pane-replay" class="${liveState.tab === 'replay' ? '' : 'hidden'}">
        <label class="field">Saved run<select id="rp-path">${runs.map((r) => `<option value="${esc(r.path)}" ${r.path === liveState.replayPath ? 'selected' : ''}>${esc(r.path === 'baseline/main_run' ? 'Baseline main run' : r.path.replace('outputs/', ''))} · W15 ${esc(r.w15 || '—')}${r.faults.length ? ' · ' + esc(r.faults.join(',')) : ''}</option>`).join('')}</select></label>
        <label class="field" style="margin-top:10px">Speed<select id="rp-speed">${[1, 2, 4, 10, 0].map((s) => `<option value="${s}" ${s === liveState.speed ? 'selected' : ''}>${s ? s + '× real time' : 'Instant'}</option>`).join('')}</select></label>
        <button class="btn" id="rp-play" style="margin-top:14px;width:100%;justify-content:center">${icon('play')} Play</button>
        <p class="muted" style="font-size:12px">Replays the saved trace of a real run, with its real tool results.</p>
      </div>
      <div class="status-line" id="lv-status"></div>
    </div>
    <div class="timeline" id="timeline"><div class="muted" style="padding:20px">Press <b>Run the agent</b> or <b>Play</b>. Each step appears here as it happens.</div></div>
    <div class="results card" id="results"><h3>${icon('gauge')} Result</h3><p class="muted">Appears when the run finishes.</p></div>
  </div>`;
  $('#tab-live').onclick = () => { liveState.tab = 'live'; renderLive(el); };
  $('#tab-replay').onclick = () => { liveState.tab = 'replay'; renderLive(el); };
  $('#lv-snap').onchange = (e) => (liveState.snapshot = e.target.value);
  $('#lv-fault').value = liveState.fault;
  $('#lv-fault').onchange = (e) => (liveState.fault = e.target.value);
  $('#rp-path').onchange = (e) => (liveState.replayPath = e.target.value);
  $('#rp-speed').onchange = (e) => (liveState.speed = +e.target.value);
  $('#lv-run').onclick = startLive;
  $('#rp-play').onclick = () => playReplay(liveState.replayPath);
  if (liveState.autoplay) { const p = liveState.autoplay; liveState.autoplay = null; playReplay(p); }
}

function setStatus(html) { const s = $('#lv-status'); if (s) s.innerHTML = html; }

async function startLive() {
  const token = ++liveState.token;
  $('#timeline').innerHTML = ''; $('#results').innerHTML = `<h3>${icon('gauge')} Result</h3><p class="muted">Running…</p>`;
  $('#lv-run').disabled = true;
  const t0 = Date.now();
  const { id } = await api.post('/api/live', { snapshot: liveState.snapshot, faults: liveState.fault ? [liveState.fault] : [] });
  const ctx = { kind: 'live', id };
  let since = 0;
  while (token === liveState.token) {
    const r = await api.get(`/api/live?id=${id}&since=${since}`);
    r.events.forEach((e) => appendEvent(e, ctx));
    since += r.events.length;
    setStatus(r.done ? '' : `<span class="spin"></span> Running live · ${Math.round((Date.now() - t0) / 1000)} s · ${since} events`);
    if (r.done) {
      if ($('#lv-run')) $('#lv-run').disabled = false;
      if (r.error) { $('#results').innerHTML = `<div class="callout bad">${esc(r.error)}</div>`; return; }
      renderResults(r.run, { kind: 'saved', path: r.run.path });
      setStatus(`Saved to <span class="mono">${esc(r.run.path)}</span>`);
      return;
    }
    await sleep(600);
  }
}

async function playReplay(path) {
  const token = ++liveState.token;
  const run = await api.get(`/api/run?path=${encodeURIComponent(path)}`);
  const ctx = { kind: 'saved', path };
  $('#timeline').innerHTML = ''; $('#results').innerHTML = `<h3>${icon('gauge')} Result</h3><p class="muted">Replaying…</p>`;
  let prev = 0;
  for (const e of run.events) {
    if (token !== liveState.token) return;
    if (liveState.speed) await sleep(Math.min(2500, Math.max(120, ((e.t - prev) * 1000) / liveState.speed)));
    prev = e.t;
    appendEvent(e, ctx);
    setStatus(`<span class="spin"></span> Replaying ${esc(run.assessment.run.run_id)} · t = ${e.t.toFixed(1)} s`);
  }
  setStatus(`Replayed <span class="mono">${esc(path)}</span>`);
  renderResults(run, ctx);
}

function appendEvent(e, ctx) {
  const tl = $('#timeline');
  if (!tl) return;
  const node = document.createElement('div');
  const t = `<span class="t">${(e.t ?? 0).toFixed(1)} s</span>`;
  switch (e.event) {
    case 'intake':
      node.className = 'ev';
      node.innerHTML = `<div class="ev-head">${icon('terminal')}<b>Intake</b>${t}</div><div class="ev-body">${esc(e.cve_id)} · <span class="mono">${esc(e.snapshot_path)}</span> · sha256 ${esc((e.snapshot_sha256 || '').slice(0, 12))}…${e.variant_change ? `<br><span style="color:var(--medium)">Variant: ${esc(e.variant_change)}</span>` : ''}</div>`;
      break;
    case 'faults':
      if (!e.faults?.length) return;
      node.className = 'ev fault';
      node.innerHTML = `<div class="ev-head">${icon('alert')}<b>Controlled failure armed</b>${t}</div><div class="ev-body">${esc(e.faults.join(', '))}</div>`;
      break;
    case 'model_response': {
      node.className = 'ev model';
      const calls = (e.tool_calls || []).map((c) => `<span class="call">${esc(callText(c.name, c.arguments))}</span>`).join('');
      node.innerHTML = `<div class="ev-head">${icon('bot')}<b>Model · turn ${e.turn}</b>${calls ? '<span class="muted">decides to call</span>' : ''}${t}</div>
        <div class="ev-body">${calls || `<i>${esc(e.content || '(text only)')}</i>`}</div>
        ${e.thinking ? `<details><summary>Show the model's reasoning</summary><div class="think">${esc(e.thinking)}</div></details>` : ''}`;
      break; }
    case 'fault_injected':
      node.className = 'ev fault';
      node.innerHTML = `<div class="ev-head">${icon('alert')}<b>Fault injected</b>${t}</div><div class="ev-body">The model's call <span class="call">${esc(e.replaced_call?.function?.name)}</span> was replaced by <span class="call">scan_network {"target": "W15"}</span></div>`;
      break;
    case 'tool_call': {
      const st = e.rejected ? 'rejected' : (e.status === 'live' || e.status === 'cached') ? e.status : e.source_mode || e.status;
      node.className = 'ev tool';
      node.innerHTML = `<div class="ev-head">${icon('wrench')}<span class="chip mono">${esc(e.ref)}</span><b class="mono" style="font-size:12px">${esc(e.tool)}</b>${mode(st)}${t}</div>
        <div class="ev-body"><span class="call">${esc(callText(e.tool, e.args))}</span><br>${esc(e.preview || e.error || '')}</div>`;
      node.title = 'Click to see the full tool result';
      node.onclick = () => showTool(ctx, e.ref);
      break; }
    case 'validation':
      node.className = `ev ${e.passed ? 'val-pass' : 'val-fail'}`;
      node.innerHTML = `<div class="ev-head">${icon(e.passed ? 'check' : 'alert')}<b>Validator · attempt ${e.attempt}</b><span class="chip">${e.findings} findings</span>${e.passed ? '<span class="mode mode-ok">passed</span>' : `<span class="mode mode-cached">${e.errors.length} problems sent back</span>`}${t}</div>
        ${e.passed ? '<div class="ev-body">Every fact matches the tool results; coverage complete.</div>' : `<ul class="ev-body">${e.errors.slice(0, 5).map((x) => `<li>${esc(x)}</li>`).join('')}${e.errors.length > 5 ? `<li>…and ${e.errors.length - 5} more</li>` : ''}</ul>`}`;
      break;
    case 'findings_accepted': return;
    case 'policy': {
      let group = tl.lastElementChild;
      if (!group || !group.classList.contains('policy-group')) {
        group = document.createElement('div');
        group.className = 'ev policy policy-group';
        group.innerHTML = `<div class="ev-head">${icon('scale')}<b>Policy code rates each machine</b><span class="chip pcount">0</span>${t}</div><div class="prows"></div>`;
        tl.appendChild(group);
      }
      const row = document.createElement('div');
      row.className = 'prow';
      row.title = e.rule;
      row.innerHTML = `<span>${esc(e.asset)}</span>${dec(e.decision)}<span class="mono muted">${esc(e.rule)}</span>`;
      $('.prows', group).appendChild(row);
      $('.pcount', group).textContent = `${$('.prows', group).children.length} machines`;
      tl.scrollTop = tl.scrollHeight;
      return; }
    case 'action_drafting':
      node.className = 'ev model';
      node.innerHTML = `<div class="ev-head">${icon('sparkles')}<b>Model drafts recommended actions</b>${t}</div><div class="ev-body">${e.error ? 'Model failed, template text used' : `${(e.drafted || []).length} non-Low machines`}</div>`;
      break;
    case 'stop':
      node.className = 'ev stop';
      node.innerHTML = `<div class="ev-head">${icon('x')}<b>Stopped: ${esc(e.status)}</b>${t}</div><div class="ev-body">${esc(e.reason)}</div>`;
      break;
    default: return;
  }
  tl.appendChild(node);
  tl.scrollTop = tl.scrollHeight;
}

async function showTool(ctx, ref) {
  const r = ctx.kind === 'live' ? await api.get(`/api/live/tool?id=${ctx.id}&ref=${ref}`) : await api.get(`/api/run/tool?path=${encodeURIComponent(ctx.path)}&ref=${ref}`);
  modal(`<span class="mono">${esc(ref)} · ${esc(r.tool)}</span>`, `<div class="row"><span class="call">${esc(callText(r.tool, r.args))}</span>${mode(r.result.status)}${mode(r.result.source_mode)}<span class="muted mono" style="font-size:12px">${esc(r.result.source || '')} · ${esc(r.result.retrieved_at || '')}</span></div>
    <pre class="json">${esc(JSON.stringify(r.result, null, 2))}</pre>`);
}

function renderResults(run, ctx) {
  const a = run.assessment, o = a.overall;
  const box = $('#results');
  if (!box) return;
  const nonLow = a.assessments.filter((x) => x.decision !== 'Low');
  box.innerHTML = `<h3>${icon('gauge')} Result</h3>
    <div class="row"><span class="muted">Overall</span>${dec(o.decision)}<span class="chip">${esc(a.run.status)}</span></div>
    <p class="muted" style="font-size:13px">${esc(o.note)}</p>
    <div class="row">${Object.entries(o.counts || {}).map(([d, c]) => `<span class="chip">${c} × ${dec(d)}</span>`).join('')}</div>
    ${bottomLine(a)}
    <div class="res-assets">${a.assessments.map((x, i) => x.decision === 'Low' ? '' : `<div class="res-asset" data-i="${i}"><span><b class="mono">${esc(x.asset.asset_id)}</b> ${esc(x.asset.instance)}</span>${dec(x.decision)}</div>`).join('')}
      ${a.assessments.length > nonLow.length ? `<details><summary>${a.assessments.length - nonLow.length} machines rated Low</summary>${a.assessments.map((x, i) => x.decision !== 'Low' ? '' : `<div class="res-asset" data-i="${i}" style="margin-top:6px"><span><b class="mono">${esc(x.asset.asset_id)}</b> ${esc(x.asset.instance)}</span>${dec('Low')}</div>`).join('')}</details>` : ''}</div>
    <div class="row" style="margin-top:12px"><button class="btn ghost small" id="open-report">${icon('book')} Full report</button><span class="muted mono" style="font-size:11px">${esc(run.path)}</span></div>`;
  $$('.res-asset', box).forEach((n) => (n.onclick = () => assetResult(a.assessments[+n.dataset.i], ctx)));
  $('#open-report').onclick = () => modal('report.md', `<div class="md">${md(run.report)}</div>`);
}

function bottomLine(a) {
  if (!a.assessments.length) return '';
  const names = (d) => a.assessments.filter((x) => x.decision === d).map((x) => `${x.asset.asset_id} ${x.asset.instance}`);
  const row = (d, label, text) => `<div class="bl-row" style="border-color:${DEC_COLOR[d]}"><b style="color:${DEC_COLOR[d]}">${label}</b><br>${esc(text)}</div>`;
  const low = names('Low').length;
  return `<div class="bottom-line"><b>Bottom line</b>
    ${names('High').length ? row('High', 'Patch now', names('High').join(', ')) : ''}
    ${names('Medium').length ? row('Medium', 'Plan the fix', names('Medium').join(', ')) : ''}
    ${names('INSUFFICIENT_EVIDENCE').length ? row('INSUFFICIENT_EVIDENCE', 'A person must check first', names('INSUFFICIENT_EVIDENCE').join(', ')) : ''}
    ${low ? row('Low', 'Not at risk from this bug', `${low} machines (already patched or not affected)`) : ''}</div>`;
}

function assetResult(x, ctx) {
  const r = x.rationale, f = r.applicability.facts;
  modal(`${esc(x.asset.asset_id)} ${esc(x.asset.instance)} ${dec(x.decision)}`, `
    <div class="grid g2">
      <div class="card tight"><h4>Applicability · ${esc(r.applicability.level)}</h4><p style="font-size:14px">${esc(r.applicability.reason)}</p>
        <div class="kv"><div>OS</div><div>${esc(f.os)}</div><div>Build</div><div class="mono">${esc(f.os_build ?? 'unknown')}</div><div>Fixed build</div><div class="mono">${esc(f.fixed_build ?? '—')}</div><div>Low-priv logon</div><div>${esc(f.low_priv_local_access)}</div></div>
        ${f.conflicts?.length ? `<div class="callout bad" style="font-size:13px">${f.conflicts.map((c) => esc(c.detail)).join('<br>')}</div>` : ''}</div>
      <div class="card tight"><h4>Impact · ${esc(r.impact.priority ?? '?')}</h4><p style="font-size:14px">${esc(r.impact.reason)}</p>
        <div class="kv"><div>Data</div><div>${esc(r.impact.data_classification)} / ${esc(r.impact.data_protection)}</div><div>Exposure</div><div>${esc(r.impact.exposure)}</div><div>Override</div><div>${esc(r.impact.priority_override ?? '—')}</div><div>Service</div><div>${esc(r.impact.business_service ?? '—')}</div></div></div>
    </div>
    <div class="card tight" style="margin-top:12px"><h4>Policy rule</h4><div class="mono">${esc(r.policy_rule)}</div><div class="muted" style="font-size:13px;margin-top:4px">Confidence: <b>${esc(x.confidence.level ?? 'n/a')}</b> · ${esc(x.confidence.reason)}</div></div>
    <div class="card tight" style="margin-top:12px"><h4>Evidence (click a row for the raw tool result)</h4><table><thead><tr><th>Ref</th><th>Source</th><th>Mode</th><th>Fact</th></tr></thead><tbody>
      ${x.evidence.map((e) => `<tr class="click" data-ref="${esc(e.ref)}"><td class="mono">${esc(e.ref)} ${esc(e.evidence_id || e.source_id || '')}</td><td class="mono" style="font-size:12px">${esc(e.source)}</td><td>${mode(e.source_mode)}</td><td style="font-size:13px">${esc(e.fact)}</td></tr>`).join('')}</tbody></table></div>
    <div class="grid g2" style="margin-top:12px">
      <div class="card tight"><h4>Recommended action <span class="chip">${esc(x.action?.drafted_by)}</span></h4><p style="font-size:14px">${esc(x.action?.recommended_action)}</p><h4>Would change the decision</h4><p style="font-size:14px">${esc(x.action?.would_change_decision)}</p></div>
      <div class="card tight"><h4>Assumptions</h4>${x.assumptions.length ? `<ul style="font-size:13px">${x.assumptions.map((s) => `<li>${esc(s)}</li>`).join('')}</ul>` : '<p class="muted">None</p>'}
        <h4>Unknowns</h4><p style="font-size:13px">Decisive: ${esc(x.unknowns.decisive.join(', ') || 'none')}<br><span class="muted">Non-decisive: ${esc(x.unknowns.non_decisive.join(', ') || 'none')}</span></p></div>
    </div>`);
  $$('#modal tr[data-ref]').forEach((row) => (row.onclick = () => showTool(ctx, row.dataset.ref)));
}

// ---------- 09 validator ----------
async function renderValidator(el) {
  const base = await once('baseline', () => api.get('/api/run?path=baseline/main_run'));
  const vals = base.events.filter((e) => e.event === 'validation');
  const checks = [
    ['Did this machine really come from a tool?', 'Every finding must point to a record a search actually returned.', 'An invented machine'],
    ['Does every fact match the tool data?', 'Build, logon access, affected product and fixed build are compared one by one with the stored record and the NVD result.', 'Typos, misreads, "fixed build from memory"'],
    ['Is the comparison right?', 'Code compares the builds itself, number by number (9339 < 9512).', 'Wrong math'],
    ['Was the supporting evidence read?', 'If a machine cites S03/S07/S08, the AI must have fetched them.', 'Skipping the cross-check that finds contradictions'],
    ['Did it look everywhere?', 'Every affected product in NVD must have been searched, and every machine running one must be in the list.', 'Forgotten machines'],
    ['Do the sources contradict each other?', 'Code scans the fetched evidence for a different build for the same machine.', 'Contradictions the AI missed'],
  ];
  el.innerHTML = `
  <p class="lead">The AI hands in its facts with <span class="mono">submit_findings</span>. Code does not trust them: each one is checked against what the tools actually returned in this run.</p>
  <div class="grid" style="grid-template-columns: minmax(0,1fr) minmax(0,1fr)">
    <div class="grid" style="align-content:start">${checks.map((c, i) => `<div class="card tight check-card"><div class="num">${i + 1}</div><div><b>${c[0]}</b><div class="muted" style="font-size:13px">${c[1]}</div><div style="font-size:12px;margin-top:2px"><span class="chip">catches: ${c[2]}</span></div></div></div>`).join('')}</div>
    <div class="grid" style="align-content:start">
      <div class="card"><h3>${icon('alert')} Caught in the baseline run</h3>
        ${vals.map((v) => `<div class="ev ${v.passed ? 'val-pass' : 'val-fail'}" style="margin-top:8px"><div class="ev-head"><b>Attempt ${v.attempt}</b><span class="chip">${v.findings} findings</span>${v.passed ? '<span class="mode mode-ok">passed</span>' : `<span class="mode mode-cached">${v.errors.length} problems</span>`}<span class="t">${v.t.toFixed(1)} s</span></div>
          ${v.passed ? '<div class="ev-body">All facts verified, every affected product checked.</div>' : `<ul class="ev-body">${v.errors.slice(0, 6).map((x) => `<li>${esc(x)}</li>`).join('')}${v.errors.length > 6 ? `<li>…and ${v.errors.length - 6} more</li>` : ''}</ul>`}</div>`).join('')}
        <div class="callout" style="font-size:14px">In <b>7 of 7</b> completed live check runs, the AI's first submission was incomplete. Each was corrected after feedback; none reached a rating with unverified facts.</div></div>
      <div class="card"><h3>Then what?</h3><ul style="font-size:14px;padding-left:18px;margin:0" class="muted">
        <li>Errors go back to the AI as the tool's reply; it gets 2 chances to fix them.</li>
        <li>A machine still wrong after that → <b>INSUFFICIENT_EVIDENCE</b>.</li>
        <li>Machines still missing → the overall result can never be "Low".</li>
        <li>The policy rates from the <b>tool data</b>, never the AI's numbers.</li></ul>
        <p class="muted" style="font-size:13px;margin-bottom:0">Pattern: evaluator–optimizer ("AI proposes, code verifies"); guards against OWASP LLM "improper output handling".</p></div>
    </div>
  </div>`;
}

// ---------- 10 tests ----------
async function renderTests(el) {
  const c = await api.get('/api/checks');
  const rows = c.rows;
  const changes = { '0': 'Nothing (base snapshot)', '0s': 'All machines, base snapshot', '1': 'W15 patched to the fixed build', '2': 'W15 holds no PII, internal only', '3a': 'W15 build removed (null)', '3b': 'S08 says September, record says July', '4a': 'NVD unreachable, cached copy exists', '4b': 'NVD unreachable, no cached copy', '4c': "Model's first call replaced by a fake tool" };
  const cell = (r, side) => {
    const v = side === 'exp' ? r.expected : r.actual;
    if (r.kind === 'policy') return typeof v === 'object' ? `${dec(v.decision)}<div class="muted" style="font-size:12px">${esc(v.applicability)} · ${esc(v.priority)}</div>` : esc(v);
    if (r.kind === 'scan') return side === 'exp' ? Object.entries(v.non_low).map(([k, d]) => `<div style="font-size:12px">${esc(k)} ${dec(d)}</div>`).join('') + '<div class="muted" style="font-size:12px">rest Low</div>'
      : Object.entries(v).map(([k, d]) => k === 'Low' ? `<div class="muted" style="font-size:12px">${d} × Low</div>` : `<div style="font-size:12px">${esc(k)} ${dec(d)}</div>`).join('');
    if (side === 'exp') return `<div style="font-size:12px">${esc(['run_status', 'decision', 'overall', 'nvd_status', 'confidence_at_most', 'min_rejected'].filter((k) => v[k] !== undefined).map((k) => `${k}=${v[k]}`).join(' · '))}</div>`;
    return `<div style="font-size:12px">${esc(['run_status', 'decision', 'overall', 'confidence', 'rejected_tool_calls'].filter((k) => v[k] !== undefined && v[k] !== null).map((k) => `${k}=${v[k]}`).join(' · '))}</div>${v.lookups ? `<div class="muted" style="font-size:11px">${esc(v.lookups.map((l) => l.join(':')).join(', '))}</div>` : ''}`;
  };
  el.innerHTML = `
  <p class="lead">Expected results were written from the policy <b>before any run</b>. Each check changes one thing. Source: <span class="mono">${esc(c.source)}</span></p>
  <div class="card"><table><thead><tr><th>#</th><th>Check</th><th>What changes</th><th>Expected</th><th>Actual (live model)</th><th>Result</th><th></th></tr></thead><tbody>
    ${rows.map((r) => `<tr><td class="mono">${esc(r.id)}</td><td><b>${esc(r.name)}</b></td><td class="muted" style="font-size:13px">${esc(changes[r.id] || '')}</td><td>${cell(r, 'exp')}</td><td>${cell(r, 'act')}</td>
      <td>${r.pass ? '<span class="mode mode-ok">PASS</span>' : `<span class="mode mode-error">FAIL</span><div style="font-size:12px">${esc(r.problems.join('; '))}</div>`}</td>
      <td><button class="btn ghost small" data-run="${esc(r.run_dir)}">Replay</button></td></tr>`).join('')}</tbody></table></div>
  <div class="grid g2" style="margin-top:16px">
    <div class="card"><h3>${icon('flask')} The three required policy checks</h3><ul class="muted" style="font-size:14px;padding-left:18px;margin:0">
      <li><b>Applicability change</b> (1): only the build changes → only applicability moves → Low.</li>
      <li><b>Impact change</b> (2): only data and exposure change → only priority moves → Medium.</li>
      <li><b>Missing / conflicting evidence</b> (3a, 3b): the agent refuses to guess → INSUFFICIENT_EVIDENCE.</li></ul>
      <button class="btn ghost small" style="margin-top:10px" onclick="openDoc('test_results','Test results')">${icon('book')} Full test results</button></div>
    <div class="card"><h3>${icon('terminal')} Offline test suite</h3><p class="muted" style="font-size:14px">pytest with a scripted model and replayed NVD/KEV, so it needs no internet: policy matches the reference on every machine, every failure path, the validator, blinding.</p>
      <button class="btn small" id="pytest">${icon('play')} Run python -m pytest</button><div id="pytest-out"></div></div>
  </div>`;
  $$('button[data-run]', el).forEach((b) => (b.onclick = () => { liveState.tab = 'replay'; liveState.replayPath = b.dataset.run; liveState.autoplay = b.dataset.run; go(SCENES.findIndex((s) => s.id === 'live')); }));
  $('#pytest').onclick = async () => {
    $('#pytest').disabled = true; $('#pytest-out').innerHTML = '<div class="status-line"><span class="spin"></span> Running…</div>';
    const r = await api.post('/api/pytest');
    $('#pytest').disabled = false;
    $('#pytest-out').innerHTML = `<div class="console" style="margin-top:10px">${esc(r.output.trim())}</div>`;
  };
}

// ---------- 11 review ----------
const SECTION_HELP = {
  A: ['Main decision: W15', 'Is every fact behind "W15 = High" true in the original sources?'],
  B: ['Other machines that are not Low', 'Are the Medium and "insufficient evidence" results right?'],
  C: ['How the agent worked', 'Did the AI really choose its own lookups, use the real sources, and stay blind to the test name?'],
};
const fmtVal = (v) => typeof v === 'string' ? `<div style="font-size:14px">${esc(v)}</div>` : `<pre class="json" style="max-height:260px">${esc(JSON.stringify(v, null, 2))}</pre>`;
async function renderReview(el) {
  const st = await api.get('/api/review');
  const done = st.items.filter((i) => /^(✅|⚠️)/.test(i.review)).length;
  const today = new Date().toISOString().slice(0, 10);
  const groups = ['A', 'B', 'C'].map((g) => [g, st.items.filter((i) => i.id[0] === g)]);
  el.innerHTML = `
  <div class="grid g2">
    <div class="card"><h3>${icon('usercheck')} What is this?</h3>
      <p class="muted" style="font-size:14px;margin:0">The assignment requires that <b>a group member checks the agent's answer against the original sources</b>, like a teacher checking homework against the textbook instead of the student's notes.
      Each card is one claim the agent made. Open its source, compare, then mark it <b>✓ correct</b> or <b>⚠ problem</b>. Your marks are saved into <span class="mono">${esc(st.path)}</span>.</p></div>
    <div class="card"><h3>${icon('check')} Progress</h3>
      <div class="row"><div class="big-num">${done}<span class="muted" style="font-size:20px"> / ${st.items.length}</span></div><div style="flex:1"><div style="height:10px;border-radius:6px;background:var(--line);overflow:hidden"><div style="height:100%;width:${(100 * done) / st.items.length}%;background:var(--accent)"></div></div>
      <div class="muted" style="font-size:12px;margin-top:6px">claims reviewed · the "Pre-check" line on each card is a scripted check done earlier; it does not replace yours</div></div></div></div>
  </div>
  ${groups.map(([g, items]) => `
    <h3 style="margin:22px 0 4px">${g} · ${esc(SECTION_HELP[g][0])}</h3><p class="muted" style="margin:0 0 10px;font-size:14px">${esc(SECTION_HELP[g][1])}</p>
    <div class="grid" style="gap:10px">${items.map((i) => {
      const verdict = i.review.startsWith('✅') ? 'ok' : i.review.startsWith('⚠') ? 'issue' : '';
      const note = i.review.replace(/^(✅|⚠️|☐)\s*/, '');
      return `<div class="card tight review-card ${verdict}" data-id="${i.id}">
        <div class="row"><span class="chip mono">${i.id}</span><b style="flex:1">${esc(i.claim.replace(/`/g, ''))}</b>
          ${verdict === 'ok' ? '<span class="mode mode-ok">✓ correct</span>' : verdict === 'issue' ? '<span class="mode mode-cached">⚠ problem</span>' : '<span class="mode mode-not_found">not reviewed</span>'}</div>
        <div class="muted" style="font-size:12px;margin:4px 0 0 2px">Pre-check: ${esc(i.precheck.replace(/[`*]/g, ''))}</div>
        <div class="row" style="margin-top:8px"><button class="btn ghost small src-btn">Show me the source</button>
          <button class="btn small ok-btn" style="background:var(--low)">✓ Correct</button><button class="btn small issue-btn" style="background:var(--medium)">⚠ Problem</button>
          <input class="note" placeholder="note: saves automatically once ✓ or ⚠ is chosen" value="${esc(note)}" style="flex:1;min-width:220px">
          ${verdict ? '<button class="btn ghost small clear-btn">Undo</button>' : ''}</div>
        <div class="src-box"></div></div>`; }).join('')}</div>`).join('')}
  <h3 style="margin:22px 0 8px">Sign-off</h3>
  <div class="card"><table><thead><tr><th>Reviewer</th><th>Date</th><th>Result</th><th></th></tr></thead><tbody>
    ${st.signoff.map((r, k) => `<tr><td><b>${esc(r.name)}</b></td><td><input type="date" id="so-date-${k}" value="${esc(r.date || today)}"></td>
      <td><input id="so-res-${k}" style="width:100%" placeholder="e.g. Agree: W15 High is supported; A11 step 3 rejected" value="${esc(r.result)}"></td>
      <td><button class="btn small" data-so="${k}">Save</button></td></tr>`).join('')}</tbody></table>
    <p class="muted" style="font-size:12px;margin-bottom:0">${done < st.items.length ? `Review all ${st.items.length} claims before signing.` : 'All claims reviewed. Sign off when you agree.'}</p></div>
  <div class="card" style="margin-top:16px"><h3>${icon('database')} The baseline (nothing to do here)</h3>
    <p class="muted" style="font-size:14px">A frozen copy of the final run (inputs, settings, code version and outputs), kept as the "before" photo for Assignment 4. The assignment asks us to save it.</p>
    <button class="btn ghost small" onclick="openDoc('baseline','Baseline')">${icon('book')} What's inside the baseline</button></div>`;

  const save = async (id, verdict, note) => { await api.post('/api/review/mark', { id, verdict, note }); const y = $('#scene').scrollTop; await renderReview(el); $('#scene').scrollTop = y; };
  $$('.review-card', el).forEach((c) => {
    const id = c.dataset.id, note = () => $('.note', c).value;
    $('.src-btn', c).onclick = async () => {
      const box = $('.src-box', c);
      if (box.innerHTML) { box.innerHTML = ''; return; }
      const r = await api.get(`/api/review/source?id=${id}`);
      box.innerHTML = `<div class="grid" style="gap:8px;margin-top:10px">${r.sources.map((x) => `<div class="card tight" style="background:var(--bg-2)"><div class="row"><b style="font-size:13px">${esc(x.label)}</b><span class="spacer"></span><span class="mono muted" style="font-size:11px">${esc(x.source)}</span></div>${fmtVal(x.value)}</div>`).join('')}</div>`;
    };
    $('.ok-btn', c).onclick = () => save(id, 'ok', note());
    $('.issue-btn', c).onclick = () => save(id, 'issue', note());
    // Notes save on their own (after a short pause in typing), keeping the current mark.
    let t;
    $('.note', c).oninput = () => {
      clearTimeout(t);
      t = setTimeout(async () => {
        const verdict = c.classList.contains('ok') ? 'ok' : c.classList.contains('issue') ? 'issue' : '';
        if (!verdict) return;  // a note needs a mark; it is saved when ✓ or ⚠ is clicked
        await api.post('/api/review/mark', { id, verdict, note: note() });
        $('.note', c).style.borderColor = 'var(--low)';
      }, 600);
    };
    $('.clear-btn', c) && ($('.clear-btn', c).onclick = () => save(id, '', ''));
  });
  const saveSignoff = async (k) => {
    await api.post('/api/review/signoff', { name: st.signoff[k].name, date: $(`#so-date-${k}`).value, result: $(`#so-res-${k}`).value });
    $(`button[data-so="${k}"]`).textContent = 'Saved ✓';
  };
  $$('button[data-so]', el).forEach((b) => {
    const k = b.dataset.so;
    let t;
    b.onclick = () => saveSignoff(k);
    // Sign-off fields save on their own as you type or change the date.
    $(`#so-res-${k}`).oninput = () => { $(`button[data-so="${k}"]`).textContent = 'Saving…'; clearTimeout(t); t = setTimeout(() => saveSignoff(k), 600); };
    $(`#so-date-${k}`).onchange = () => saveSignoff(k);
  });
}

// ---------- 12 limits ----------
async function renderLimits(el) {
  const items = [
    ['building', 'Simulated environment', 'Builds, data types, access paths and assumptions A1–A15 are additions to a fictional company. Real use needs a live inventory and patch data; that is why confidence is Medium.'],
    ['bot', 'Non-deterministic model', 'Tool order and the number of correction rounds vary between runs. The decisions did not vary, because code computes them from validated data. One model tested.'],
    ['database', 'Coverage depends on naming', 'Searches are plain text; a product named differently in the inventory could be missed.'],
    ['alert', 'Narrow conflict detection', 'Code catches a different build stated for the same machine; other disagreements depend on the AI reporting them.'],
    ['check', 'Validator partly redundant here', 'On this clean inventory, code can recompute most facts itself. Its essential job is completeness: catching forgotten machines.'],
    ['siren', 'Sources', 'CVSS v3.1 only (Microsoft\'s score), no EPSS, the Microsoft advisory is only saved by hand (the agent cannot read that page), a cached KEV feed can be stale.'],
    ['gauge', 'Free-tier model service', 'Ollama Cloud returned intermittent HTTP 500s; we retry with backoff and stop cleanly if it stays down.'],
    ['usercheck', 'Recommends only', 'The agent never patches or changes access. People act on its report after review.'],
    ['bug', 'Written for this kind of bug', 'The "can it work here" check assumes the attacker needs a normal user account on the machine. A bug attackable straight from the internet needs a different check (e.g. internet exposure).'],
  ];
  el.innerHTML = `
  <div class="grid g3">${items.map((x) => `<div class="card"><h3>${icon(x[0])} ${esc(x[1])}</h3><p class="muted" style="font-size:14px">${esc(x[2])}</p></div>`).join('')}</div>
  <div class="card" style="margin-top:16px"><h3>${icon('sparkles')} Next (Assignment 4)</h3>
    <p class="muted" style="font-size:14px;margin:0">Tracing every model and tool call, evaluating over more CVEs and environments, adding EPSS, and comparing against the frozen baseline in <span class="mono">baseline/</span>.</p></div>
  <div class="hero" style="margin-top:16px;text-align:center"><h2 style="margin:0">Thank you</h2><p class="muted" style="margin:6px 0 0">Paul Prommark · Supawich Puengdang · github.com/Puminunp/security-triage-agent</p></div>`;
}

// ---------- boot ----------
buildNav();
window.addEventListener('hashchange', () => { const i = SCENES.findIndex((x) => x.id === location.hash.slice(1)); if (i >= 0 && i !== current) go(i); });
const start = SCENES.findIndex((s) => s.id === location.hash.slice(1));
go(start >= 0 ? start : 0);
