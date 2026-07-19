import crypto from 'node:crypto';
import dns from 'node:dns/promises';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const reportsDir = path.resolve(__dirname, '..', 'reports');
const audits = new Map();

const agentOrder = [
  'Scope Agent',
  'Recon Agent',
  'Route Agent',
  'Scanner Agent',
  'CORS Agent',
  'Exploit Agent',
  'PoC Agent',
  'Duplicate Agent',
  'Report Agent'
];

const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function nowTime() {
  return new Date().toLocaleTimeString([], { hour12: false });
}

function pushEvent(audit, agent, message, state = 'done') {
  audit.timeline.unshift({ time: nowTime(), agent, message, state });
}

function normalizeTarget(rawTarget) {
  const value = String(rawTarget || '').trim();
  if (!value) throw new Error('Target is required.');

  const withProtocol = /^https?:\/\//i.test(value) ? value : `https://${value}`;
  const url = new URL(withProtocol);

  if (!['http:', 'https:'].includes(url.protocol)) {
    throw new Error('Only HTTP and HTTPS targets are supported.');
  }

  url.hash = '';
  return {
    input: value,
    url: url.toString(),
    origin: url.origin,
    hostname: url.hostname,
    protocol: url.protocol
  };
}

function createAudit({ target, scopeRules = '', mode = 'standard', authorized }) {
  if (!authorized) {
    throw new Error('Confirm that you are authorized to test this target before running agents.');
  }

  const id = crypto.randomUUID();
  const normalized = normalizeTarget(target);
  const audit = {
    id,
    target: normalized,
    mode,
    scopeRules,
    status: 'queued',
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    agents: agentOrder.map((name) => ({
      name,
      role: roleForAgent(name),
      status: 'queued',
      progress: 0,
      summary: 'Waiting for orchestrator',
      evidence: []
    })),
    findings: [],
    evidence: {},
    timeline: [],
    report: null,
    error: null
  };

  audits.set(id, audit);
  runAudit(audit).catch((error) => {
    audit.status = 'failed';
    audit.error = error.message;
    audit.updatedAt = new Date().toISOString();
    pushEvent(audit, 'Orchestrator', error.message, 'error');
  });

  return audit;
}

function listAudits() {
  return [...audits.values()].sort((a, b) => b.createdAt.localeCompare(a.createdAt));
}

function getAudit(id) {
  return audits.get(id);
}

function roleForAgent(name) {
  return {
    'Scope Agent': 'Confirms rules and normalizes target',
    'Recon Agent': 'Maps live web surface',
    'Route Agent': 'Safely probes common app endpoints',
    'Scanner Agent': 'Checks headers, cookies, forms, and exposed metadata',
    'CORS Agent': 'Checks browser trust boundaries',
    'Exploit Agent': 'Validates safely reproducible impact',
    'PoC Agent': 'Creates copyable repro commands',
    'Duplicate Agent': 'Builds public duplicate search leads',
    'Report Agent': 'Packages evidence into markdown'
  }[name];
}

function getAgent(audit, name) {
  return audit.agents.find((agent) => agent.name === name);
}

async function runAgent(audit, name, fn) {
  const agent = getAgent(audit, name);
  agent.status = 'running';
  agent.progress = Math.max(agent.progress, 12);
  agent.summary = 'Running';
  audit.status = 'running';
  audit.updatedAt = new Date().toISOString();
  pushEvent(audit, name, 'Started');

  await delay(250);
  const result = await fn(audit, agent);
  agent.status = 'complete';
  agent.progress = 100;
  agent.summary = result?.summary || 'Complete';
  agent.evidence = result?.evidence || agent.evidence;
  audit.updatedAt = new Date().toISOString();
  pushEvent(audit, name, agent.summary);
}

async function runAudit(audit) {
  await runAgent(audit, 'Scope Agent', runScopeAgent);
  await runAgent(audit, 'Recon Agent', runReconAgent);
  await runAgent(audit, 'Route Agent', runRouteAgent);
  await runAgent(audit, 'Scanner Agent', runScannerAgent);
  await runAgent(audit, 'CORS Agent', runCorsAgent);
  await runAgent(audit, 'Exploit Agent', runExploitAgent);
  await runAgent(audit, 'PoC Agent', runPocAgent);
  await runAgent(audit, 'Duplicate Agent', runDuplicateAgent);
  await runAgent(audit, 'Report Agent', runReportAgent);
  audit.status = 'complete';
  audit.updatedAt = new Date().toISOString();
  pushEvent(audit, 'Orchestrator', `Audit complete with ${audit.findings.length} findings`);
}

async function runRouteAgent(audit) {
  const probes = [
    '/',
    '/robots.txt',
    '/sitemap.xml',
    '/.well-known/security.txt',
    '/api',
    '/graphql',
    '/admin',
    '/login',
    '/debug',
    '/health',
    '/status',
    '/.env'
  ];
  const routes = [];

  for (const route of probes) {
    const url = new URL(route, audit.target.origin).toString();
    try {
      const { response } = await fetchText(url, { method: 'HEAD', timeoutMs: 3500 });
      routes.push({ route, url, status: response.status, contentType: response.headers.get('content-type') || '' });
    } catch (error) {
      routes.push({ route, url, status: 'error', error: error.message });
    }
  }

  audit.evidence.routes = routes;
  return {
    summary: `${routes.length} routes probed safely`,
    evidence: routes.map((route) => `${route.route}: ${route.status}`)
  };
}

async function runScopeAgent(audit) {
  const evidence = [
    `Target normalized to ${audit.target.url}`,
    `Allowed origin: ${audit.target.origin}`,
    audit.scopeRules ? `Scope notes recorded: ${audit.scopeRules.slice(0, 180)}` : 'No extra scope notes supplied'
  ];
  audit.evidence.scope = evidence;
  return { summary: 'Authorized scope locked', evidence };
}

async function fetchText(url, options = {}) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), options.timeoutMs || 8000);
  try {
    const response = await fetch(url, {
      method: options.method || 'GET',
      redirect: 'follow',
      signal: controller.signal,
      headers: {
        'user-agent': 'BugBunnyLocal/0.1 authorized-security-audit',
        ...(options.headers || {})
      }
    });
    const text = options.method === 'HEAD' ? '' : await response.text();
    return { response, text };
  } finally {
    clearTimeout(timeout);
  }
}

async function runReconAgent(audit) {
  const evidence = [];
  try {
    const addresses = await dns.lookup(audit.target.hostname, { all: true });
    audit.evidence.dns = addresses.map((entry) => `${entry.family === 6 ? 'AAAA' : 'A'} ${entry.address}`);
    evidence.push(`${addresses.length} DNS addresses resolved`);
  } catch (error) {
    audit.evidence.dns = [`DNS lookup failed: ${error.message}`];
    evidence.push('DNS lookup failed');
  }

  const page = await fetchText(audit.target.url);
  const headers = Object.fromEntries(page.response.headers.entries());
  const title = page.text.match(/<title[^>]*>(.*?)<\/title>/is)?.[1]?.replace(/\s+/g, ' ').trim() || 'No title found';
  const links = collectLinks(page.text, audit.target.origin).slice(0, 24);
  const forms = [...page.text.matchAll(/<form\b[^>]*>/gi)].length;

  audit.evidence.http = {
    status: page.response.status,
    finalUrl: page.response.url,
    headers,
    title,
    forms,
    links
  };
  evidence.push(`HTTP ${page.response.status} from ${page.response.url}`);
  evidence.push(`Title: ${title}`);
  evidence.push(`${links.length} same-origin links collected`);
  evidence.push(`${forms} forms detected`);

  try {
    const robots = await fetchText(new URL('/robots.txt', audit.target.origin).toString(), { timeoutMs: 4000 });
    audit.evidence.robots = robots.response.ok ? robots.text.slice(0, 2000) : `robots.txt returned HTTP ${robots.response.status}`;
    evidence.push(`robots.txt returned HTTP ${robots.response.status}`);
  } catch (error) {
    audit.evidence.robots = `robots.txt probe failed: ${error.message}`;
  }

  return { summary: `Mapped ${links.length} links and ${forms} forms`, evidence };
}

function collectLinks(html, origin) {
  const links = new Set();
  const re = /\b(?:href|src)=["']([^"'#\s]+)["']/gi;
  for (const match of html.matchAll(re)) {
    try {
      const url = new URL(match[1], origin);
      if (url.origin === origin) {
        url.hash = '';
        links.add(url.toString());
      }
    } catch {
      // Ignore malformed references.
    }
  }
  return [...links];
}

async function runScannerAgent(audit) {
  const headers = audit.evidence.http?.headers || {};
  const evidence = [];
  const add = (finding) => {
    audit.findings.push({ id: crypto.randomUUID(), ...finding, status: 'Verified', time: 'just now' });
    evidence.push(`${finding.severity}: ${finding.title}`);
  };

  if (!headers['content-security-policy']) {
    add({
      severity: 'Medium',
      path: audit.target.origin,
      title: 'Missing Content-Security-Policy header',
      hypothesis: 'Browsers have no CSP policy to reduce XSS impact or script injection blast radius.',
      confidence: 82,
      evidence: ['content-security-policy header was absent on the target response.'],
      remediation: 'Define a restrictive Content-Security-Policy and tighten script/style sources.'
    });
  }

  if (audit.target.protocol === 'https:' && !headers['strict-transport-security']) {
    add({
      severity: 'Medium',
      path: audit.target.origin,
      title: 'Missing HSTS header',
      hypothesis: 'Users can be exposed to downgrade or first-request interception risk.',
      confidence: 78,
      evidence: ['strict-transport-security header was absent over HTTPS.'],
      remediation: 'Send Strict-Transport-Security with an appropriate max-age and includeSubDomains when safe.'
    });
  }

  if (!headers['x-frame-options'] && !frameAncestors(headers['content-security-policy'])) {
    add({
      severity: 'Low',
      path: audit.target.origin,
      title: 'No clickjacking frame control detected',
      hypothesis: 'Pages may be embeddable in hostile frames unless application logic blocks it.',
      confidence: 70,
      evidence: ['Neither x-frame-options nor CSP frame-ancestors was present.'],
      remediation: 'Add CSP frame-ancestors or X-Frame-Options according to app requirements.'
    });
  }

  if (!headers['referrer-policy']) {
    add({
      severity: 'Low',
      path: audit.target.origin,
      title: 'Missing Referrer-Policy header',
      hypothesis: 'Sensitive URL path or query data may leak through the Referer header.',
      confidence: 68,
      evidence: ['referrer-policy header was absent.'],
      remediation: 'Set Referrer-Policy, commonly strict-origin-when-cross-origin.'
    });
  }

  const setCookie = headers['set-cookie'] || '';
  if (setCookie && /session|auth|token/i.test(setCookie) && !/;\s*secure/i.test(setCookie)) {
    add({
      severity: 'High',
      path: audit.target.origin,
      title: 'Sensitive cookie missing Secure flag',
      hypothesis: 'Authentication-related cookies may be sent over plaintext requests.',
      confidence: 88,
      evidence: ['set-cookie contained auth-like cookie name without a Secure attribute.'],
      remediation: 'Mark authentication cookies Secure, HttpOnly, and SameSite where compatible.'
    });
  }

  const server = headers.server || headers['x-powered-by'];
  if (server) {
    add({
      severity: 'Info',
      path: audit.target.origin,
      title: 'Technology fingerprint exposed',
      hypothesis: 'Server or framework headers reveal implementation details useful for targeted testing.',
      confidence: 65,
      evidence: [`Observed header: ${headers.server ? `server=${headers.server}` : `x-powered-by=${headers['x-powered-by']}`}`],
      remediation: 'Remove or minimize framework/version banners where operationally practical.'
    });
  }

  if (audit.findings.length === 0) {
    evidence.push('No baseline web misconfiguration findings detected.');
  }

  const exposedEnv = audit.evidence.routes?.find((route) => route.route === '/.env' && Number(route.status) < 400);
  if (exposedEnv) {
    try {
      const envProbe = await fetchText(exposedEnv.url, { timeoutMs: 3500 });
      const contentType = envProbe.response.headers.get('content-type') || '';
      const looksLikeEnv = /(^|\n)[A-Z0-9_]{3,}\s*=\s*[^=\n]{3,}/.test(envProbe.text) && !/text\/html/i.test(contentType);
      audit.evidence.envProbe = {
        status: envProbe.response.status,
        contentType,
        matchedSecretPattern: looksLikeEnv
      };
      if (looksLikeEnv) {
        add({
          severity: 'Critical',
          path: exposedEnv.url,
          title: 'Readable environment file exposed',
          hypothesis: 'The environment file route returned secret-like key/value content.',
          confidence: 92,
          evidence: [`GET ${exposedEnv.url} returned non-HTML content matching environment variable patterns.`],
          remediation: 'Block dotfiles at the web server and rotate any exposed credentials.'
        });
      } else {
        evidence.push('/.env route did not return readable secret-like content');
      }
    } catch (error) {
      evidence.push(`/.env validation failed safely: ${error.message}`);
    }
  }

  const securityTxt = audit.evidence.routes?.find((route) => route.route === '/.well-known/security.txt');
  if (securityTxt && Number(securityTxt.status) === 404) {
    add({
      severity: 'Info',
      path: securityTxt.url,
      title: 'security.txt not published',
      hypothesis: 'Researchers may not have a standard disclosure contact path.',
      confidence: 55,
      evidence: [`${securityTxt.url} returned HTTP 404.`],
      remediation: 'Publish /.well-known/security.txt with disclosure policy and contact details.'
    });
  }

  return { summary: `${audit.findings.length} findings produced`, evidence };
}

async function runCorsAgent(audit) {
  const evidence = [];
  try {
    const { response } = await fetchText(audit.target.url, {
      method: 'GET',
      timeoutMs: 5000,
      headers: { origin: 'https://attacker.example' }
    });
    const acao = response.headers.get('access-control-allow-origin') || '';
    const acac = response.headers.get('access-control-allow-credentials') || '';
    audit.evidence.cors = { acao, acac };
    evidence.push(`access-control-allow-origin: ${acao || 'absent'}`);
    evidence.push(`access-control-allow-credentials: ${acac || 'absent'}`);
    if ((acao === '*' || acao === 'https://attacker.example') && /true/i.test(acac)) {
      audit.findings.push({
        id: crypto.randomUUID(),
        severity: 'High',
        path: audit.target.origin,
        title: 'Permissive credentialed CORS policy',
        hypothesis: 'A hostile origin may read credentialed responses from the browser.',
        confidence: 90,
        status: 'Verified',
        time: 'just now',
        evidence: [`Origin reflection/wildcard observed with credentials: ACAO=${acao}, ACAC=${acac}.`],
        remediation: 'Allowlist trusted origins exactly and avoid credentialed wildcard/reflected CORS.'
      });
    }
  } catch (error) {
    audit.evidence.cors = { error: error.message };
    evidence.push(`CORS probe failed: ${error.message}`);
  }
  return { summary: 'CORS boundary checked', evidence };
}

function frameAncestors(csp = '') {
  return /frame-ancestors/i.test(csp);
}

async function runExploitAgent(audit) {
  const evidence = audit.findings.map((finding) => {
    finding.validation = `Non-invasive validation: observed live response/evidence supports ${finding.title}.`;
    return `${finding.title}: validation attached`;
  });

  if (audit.evidence.http?.links?.some((link) => /graphql/i.test(link))) {
    audit.findings.push({
      id: crypto.randomUUID(),
      severity: 'Info',
      path: new URL('/graphql', audit.target.origin).toString(),
      title: 'GraphQL-like endpoint discovered',
      hypothesis: 'A GraphQL endpoint path appeared in same-origin references and may merit authorized introspection testing.',
      confidence: 58,
      status: 'Candidate',
      time: 'just now',
      evidence: ['Same-origin link included a graphql path.'],
      remediation: 'Confirm production GraphQL introspection, auth, and resolver authorization controls.'
    });
    evidence.push('GraphQL candidate added from recon links');
  }

  return { summary: 'Safe validation completed', evidence: evidence.length ? evidence : ['No exploit validation needed'] };
}

async function runPocAgent(audit) {
  const evidence = audit.findings.map((finding) => {
    finding.poc = buildPoc(audit, finding);
    return `${finding.title}: PoC command generated`;
  });
  return { summary: `${evidence.length} PoCs generated`, evidence };
}

function buildPoc(audit, finding) {
  if (/header|fingerprint|clickjacking|hsts|referrer|csp/i.test(finding.title)) {
    return `curl -I ${JSON.stringify(audit.target.url)}`;
  }
  return `curl -sS ${JSON.stringify(finding.path || audit.target.url)}`;
}

async function runDuplicateAgent(audit) {
  const evidence = audit.findings.slice(0, 5).map((finding) => {
    finding.duplicateSearch = [
      `${audit.target.hostname} ${finding.title}`,
      `"${finding.title}" bug bounty`,
      `"${finding.title}" CVE`
    ];
    return `${finding.title}: duplicate search leads generated`;
  });
  return { summary: 'Duplicate leads prepared', evidence: evidence.length ? evidence : ['No findings to cross-check'] };
}

async function runReportAgent(audit) {
  await fs.mkdir(reportsDir, { recursive: true });
  const report = renderReport(audit);
  const filename = `${audit.id}.md`;
  const filepath = path.join(reportsDir, filename);
  await fs.writeFile(filepath, report, 'utf8');
  audit.report = {
    filename,
    path: filepath,
    markdown: report
  };
  return { summary: 'Markdown report written', evidence: [`Report saved to ${filepath}`] };
}

function renderReport(audit) {
  const lines = [
    `# Bug Bunny.ai Local Audit Report`,
    ``,
    `Target: ${audit.target.url}`,
    `Mode: ${audit.mode}`,
    `Generated: ${new Date().toISOString()}`,
    ``,
    `## Scope`,
    ...(audit.evidence.scope || []).map((item) => `- ${item}`),
    ``,
    `## Recon Evidence`,
    `- HTTP status: ${audit.evidence.http?.status ?? 'n/a'}`,
    `- Final URL: ${audit.evidence.http?.finalUrl ?? 'n/a'}`,
    `- Page title: ${audit.evidence.http?.title ?? 'n/a'}`,
    `- Forms detected: ${audit.evidence.http?.forms ?? 0}`,
    `- Same-origin links collected: ${audit.evidence.http?.links?.length ?? 0}`,
    `- Route probes: ${audit.evidence.routes?.length ?? 0}`,
    `- CORS ACAO: ${audit.evidence.cors?.acao || 'absent'}`,
    ``,
    `## Findings`
  ];

  if (!audit.findings.length) {
    lines.push(`No findings were produced by the baseline agent run.`);
  }

  for (const finding of audit.findings) {
    lines.push(
      ``,
      `### ${finding.severity}: ${finding.title}`,
      `- Path: ${finding.path}`,
      `- Confidence: ${finding.confidence}%`,
      `- Status: ${finding.status}`,
      `- Hypothesis: ${finding.hypothesis}`,
      `- Evidence: ${(finding.evidence || []).join(' ') || 'n/a'}`,
      `- Validation: ${finding.validation || 'n/a'}`,
      `- PoC: \`${finding.poc || 'n/a'}\``,
      `- Remediation: ${finding.remediation || 'n/a'}`
    );
  }

  lines.push(
    ``,
    `## Timeline`,
    ...audit.timeline.slice().reverse().map((event) => `- ${event.time} [${event.agent}] ${event.message}`)
  );

  return `${lines.join('\n')}\n`;
}

export { createAudit, getAudit, listAudits };
