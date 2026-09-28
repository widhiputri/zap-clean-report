'use strict';

const DESCRIPTIONS = {
  'sql injection':               'SQL Injection lets an attacker manipulate the queries an application sends to its database. By inserting malicious input, an attacker can read sensitive data, bypass authentication, modify or delete records, and in some cases execute commands on the database server.',
  'cross site scripting':        'Cross-Site Scripting (XSS) allows an attacker to inject malicious scripts into pages viewed by other users. This can be used to steal session tokens, hijack accounts, redirect users to fake sites, or perform actions on behalf of the victim.',
  'cross-site scripting':        'Cross-Site Scripting (XSS) allows an attacker to inject malicious scripts into pages viewed by other users. This can be used to steal session tokens, hijack accounts, redirect users to fake sites, or perform actions on behalf of the victim.',
  'path traversal':              'Path Traversal allows an attacker to access files and directories stored outside the intended web root. By manipulating file paths, they can read sensitive files such as configuration files, credentials, or system files.',
  'remote file inclusion':       'Remote File Inclusion allows an attacker to force the application to load and execute a file from a remote server, enabling arbitrary code execution.',
  'command injection':           'Command Injection allows an attacker to execute arbitrary operating system commands on the server. This can lead to full server compromise, data theft, or service disruption.',
  'csrf':                        'Cross-Site Request Forgery (CSRF) tricks an authenticated user into unknowingly submitting a request that performs an action on their behalf, such as changing account details or making transactions.',
  'cross-site request forgery':  'Cross-Site Request Forgery (CSRF) tricks an authenticated user into unknowingly submitting a request that performs an action on their behalf, such as changing account details or making transactions.',
  'open redirect':               'Open Redirect allows an attacker to redirect users from a trusted site to a malicious one. This is commonly used in phishing attacks to make fake pages appear legitimate.',
  'information disclosure':      'Information Disclosure occurs when the application unintentionally exposes sensitive information (such as stack traces, internal paths, API keys, or version details) that can help an attacker plan further attacks.',
  'sensitive information':       'Sensitive information was detected in the response. This may include credentials, tokens, personal data, or internal system details that should not be publicly accessible.',
  'user agent fuzzer':           'The scanner sent requests with different User-Agent headers to check whether the application behaves differently based on the client type. Inconsistent responses may indicate security logic that can be bypassed by spoofing the User-Agent.',
  'x-frame-options':             'Missing X-Frame-Options header means the page can be embedded in an iframe on another site. This exposes users to clickjacking attacks where they are tricked into clicking hidden elements.',
  'content security policy':     'Missing or weak Content Security Policy (CSP) means the browser has no restrictions on what scripts or resources can be loaded, making it easier for attackers to inject and execute malicious code.',
  'strict-transport-security':   'Missing HTTP Strict Transport Security (HSTS) means the browser may allow connections over insecure HTTP. Attackers on the same network can intercept or modify traffic.',
  'hsts':                        'HTTP Strict Transport Security (HSTS) was detected. This is a positive security header that instructs browsers to only connect over HTTPS, preventing downgrade attacks.',
  'cookie':                      'A cookie is missing a security flag. Without HttpOnly, scripts can read the cookie. Without Secure, the cookie can be sent over unencrypted connections. Both increase the risk of session hijacking.',
  'session':                     'A session management issue was detected. Weak session handling can allow attackers to predict, steal, or reuse session tokens to impersonate legitimate users.',
  'authentication':              'An authentication weakness was detected. This may allow attackers to bypass login controls or gain unauthorised access to protected resources.',
  'authorisation':               'An authorisation issue was detected. A user may be able to access resources or perform actions beyond their intended permission level.',
  'authorization':               'An authorisation issue was detected. A user may be able to access resources or perform actions beyond their intended permission level.',
  'idor':                        'Insecure Direct Object Reference (IDOR) allows an attacker to access another user\'s data by manipulating identifiers in requests, such as changing an ID in a URL or parameter.',
};

const DEFAULT_ACCENT = '#20B2AA';

const RISK = {
  3: { label: 'High',          slug: 'high',          color: '#D64A3B', soft: 'rgba(214,74,59,.07)'  },
  2: { label: 'Medium',        slug: 'medium',        color: '#EB9317', soft: 'rgba(235,147,23,.08)' },
  1: { label: 'Low',           slug: 'low',           color: '#C6A700', soft: 'rgba(198,167,0,.08)'  },
  0: { label: 'Informational', slug: 'informational', color: '#2C7AA1', soft: 'rgba(44,122,161,.07)' },
};

const CONFIDENCE_TIPS = {
  4: 'Confirmed: ZAP verified this with certainty. The vulnerability was proven in the response.',
  3: 'High confidence: ZAP is very likely correct. Manual verification is still recommended.',
  2: 'Medium confidence: ZAP is fairly certain, but some false positives are possible. Investigate before acting.',
  1: 'Low confidence: ZAP detected a possible issue but it may be a false positive. Treat as a lead, not a fact.',
  0: 'False positive: the scanner flagged it but it is not a real vulnerability.',
};

const SHIELD_PATH = 'M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4z';
const CHECK_PATH  = 'M10 17l-4-4 1.41-1.41L10 14.17l6.59-6.59L18 9l-8 8z';

function shieldSvg(fill, size) {
  return `<svg viewBox="0 0 24 24" width="${size}" height="${size}" aria-hidden="true"><path fill="${fill}" d="${SHIELD_PATH}"/><path fill="#fff" d="${CHECK_PATH}"/></svg>`;
}

// ZAP's own alert text carries em dashes, and a reader cannot tell our copy from the scanner's.
function removeEmDash(text) {
  return String(text || '').replace(/\s*\u2014\s*/g, ', ');
}

function renderZapHtml(text) {
  return removeEmDash(text).replace(/\*([^*]+)\*/g, '$1');
}

function formatSolution(html) {
  const items = renderZapHtml(html)
    .split(/<p>|<\/p>|\n/)
    .map(s => s.trim())
    .filter(Boolean);
  if (!items.length) return '';
  return `<ul class="solution-list">${items.map(s => `<li>${s}</li>`).join('')}</ul>`;
}

function enrichDescription(name) {
  const key = Object.keys(DESCRIPTIONS).find(k => name.toLowerCase().includes(k));
  return key ? DESCRIPTIONS[key] : null;
}

function parseAlerts(raw) {
  const alerts = [];
  (raw.site || []).forEach(site => {
    (site.alerts || []).forEach(a => {
      const confRaw = a.confidence;
      const confMap = { 'false positive': 0, low: 1, medium: 2, high: 3, confirmed: 4 };
      const conf    = typeof confRaw === 'string'
        ? (confMap[confRaw.toLowerCase()] ?? 2)
        : (parseInt(confRaw, 10) || 0);
      alerts.push({
        name:       a.name       || a.alert || '',
        riskcode:   parseInt(a.riskcode, 10) || 0,
        confidence: conf,
        desc:       a.desc       || '',
        solution:   a.solution   || '',
        otherinfo:  a.otherinfo  || '',
        reference:  a.reference  || '',
        cweid:      a.cweid      || '',
        wascid:     a.wascid     || '',
        systemic:     a.systemic,
        tags:         a.tags || {},
        inputvector:  a.inputvector || '',
        count:        parseInt(a.count, 10) || (a.instances || []).length,
        instances:    a.instances  || [],
      });
    });
  });
  return alerts.sort((a, b) => b.riskcode - a.riskcode);
}

function confidenceLabel(c) {
  return ['False Positive', 'Low', 'Medium', 'High', 'Confirmed'][c] || 'Unknown';
}

function esc(str) {
  return String(str || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function plural(n, word) {
  return `${n} ${word}${n !== 1 ? 's' : ''}`;
}

function truncateUri(uri, max = 90) {
  if (!uri) return '';
  try {
    const u    = new URL(uri);
    const base = u.origin + u.pathname;
    if (uri.length <= max) return esc(uri);
    if (base.length <= max) return esc(base) + '<span class="uri-clipped">?…</span>';
    return esc(base.substring(0, max)) + '<span class="uri-clipped">…</span>';
  } catch {
    return uri.length <= max ? esc(uri) : esc(uri.substring(0, max)) + '<span class="uri-clipped">…</span>';
  }
}

function renderInstance(inst) {
  const method   = esc(inst.method || 'GET');
  const param    = inst.param    ? `<span class="param-tag">${esc(inst.param)}</span>` : '';
  const attack   = inst.attack   ? `<div class="instance-detail">Attack: <code>${esc(inst.attack)}</code></div>`   : '';
  const evidence = inst.evidence && inst.evidence !== inst.attack ? `<div class="instance-detail">Evidence: <code>${esc(inst.evidence)}</code></div>` : '';
  const other    = inst.otherinfo && inst.otherinfo !== inst.evidence
    ? `<div class="instance-detail instance-other">${esc(inst.otherinfo)}</div>` : '';
  return `<li>
    <div class="url-row">
      <span class="http-method">${method}</span>
      <span class="uri" title="${esc(inst.uri || '')}">${truncateUri(inst.uri)}</span>
      ${param}
    </div>
    ${attack}${evidence}${other}
  </li>`;
}

function renderInstances(instances) {
  if (!instances.length) return '<p class="no-instances">No URL instances recorded.</p>';

  const shown = instances.slice(0, 5);
  const rest  = instances.slice(5);

  const shownHtml = `<ul class="url-list">${shown.map(renderInstance).join('')}</ul>`;

  if (!rest.length) return shownHtml;

  const restHtml = `<ul class="url-list url-list-more">${rest.map(renderInstance).join('')}</ul>`;

  return `<div class="instances-wrap">
    ${shownHtml}
    <details class="more-instances">
      <summary class="more-instances-toggle">
        <span class="more-chevron">&#9660;</span>
        <span class="more-closed more-text">Show ${plural(rest.length, 'more URL')}</span>
        <span class="more-open more-text">Show less</span>
      </summary>
      ${restHtml}
    </details>
  </div>`;
}

function renderAlert(alert) {
  const risk     = RISK[alert.riskcode] || RISK[0];
  const conf     = confidenceLabel(alert.confidence);
  const systemic = alert.systemic === 'true' || alert.systemic === true;
  const cweId    = parseInt(alert.cweid, 10);
  const cwe      = cweId > 0 ? `<a class="badge meta-badge" href="https://cwe.mitre.org/data/definitions/${cweId}.html" target="_blank" rel="noopener">CWE-${cweId}</a>` : '';
  const wascId   = parseInt(alert.wascid, 10);
  const wasc     = wascId > 0 ? `<a class="badge wasc-badge" href="https://projects.webappsec.org/w/page/13246953/Threat-Classification" target="_blank" rel="noopener">WASC-${wascId}</a>` : '';

  const refs = (alert.reference || '')
    .replace(/<[^>]+>/g, ' ')
    .split(/\s+/)
    .map(r => r.trim())
    .filter(r => r.startsWith('http'))
    .slice(0, 3)
    .map(r => `<a href="${esc(r)}" target="_blank" rel="noopener">${esc(r)}</a>`)
    .join('<br>');

  const owaspBadges = Object.entries(alert.tags || {})
    .filter(([k]) => /^OWASP_\d{4}_/.test(k))
    .map(([k, url]) => {
      const cat = k.replace(/^OWASP_\d{4}_/, '');
      return `<a class="badge owasp-badge" href="${esc(url)}" target="_blank" rel="noopener">OWASP ${esc(cat)}</a>`;
    })
    .join('');

  const shownCount = alert.instances.length;
  const ofTotal    = alert.count > shownCount ? ` <span class="show-more">(of ${alert.count})</span>` : '';
  const enriched   = enrichDescription(alert.name);
  const zapDesc    = renderZapHtml(alert.desc);
  const solution   = formatSolution(alert.solution);
  const otherinfo  = renderZapHtml(alert.otherinfo);

  return `
  <details class="finding" style="border-left-color:${risk.color}">
    <summary class="finding-summary" style="background:${risk.soft}">
      <span class="chevron" style="color:${risk.color}">&#9656;</span>
      <span class="finding-title">${esc(alert.name)}</span>
      <span class="finding-badges">
        <span class="badge risk-badge" style="background:${risk.color}">${risk.label}</span>
        <span class="badge conf-badge" title="${esc(CONFIDENCE_TIPS[alert.confidence] || '')}">${esc(conf)}</span>
        ${cwe}${wasc}${owaspBadges}
        ${systemic ? '<span class="badge systemic-badge">Systemic</span>' : ''}
        ${alert.count > 0 ? `<span class="instance-count">${plural(shownCount, 'URL')}${ofTotal}</span>` : ''}
      </span>
    </summary>

    <div class="finding-body">

      <div class="finding-section">
        <div class="section-label">What is this?</div>
        ${enriched ? `<div class="desc-enriched"><div class="ipt-label">In plain terms</div>${enriched}</div>` : ''}
        ${zapDesc ? `<div class="desc-plain">${zapDesc}</div>` : (enriched ? '' : '<div class="desc-plain"><em>No description.</em></div>')}
      </div>

      ${solution ? `
      <div class="finding-section">
        <div class="section-label">How to fix</div>
        <div class="fix-card">${solution}</div>
      </div>` : ''}

      ${alert.instances.length ? `
      <div class="finding-section">
        <div class="section-label">Affected URLs <span class="url-label-count">${plural(alert.count, 'URL')}</span>${alert.inputvector ? `<span class="inputvec-label">via ${esc(alert.inputvector)}</span>` : ''}</div>
        ${renderInstances(alert.instances)}
        <div class="url-note">The URLs above show where this issue was found. Some parameters may look unusual because the scanner deliberately sent unexpected values to test how the application responds. This is normal for a security scan and does not reflect real user activity.</div>
      </div>` : ''}

      ${otherinfo ? `
      <div class="finding-section">
        <div class="section-label">Additional info</div>
        <div class="section-content">${otherinfo}</div>
      </div>` : ''}

      ${refs ? `
      <div class="finding-section">
        <div class="section-label">External references</div>
        <div class="section-content refs-content">${refs}</div>
      </div>` : ''}

    </div>
  </details>`;
}

function localUtcOffset() {
  const pad        = n => String(n).padStart(2, '0');
  const offsetMins = -new Date().getTimezoneOffset();
  const sign       = offsetMins >= 0 ? '+' : '-';
  const abs        = Math.abs(offsetMins);
  return `(UTC${sign}${pad(Math.floor(abs / 60))}:${pad(abs % 60)})`;
}

function formatLocalTimestamp() {
  const d      = new Date();
  const days   = ['Sun','Mon','Tue','Wed','Thu','Fri','Sat'];
  const months = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
  const pad    = n => String(n).padStart(2, '0');

  return `${days[d.getDay()]}, ${pad(d.getDate())} ${months[d.getMonth()]} ${d.getFullYear()} `
       + `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())} ${localUtcOffset()}`;
}

// The accent lands inside a <style> block, so anything but a plain hex colour is refused.
function safeAccent(value) {
  return /^#(?:[0-9a-f]{3}|[0-9a-f]{6})$/i.test(value || '') ? value : DEFAULT_ACCENT;
}

function renderTitle(title) {
  const words = esc(title).split(' ');
  if (words.length < 2) return words.join(' ');
  const last = words.pop();
  return `${words.join(' ')} <em>${last}</em>`;
}

function renderVerdict(counts) {
  if (counts[3] > 0) {
    return { rgb: '214,74,59', color: RISK[3].color, num: counts[3], title: counts[3] === 1 ? 'High-severity finding' : 'High-severity findings', sub: 'Requires immediate attention' };
  }
  if (counts[2] > 0) {
    return { rgb: '235,147,23', color: RISK[2].color, num: counts[2], title: counts[2] === 1 ? 'Medium-severity finding' : 'Medium-severity findings', sub: 'Address in the current sprint' };
  }
  return { rgb: null, color: 'var(--accent)', num: 0, title: 'No high-severity findings', sub: 'Clean under the tested conditions' };
}

function generateReport(raw, opts = {}) {
  const alerts    = parseAlerts(raw);
  const title     = opts.title || 'Security Scan Report';
  const brand     = opts.brand || {};
  const accent    = safeAccent(brand.accent);
  const now       = formatLocalTimestamp();
  const generated = (raw['@generated'] || now).replace(/\s*\(UTC[^)]*\)$/, '') + ' ' + localUtcOffset();
  const zapVer    = raw['@version'] || 'Unknown';

  const siteList = raw.site || [];
  const sites    = siteList.map(s => s['@name'] || s['@host'] || '').filter(Boolean);
  const target   = sites.join(', ') || 'Unknown';
  let   eyebrow  = sites[0] || 'Security scan';
  try { eyebrow = new URL(sites[0]).hostname; } catch { /* keep the raw site name */ }

  const counts = { 3: 0, 2: 0, 1: 0, 0: 0 };
  alerts.forEach(a => { counts[a.riskcode] = (counts[a.riskcode] || 0) + 1; });

  const totalAlerts    = alerts.length;
  const totalInstances = alerts.reduce((n, a) => n + a.count, 0);
  const hasFindings    = totalAlerts > 0;
  const verdict        = renderVerdict(counts);
  const verdictStyle   = verdict.rgb
    ? `background:rgba(${verdict.rgb},.16);border:1px solid rgba(${verdict.rgb},.45)`
    : 'background:color-mix(in srgb,var(--accent) 14%,transparent);border:1px solid color-mix(in srgb,var(--accent) 40%,transparent)';

  const logoHtml = brand.logo
    ? `<img class="brand-logo" src="${esc(brand.logo)}" alt="">`
    : shieldSvg('var(--accent)', 24);
  const brandName = esc(brand.name || 'zap-clean-report');
  const footerTxt = esc(brand.footer || 'Generated by zap-clean-report');
  const favicon   = `data:image/svg+xml,${encodeURIComponent(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path fill="${accent}" d="${SHIELD_PATH}"/><path fill="#fff" d="${CHECK_PATH}"/></svg>`)}`;

  const tile = (cls, num, label, zero) =>
    `<div class="summary-card ${cls}${zero ? ' card-zero' : ''}"><div class="num">${num}</div><div class="lbl">${label}</div></div>`;

  const byRisk = [3, 2, 1, 0].map(rc => {
    const group = alerts.filter(a => a.riskcode === rc);
    if (!group.length) return '';
    return `
    <section class="risk-section" data-risk="${RISK[rc].slug}">
      ${group.map(renderAlert).join('\n')}
    </section>`;
  }).join('');

  const filterBtns = [3, 2, 1, 0]
    .filter(rc => counts[rc] > 0)
    .map(rc => `<button class="filter-btn" onclick="setRisk('${RISK[rc].slug}',this)">${RISK[rc].label} (${counts[rc]})</button>`)
    .join('');

  const sitePills = siteList.length
    ? siteList.map(s => `<span class="pill mono">${esc(s['@name'] || s['@host'] || '')}</span>`).join('')
    : '<span class="pill">Unknown</span>';

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600&family=Source+Serif+4:ital,wght@0,400;0,600;1,400;1,600&family=JetBrains+Mono:wght@400;500&display=swap">
<link rel="icon" type="image/svg+xml" href="${favicon}">
<style>
:root{
  --accent:${accent};
  --accent-dark:color-mix(in srgb,var(--accent) 75%,#000);
  --accent-soft:color-mix(in srgb,var(--accent) 12%,transparent);
  --accent-line:color-mix(in srgb,var(--accent) 30%,transparent);
  --ink:#2B2B2B; --g700:#2B2B2B; --g600:#4A4A4A; --g500:#6D6D6D; --g400:#9A9A9A; --g300:#BFBFBF;
  --border:#DEDEDE; --border-sub:#EDEDED; --g50:#F7F7F7; --g100:#EDEDED;
  --bg:#E9EBED; --header:#23272B;
  --high:#D64A3B; --med:#EB9317; --low:#C6A700; --info:#2C7AA1;
  --purple:#6A3E87; --navy:#003A63; --steel:#4F6B6C; --blue:#2C7AA1; --coral:#D64A3B;
  --serif:"Source Serif 4",Georgia,"Times New Roman",serif;
  --sans:"Inter",-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
  --mono:"JetBrains Mono",ui-monospace,Menlo,Consolas,monospace;
  --r-sm:4px; --r-md:6px; --r-lg:8px; --r-full:9999px;
  --sh-xs:0 1px 2px rgba(0,0,0,.04); --sh-sm:0 1px 3px rgba(0,0,0,.06),0 1px 2px rgba(0,0,0,.04);
}
*{box-sizing:border-box;margin:0;padding:0}
html{scroll-behavior:smooth;-webkit-font-smoothing:antialiased}
body{font-family:var(--sans);font-weight:300;font-size:14px;line-height:1.5;color:var(--ink);background:var(--bg)}
a{color:inherit;text-decoration:none}
.section-content a{color:var(--accent-dark)}
.section-content a:hover{text-decoration:underline}
.mono{font-family:var(--mono)}

/* Header band */
header{background:linear-gradient(180deg,#23272B 0%,#2B2F33 100%);color:#fff}
.header-inner{max-width:1200px;margin:0 auto;padding:30px 40px 38px}
.top{display:flex;align-items:center;justify-content:space-between;gap:24px;margin-bottom:34px}
.brand{display:flex;align-items:center;gap:11px;font-weight:600;font-size:16px;letter-spacing:.04em}
.brand svg{flex-shrink:0}
.brand-logo{height:26px;width:auto;display:block}
.scanpill{display:flex;align-items:center;gap:10px;font-size:11px;letter-spacing:.14em;text-transform:uppercase;color:rgba(255,255,255,.55)}
.scandot{width:7px;height:7px;border-radius:50%;background:var(--accent);box-shadow:0 0 0 3px color-mix(in srgb,var(--accent) 25%,transparent)}
.headrow{display:flex;align-items:flex-end;justify-content:space-between;gap:40px;flex-wrap:wrap}
.eyebrow{font-size:11px;letter-spacing:.18em;text-transform:uppercase;color:var(--accent);font-weight:600;margin-bottom:14px}
header h1{font-family:var(--serif);font-weight:400;font-size:52px;line-height:1.02;letter-spacing:-.02em;color:#fff}
header h1 em{font-style:italic}
.genline{margin-top:16px;font-size:13px;color:rgba(255,255,255,.6);display:flex;gap:18px;flex-wrap:wrap}
.genline b{color:rgba(255,255,255,.85);font-weight:400}
.genline .mono{color:rgba(255,255,255,.85);word-break:break-all}
.sep{color:rgba(255,255,255,.3)}
.verdict{display:flex;align-items:center;gap:14px;padding:16px 22px;border-radius:var(--r-lg)}
.verdict .vnum{font-family:var(--serif);font-size:40px;line-height:1;font-weight:600}
.verdict .vtitle{font-size:13px;font-weight:600;color:#fff;letter-spacing:.01em}
.verdict .vsub{font-size:12px;color:rgba(255,255,255,.6);margin-top:3px}

/* Sticky nav */
.section-nav{position:sticky;top:0;z-index:30;background:rgba(38,42,46,.97);border-bottom:1px solid rgba(255,255,255,.08)}
.section-nav-inner{max-width:1200px;margin:0 auto;padding:0 40px;display:flex}
.section-nav a{flex:1;text-align:center;font-size:13px;font-weight:500;color:rgba(255,255,255,.55);padding:15px 8px;border-bottom:2px solid transparent;transition:color .15s,border-color .15s;white-space:nowrap}
.section-nav a:hover{color:#fff}
.section-nav a.active{color:#fff;border-bottom-color:var(--accent)}

.container{max-width:1200px;margin:0 auto;padding:36px 40px 0}
.anchor{display:block;height:0;scroll-margin-top:60px}

/* Numbered section heads */
.sec-head{display:flex;align-items:baseline;gap:14px;margin:40px 0 18px}
.sec-head h2{font-size:20px;font-weight:600;color:var(--ink);letter-spacing:-.01em}
.sec-head .rule{flex:1;height:1px;background:var(--border)}
.sec-head .num{font-family:var(--mono);font-size:12px;color:var(--g400)}

.report-intro{background:#fff;border:1px solid var(--border);border-left:3px solid var(--accent);border-radius:var(--r-md);padding:22px 26px;box-shadow:var(--sh-xs);font-size:14.5px;line-height:1.6;color:var(--g700)}
.report-intro strong{font-weight:600;color:var(--ink)}

/* Stat tiles */
.summary{display:grid;grid-template-columns:repeat(6,1fr);gap:12px;margin-top:24px}
.summary-card{background:#fff;border:1px solid var(--border);border-top:3px solid var(--g400);border-radius:var(--r-md);padding:18px 14px 16px;text-align:center;box-shadow:var(--sh-xs)}
.summary-card .num{font-family:var(--serif);font-weight:600;font-size:34px;line-height:1;color:var(--ink)}
.summary-card .lbl{margin-top:9px;font-size:10.5px;letter-spacing:.09em;text-transform:uppercase;color:var(--g500);font-weight:600;display:inline-flex;align-items:center;gap:5px}
.card-h{border-top-color:var(--high)} .card-h .num{color:var(--high)}
.card-m{border-top-color:var(--med)} .card-m .num{color:var(--med)}
.card-l{border-top-color:var(--low)} .card-l .num{color:var(--low)}
.card-i{border-top-color:var(--info)} .card-i .num{color:var(--info)}
.card-total{border-top-color:var(--g400)}
.card-urls{border-top-color:var(--accent)} .card-urls .num{color:var(--accent-dark)}
.summary-card.card-zero{border-top-color:var(--border)}
.summary-card.card-zero .num{color:var(--g400)}

/* How-to-read legend */
.legend{background:#fff;border:1px solid var(--border);border-radius:var(--r-md);box-shadow:var(--sh-xs);padding:4px 28px 12px;margin-top:40px}
.section-toggle{display:flex;align-items:center;gap:8px;padding:13px 0;cursor:pointer;list-style:none;user-select:none;font-size:11px;letter-spacing:.12em;text-transform:uppercase;color:var(--accent-dark);font-weight:600}
.section-toggle::-webkit-details-marker{display:none}
.sec-chevron{font-size:11px;color:var(--accent);transition:transform .2s;display:inline-block}
details[open]>.section-toggle .sec-chevron{transform:rotate(90deg)}
.legend-body{padding:4px 0 12px}
.legend-group-title{font-size:11px;letter-spacing:.1em;text-transform:uppercase;color:var(--g500);font-weight:600;margin:24px 0 10px}
.legend-group-title:first-child{margin-top:0}
.legend-subnote{font-size:11.5px;color:var(--g400);margin:-6px 0 14px}
.risk-legend{display:flex;flex-direction:column;gap:8px}
.risk-legend-row{display:grid;grid-template-columns:104px 120px 1fr;gap:18px;align-items:center;padding:13px 18px;background:var(--g50);border-left:3px solid;border-radius:var(--r-sm)}
.risk-legend-name{font-size:14px;font-weight:600}
.risk-legend-action{font-size:11px;font-weight:600;padding:4px 11px;border-radius:var(--r-full);text-align:center}
.risk-legend-desc{font-size:13px;line-height:1.5;color:var(--g600)}
.conf-legend{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}
.conf-card{background:var(--g50);border:1px solid var(--border-sub);border-radius:var(--r-sm);padding:15px 16px}
.conf-card-label{font-size:13px;font-weight:600;color:var(--ink);margin-bottom:5px}
.conf-card-desc{font-size:12.5px;line-height:1.5;color:var(--g600)}
.badge-legend{display:grid;grid-template-columns:1fr 1fr;gap:14px 32px}
.badge-legend-item{display:grid;grid-template-columns:96px 1fr;gap:14px;align-items:start}
.badge-legend-item>.badge{justify-self:start}
.badge-legend-desc{font-size:12.5px;line-height:1.5;color:var(--g600)}

/* Scan details */
.meta-section{background:#fff;border:1px solid var(--border);border-radius:var(--r-md);padding:8px 28px;box-shadow:var(--sh-xs)}
.config-row{display:flex;gap:24px;padding:15px 0;border-bottom:1px solid var(--border-sub);align-items:center}
.config-row:last-child{border-bottom:none}
.config-key{width:160px;flex-shrink:0;font-size:12px;letter-spacing:.04em;text-transform:uppercase;color:var(--g500);font-weight:600}
.config-val{font-size:14.5px;color:var(--ink);display:flex;flex-wrap:wrap;gap:8px;align-items:center;min-width:0}
.pill{display:inline-flex;align-items:center;font-size:12.5px;font-weight:500;padding:5px 12px;border-radius:var(--r-full);background:var(--g100);color:var(--g600);word-break:break-all}

/* Filters */
.filter-bar{display:flex;align-items:center;gap:14px;flex-wrap:wrap;background:#fff;border:1px solid var(--border);border-radius:var(--r-md);box-shadow:var(--sh-xs);padding:10px 22px}
.filter-label{width:88px;flex-shrink:0;font-size:11px;letter-spacing:.08em;text-transform:uppercase;color:var(--g500);font-weight:600}
.filter-btn{font-family:inherit;font-size:12.5px;font-weight:400;padding:7px 15px;border-radius:var(--r-full);border:1px solid var(--border);background:#fff;color:var(--g600);cursor:pointer;transition:all .15s}
.filter-btn:hover{border-color:var(--accent)}
.filter-btn.active{background:var(--ink);border-color:var(--ink);color:#fff;font-weight:600}

/* Finding cards */
.finding{background:#fff;border:1px solid var(--border);border-left:3px solid var(--g400);border-radius:var(--r-md);overflow:hidden;box-shadow:var(--sh-sm);margin-top:22px}
.finding-summary{padding:20px 26px;cursor:pointer;display:flex;align-items:center;gap:14px;list-style:none;user-select:none;border-bottom:1px solid var(--border-sub)}
.finding-summary::-webkit-details-marker{display:none}
.chevron{font-size:16px;flex-shrink:0;transition:transform .15s;display:inline-block}
details.finding[open] .chevron{transform:rotate(90deg)}
.finding-title{font-weight:600;font-size:15px;flex:1;color:var(--ink);min-width:0}
.finding-badges{display:flex;align-items:center;gap:7px;flex-wrap:wrap;justify-content:flex-end}
.badge{font-size:11px;padding:4px 10px;border-radius:var(--r-sm);font-weight:600;white-space:nowrap;cursor:default}
a.badge{cursor:pointer}
.risk-badge{color:#fff;padding:4px 11px;letter-spacing:.04em}
.conf-badge{background:var(--g100);color:var(--g600);font-weight:500;cursor:help}
.meta-badge{background:rgba(106,62,135,.12);color:var(--purple)}
.wasc-badge{background:rgba(0,58,99,.1);color:var(--navy)}
.owasp-badge{background:rgba(44,122,161,.12);color:var(--blue)}
.systemic-badge{background:rgba(79,107,108,.14);color:var(--steel)}
.instance-count{font-size:11px;color:var(--g400);margin-left:2px;font-weight:400;white-space:nowrap}
.show-more{font-style:italic}

.finding-body{padding:24px 26px;display:flex;flex-direction:column}
.finding-section{padding:18px 0 0}
.finding-section:first-child{padding-top:0}
.section-label{font-size:11px;letter-spacing:.1em;text-transform:uppercase;color:var(--g500);font-weight:600;margin-bottom:10px;display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.url-label-count{background:var(--g100);color:var(--g600);font-size:11px;font-weight:600;padding:3px 9px;border-radius:var(--r-sm);letter-spacing:0;text-transform:none}
.inputvec-label{font-size:10px;font-weight:600;color:var(--accent-dark);background:var(--accent-soft);padding:2px 9px;border-radius:var(--r-full);letter-spacing:0;text-transform:none}
.section-content{font-size:14px;color:var(--g600);line-height:1.6}
.section-content p{margin-bottom:8px}
.section-content p:last-child{margin-bottom:0}
.desc-enriched{background:color-mix(in srgb,var(--accent) 7%,transparent);border-left:3px solid var(--accent);border-radius:var(--r-sm);padding:12px 16px;font-size:14px;line-height:1.6;color:var(--g700);font-weight:400}
.ipt-label{font-size:10px;letter-spacing:.08em;text-transform:uppercase;color:var(--accent-dark);font-weight:600;margin-bottom:5px}
.desc-plain{margin-top:14px;font-size:14px;line-height:1.6;color:var(--g700)}
.desc-plain:first-child{margin-top:0}
.desc-plain p{margin-bottom:8px}
.desc-plain p:last-child{margin-bottom:0}
.fix-card{background:var(--g50);border:1px solid var(--border-sub);border-left:3px solid var(--accent-dark);border-radius:var(--r-md);padding:16px 18px}
.solution-list{padding-left:20px;display:flex;flex-direction:column;gap:7px}
.solution-list li{font-size:13.5px;line-height:1.55;color:var(--g600)}
.refs-content{font-size:12.5px;line-height:1.8;word-break:break-all}

.url-list{list-style:none;display:flex;flex-direction:column;gap:10px;margin-top:2px}
.url-list li{background:var(--g50);border:1px solid var(--border-sub);border-radius:var(--r-sm);padding:13px 16px;font-size:12px}
.url-row{display:flex;align-items:baseline;gap:9px;flex-wrap:wrap}
.http-method{font-weight:600;font-size:10px;letter-spacing:.06em;padding:3px 8px;background:var(--accent-soft);color:var(--accent-dark);border-radius:3px;flex-shrink:0}
.uri{font-family:var(--mono);font-size:11.5px;color:var(--g700);word-break:break-all;line-height:1.4;min-width:0}
.uri-clipped{color:var(--g300);font-style:italic}
.param-tag{font-size:10px;font-weight:600;background:rgba(214,74,59,.1);color:var(--coral);padding:3px 8px;border-radius:3px}
.instance-detail{margin-top:9px;padding-top:9px;border-top:1px dashed var(--border);font-size:12px;color:var(--g500);overflow-wrap:anywhere;word-break:break-word;min-width:0}
.instance-detail code{font-family:var(--mono);color:var(--ink);overflow-wrap:anywhere;word-break:break-all;white-space:pre-wrap}
.instance-other{font-style:italic;border:none;padding-top:7px;margin-top:7px}
.no-instances{color:var(--g400);font-size:12px;font-style:italic}
.instances-wrap{display:flex;flex-direction:column;gap:10px}
.more-instances-toggle{display:inline-flex;align-items:center;gap:5px;font-size:13px;color:var(--accent-dark);cursor:pointer;list-style:none;user-select:none;font-weight:500;padding:2px 0}
.more-instances-toggle::-webkit-details-marker{display:none}
.more-instances-toggle:hover .more-text{text-decoration:underline}
.more-chevron{font-size:9px;transition:transform .2s;display:inline-block}
details.more-instances[open] .more-chevron{transform:rotate(180deg)}
.more-closed{display:inline}.more-open{display:none}
details.more-instances[open] .more-closed{display:none}
details.more-instances[open] .more-open{display:inline}
.url-list-more{margin-top:10px}
.url-note{font-size:12px;color:var(--g400);margin-top:14px;line-height:1.5;font-style:italic}
.no-findings{text-align:center;padding:50px;color:var(--accent-dark);font-size:18px;font-weight:600;background:#fff;border:1px solid var(--border);border-radius:var(--r-md)}

/* Info tooltip */
.info-icon{position:relative;display:inline-flex;align-items:center;justify-content:center;width:15px;height:15px;border-radius:50%;background:var(--border);color:var(--g600);font-family:var(--serif);font-size:11px;font-weight:600;font-style:italic;line-height:1;text-transform:none;letter-spacing:0;cursor:help;flex-shrink:0;transition:background .15s,color .15s}
.info-icon:hover{background:var(--accent);color:#fff}
.info-icon:hover .info-tooltip{opacity:1;visibility:visible;transform:none}
.info-tooltip{position:absolute;bottom:calc(100% + 9px);right:-6px;width:230px;padding:10px 13px;background:#23272B;color:#E9EBED;font-family:var(--sans);font-size:11.5px;line-height:1.5;font-weight:400;font-style:normal;border-radius:var(--r-md);box-shadow:0 10px 30px rgba(0,0,0,.22);opacity:0;visibility:hidden;transform:translateY(3px);transition:opacity .15s,transform .15s,visibility .15s;z-index:60;pointer-events:none;text-align:left}
.info-tooltip::after{content:'';position:absolute;top:100%;right:12px;border:5px solid transparent;border-top-color:#23272B}

/* Footer */
footer{max-width:1200px;margin:48px auto 0;padding:24px 40px 40px;border-top:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;gap:16px;font-size:12px;color:var(--g500);flex-wrap:wrap}
.foot-left{display:flex;align-items:center;gap:10px;letter-spacing:.02em}
footer .mono{color:var(--g400)}

@media(max-width:960px){
  .summary{grid-template-columns:repeat(3,1fr)}
  .conf-legend{grid-template-columns:1fr 1fr}
  .badge-legend{grid-template-columns:1fr}
}
@media(max-width:640px){
  .header-inner{padding:22px 16px 28px}
  .top{margin-bottom:24px}
  .scanpill,.sep{display:none}
  header h1{font-size:36px}
  .headrow{gap:20px}
  .section-nav-inner{padding:0 8px;overflow-x:auto}
  .section-nav a{flex:none;padding:13px 12px}
  .container{padding:24px 16px 0}
  footer{padding:20px 16px 32px}
  .summary{grid-template-columns:1fr 1fr}
  .legend,.meta-section{padding-left:16px;padding-right:16px}
  .risk-legend-row{grid-template-columns:1fr;gap:6px}
  .risk-legend-action{justify-self:start}
  .conf-legend{grid-template-columns:1fr}
  .config-row{flex-direction:column;align-items:flex-start;gap:8px}
  .filter-bar{padding:10px 14px}
  .filter-label{width:auto}
  .finding-summary{flex-wrap:wrap;padding:16px}
  .finding-title{flex-basis:calc(100% - 40px)}
  .finding-badges{justify-content:flex-start}
  .finding-body{padding:18px 16px}
}
@media print{
  body{background:#fff}
  .section-nav,.filter-bar,.more-instances-toggle,.info-icon{display:none!important}
  .container{padding:20px 0 0;max-width:100%}
  details.finding{overflow:visible!important}
  .finding,.meta-section,.summary-card,.legend,.report-intro,.filter-bar{box-shadow:none!important}
  header,.finding-summary,.summary-card,.desc-enriched,.badge,.verdict,.http-method,.risk-legend-row,.risk-legend-action{-webkit-print-color-adjust:exact;print-color-adjust:exact}
  .finding{break-inside:avoid-page}
  @page{margin:1.2cm;size:A4}
}
</style>
</head>
<body>

<header>
  <div class="header-inner">
    <div class="top">
      <div class="brand">${logoHtml}<span>${brandName}</span></div>
      <div class="scanpill"><span class="scandot"></span>Automated Security Scan</div>
    </div>
    <div class="headrow">
      <div>
        <div class="eyebrow">${esc(eyebrow)} &middot; OWASP ZAP</div>
        <h1>${renderTitle(title)}</h1>
        <div class="genline">
          <span>Generated <b>${esc(generated)}</b></span>
          <span class="sep">|</span>
          <span>Target <span class="mono">${esc(target)}</span></span>
        </div>
      </div>
      <div class="verdict" style="${verdictStyle}">
        <div class="vnum" style="color:${verdict.color}">${verdict.num}</div>
        <div><div class="vtitle">${verdict.title}</div><div class="vsub">${verdict.sub}</div></div>
      </div>
    </div>
  </div>
</header>

<nav class="section-nav"><div class="section-nav-inner">
  <a href="#sec-overview">Overview</a>
  <a href="#sec-details">Scan Details</a>
  <a href="#sec-findings">Findings</a>
</div></nav>

<div class="container">

  <div id="sec-overview" class="anchor"></div>
  <div class="report-intro">
    This report presents the results of an automated security scan performed against <strong>${esc(target)}</strong> using OWASP ZAP,
    an industry-standard security testing tool. The scan actively tests the target for security weaknesses.
    Findings are grouped by severity. <strong>High and Medium findings require immediate attention.</strong>
    Low and informational findings are worth reviewing but pose no immediate risk.
    ${!hasFindings ? '<br><br>No security findings were identified. The target appears clean under the tested conditions.' : ''}
  </div>

  <div class="summary">
    ${tile('card-total', totalAlerts, 'Total Findings', false)}
    ${tile('card-h', counts[3], 'High', counts[3] === 0)}
    ${tile('card-m', counts[2], 'Medium', counts[2] === 0)}
    ${tile('card-l', counts[1], 'Low', counts[1] === 0)}
    ${tile('card-i', counts[0], 'Informational', counts[0] === 0)}
    <div class="summary-card card-urls"><div class="num">${totalInstances}</div><div class="lbl">Affected URLs <span class="info-icon">i<span class="info-tooltip">Total number of affected URLs across all findings. One finding can affect multiple URLs.</span></span></div></div>
  </div>

  <details class="legend" open>
    <summary class="section-toggle"><span class="sec-chevron">&#9656;</span>How to Read This Report</summary>
    <div class="legend-body">

      <div class="legend-group-title">Risk Level</div>
      <div class="risk-legend">
        <div class="risk-legend-row" style="border-left-color:#D64A3B">
          <span class="risk-legend-name" style="color:#D64A3B">High</span>
          <span class="risk-legend-action" style="background:rgba(214,74,59,.12);color:#D64A3B">Fix immediately</span>
          <span class="risk-legend-desc">Serious vulnerability that could directly lead to data loss, account takeover, or system compromise. Prioritise before the next release.</span>
        </div>
        <div class="risk-legend-row" style="border-left-color:#EB9317">
          <span class="risk-legend-name" style="color:#EB9317">Medium</span>
          <span class="risk-legend-action" style="background:rgba(235,147,23,.14);color:#B5710D">Fix this sprint</span>
          <span class="risk-legend-desc">Significant issue that increases attack surface. Address in the current or next sprint.</span>
        </div>
        <div class="risk-legend-row" style="border-left-color:#C6A700">
          <span class="risk-legend-name" style="color:#9A7E00">Low</span>
          <span class="risk-legend-action" style="background:rgba(198,167,0,.16);color:#9A7E00">Schedule</span>
          <span class="risk-legend-desc">Minor weakness or defence-in-depth gap. Low immediate risk but worth planning into a future sprint.</span>
        </div>
        <div class="risk-legend-row" style="border-left-color:#2C7AA1">
          <span class="risk-legend-name" style="color:#2C7AA1">Informational</span>
          <span class="risk-legend-action" style="background:rgba(44,122,161,.12);color:#2C7AA1">Review</span>
          <span class="risk-legend-desc">No direct risk, but may help an attacker with reconnaissance. Useful context for developers and architects.</span>
        </div>
      </div>

      <div class="legend-group-title">Confidence</div>
      <div class="conf-legend">
        <div class="conf-card"><div class="conf-card-label">Confirmed</div><div class="conf-card-desc">Verified with certainty in the server response.</div></div>
        <div class="conf-card"><div class="conf-card-label">High</div><div class="conf-card-desc">Very likely a real issue. Manual verification still recommended.</div></div>
        <div class="conf-card"><div class="conf-card-label">Medium</div><div class="conf-card-desc">Probably real, but some false positives are possible.</div></div>
        <div class="conf-card"><div class="conf-card-label">Low</div><div class="conf-card-desc">Possible issue. Treat as a lead, not a confirmed finding.</div></div>
      </div>

      <div class="legend-group-title">Reference Badges</div>
      <div class="legend-subnote">Standard security references attached to a finding.</div>
      <div class="badge-legend">
        <div class="badge-legend-item">
          <span class="badge meta-badge">CWE-&lt;n&gt;</span>
          <span class="badge-legend-desc">Common Weakness Enumeration. A globally recognised ID for a category of software weakness (e.g. CWE-89 is SQL Injection). Click to open the full description on MITRE.</span>
        </div>
        <div class="badge-legend-item">
          <span class="badge wasc-badge">WASC-&lt;n&gt;</span>
          <span class="badge-legend-desc">Web Application Security Consortium classification. Groups vulnerabilities into broader threat categories.</span>
        </div>
        <div class="badge-legend-item">
          <span class="badge owasp-badge">OWASP A&lt;xx&gt;</span>
          <span class="badge-legend-desc">Maps this finding to an OWASP Top 10 category, the industry-standard list of the most critical web security risks.</span>
        </div>
        <div class="badge-legend-item">
          <span class="badge systemic-badge">Systemic</span>
          <span class="badge-legend-desc">Found across multiple endpoints, indicating a systemic issue in how the application is built rather than an isolated mistake. Fix at the root, not per URL.</span>
        </div>
      </div>

    </div>
  </details>

  <div id="sec-details" class="anchor"></div>
  <div class="sec-head"><h2>Scan Details</h2><span class="rule"></span><span class="num">01</span></div>
  <div class="meta-section">
    <div class="config-row"><div class="config-key">Target</div><div class="config-val">${sitePills}</div></div>
    <div class="config-row"><div class="config-key">Scanner</div><div class="config-val">OWASP ZAP ${esc(zapVer)}</div></div>
    <div class="config-row"><div class="config-key">Scan generated</div><div class="config-val">${esc(generated)}</div></div>
    <div class="config-row"><div class="config-key">Report created</div><div class="config-val">${esc(now)}</div></div>
  </div>

  <div id="sec-findings" class="anchor"></div>
  <div class="sec-head"><h2>Findings</h2><span class="rule"></span><span class="num">02</span></div>
  ${hasFindings ? `
  <div class="filter-bar">
    <span class="filter-label">Severity</span>
    <button class="filter-btn active" onclick="setRisk('all',this)">All</button>
    ${filterBtns}
  </div>
  ${byRisk}` : '<div class="no-findings">&#10003;&nbsp; No security findings identified.</div>'}

</div>

<footer>
  <div class="foot-left">${shieldSvg('var(--accent)', 18)}<span>${footerTxt}</span></div>
  <span class="mono">OWASP ZAP ${esc(zapVer)}</span>
</footer>

<script>
  function setRisk(level, btn) {
    document.querySelectorAll('.risk-section').forEach(function (s) {
      s.style.display = (level === 'all' || s.dataset.risk === level) ? '' : 'none';
    });
    btn.parentElement.querySelectorAll('.filter-btn').forEach(function (b) { b.classList.toggle('active', b === btn); });
  }

  (function () {
    var saved = [];
    window.addEventListener('beforeprint', function () {
      saved = [];
      document.querySelectorAll('details').forEach(function (d) { saved.push(d.open); d.open = true; });
    });
    window.addEventListener('afterprint', function () {
      document.querySelectorAll('details').forEach(function (d, i) { d.open = saved[i] !== undefined ? saved[i] : false; });
    });
  })();

  (function () {
    var links = {};
    document.querySelectorAll('.section-nav a').forEach(function (a) { links[a.getAttribute('href').slice(1)] = a; });
    var anchors = Array.prototype.slice.call(document.querySelectorAll('.anchor[id^="sec-"]'))
      .filter(function (a) { return links[a.id]; });
    function setActive(id) { Object.keys(links).forEach(function (k) { links[k].classList.toggle('active', k === id); }); }
    function onScroll() {
      var current = anchors[0].id;
      for (var i = 0; i < anchors.length; i++) {
        if (anchors[i].getBoundingClientRect().top <= 110) { current = anchors[i].id; } else { break; }
      }
      setActive(current);
    }
    if (!anchors.length) return;
    window.addEventListener('scroll', onScroll, { passive: true });
    window.addEventListener('resize', onScroll);
    onScroll();
  })();
</script>
</body>
</html>`;
}

module.exports = { generateReport };
