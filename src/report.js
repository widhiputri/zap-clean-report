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

function formatSolution(html) {
  if (!html) return '<em>No remediation guidance provided.</em>';
  return '<ul class="solution-list">'
    + html
        .replace(/\*([^*]+)\*/g, '$1')
        .split(/<p>|<\/p>|\n/)
        .map(s => s.trim())
        .filter(Boolean)
        .map(s => `<li>${s}</li>`)
        .join('')
    + '</ul>';
}

function enrichDescription(name) {
  const key = Object.keys(DESCRIPTIONS).find(k => name.toLowerCase().includes(k));
  return key ? DESCRIPTIONS[key] : null;
}

const RISK = {
  3: { label: 'High',          color: '#c62828', bg: '#ffebee', border: '#e53935', pill: '#c62828' },
  2: { label: 'Medium',        color: '#d97706', bg: '#fffbeb', border: '#f59e0b', pill: '#d97706' },
  1: { label: 'Low',           color: '#9e9d24', bg: '#f9fbe7', border: '#cddc39', pill: '#9e9d24' },
  0: { label: 'Informational', color: '#1565c0', bg: '#e3f2fd', border: '#1976d2', pill: '#1565c0' },
};

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

function truncateText(str, max = 140) {
  if (!str || str.length <= max) return esc(str);
  return esc(str.substring(0, max)) + '<span class="text-clipped">…</span>';
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
        <span class="more-closed more-text">Show ${rest.length} more URL${rest.length > 1 ? 's' : ''}</span>
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
  const cwe      = cweId > 0 ? `<a class="badge meta-badge" href="https://cwe.mitre.org/data/definitions/${cweId}.html" target="_blank">CWE-${cweId}</a>` : '';
  const wascId   = parseInt(alert.wascid, 10);
  const wasc     = wascId > 0 ? `<span class="badge meta-badge">WASC-${wascId}</span>` : '';

  const refs = (alert.reference || '')
    .replace(/<[^>]+>/g, ' ')
    .split(/\s+/)
    .map(r => r.trim())
    .filter(r => r.startsWith('http'))
    .slice(0, 3)
    .map(r => `<a href="${esc(r)}" target="_blank">${esc(r)}</a>`)
    .join('<br>');

  const owaspBadges = Object.entries(alert.tags || {})
    .filter(([k]) => /^OWASP_\d{4}_/.test(k))
    .map(([k, url]) => {
      const cat = k.replace(/^OWASP_\d{4}_/, '');
      return `<a class="badge owasp-badge" href="${esc(url)}" target="_blank">OWASP ${esc(cat)}</a>`;
    })
    .join('');

  return `
  <details class="finding" style="border-left-color:${risk.border};background:${risk.bg}">
    <summary class="finding-summary">
      <span class="chevron">&#9654;</span>
      <span class="finding-title">${esc(alert.name)}</span>
      <span class="finding-badges">
        <span class="badge risk-badge" style="background:${risk.pill}">${risk.label}</span>
        <span class="badge conf-badge">${esc(conf)}</span>
        ${cwe}${wasc}${owaspBadges}
        ${systemic ? `<span class="badge systemic-badge">Systemic</span>` : ''}
        ${alert.count > 0 ? `<span class="instance-count">${alert.count} URL${alert.count !== 1 ? 's' : ''}</span>` : ''}
      </span>
    </summary>

    <div class="finding-body">

      ${(() => {
        const enriched = enrichDescription(alert.name);
        const zapDesc  = alert.desc || '';
        return `
      <div class="finding-section">
        <div class="section-label">Description</div>
        <div class="section-content desc-content">${enriched || zapDesc || '<em>No description.</em>'}</div>
      </div>
      ${enriched && zapDesc ? `
      <div class="finding-section">
        <div class="section-label">Technical detail from ZAP</div>
        <div class="section-content desc-content">${zapDesc}</div>
      </div>` : ''}`;
      })()}

      ${alert.solution ? `
      <div class="finding-section">
        <div class="section-label">How to fix</div>
        <div class="section-content">${formatSolution(alert.solution)}</div>
      </div>` : ''}

      ${alert.instances.length ? `
      <div class="finding-section">
        <div class="section-label">Affected URLs <span class="url-label-count">${alert.count} URLs</span>${alert.inputvector ? `<span class="inputvec-label">via ${esc(alert.inputvector)}</span>` : ''}</div>
        ${renderInstances(alert.instances)}
      </div>` : ''}

      ${alert.otherinfo ? `
      <div class="finding-section">
        <div class="section-label">Additional Info</div>
        <div class="section-content desc-content">${alert.otherinfo}</div>
      </div>` : ''}

      ${refs ? `
      <div class="finding-section refs-section">
        <div class="section-label">External References</div>
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

function generateReport(raw, opts = {}) {
  const alerts    = parseAlerts(raw);
  const title     = opts.title || 'Security Scan Report';
  const now       = formatLocalTimestamp();
  const generated = (raw['@generated'] || now).replace(/\s*\(UTC[^)]*\)$/, '') + ' ' + localUtcOffset();

  const sites  = (raw.site || []).map(s => s['@name'] || s['@host'] || '').filter(Boolean);
  const target = sites.join(', ') || 'Unknown';

  const counts = { 3: 0, 2: 0, 1: 0, 0: 0 };
  alerts.forEach(a => { counts[a.riskcode] = (counts[a.riskcode] || 0) + 1; });

  const totalAlerts    = alerts.length;
  const totalInstances = alerts.reduce((n, a) => n + a.count, 0);
  const hasFindings    = totalAlerts > 0;

  const byRisk = [3, 2, 1, 0].map(rc => {
    const group = alerts.filter(a => a.riskcode === rc);
    if (!group.length) return '';
    const risk = RISK[rc];
    return `
    <div class="risk-section" data-risk="${risk.label.toLowerCase()}">
      <div class="risk-heading" style="border-left-color:${risk.border}">
        <span class="risk-pill" style="background:${risk.pill}">${risk.label}</span>
        <span class="risk-count">${group.length} finding${group.length !== 1 ? 's' : ''}</span>
      </div>
      ${group.map(renderAlert).join('\n')}
    </div>`;
  }).join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)}</title>
<link rel="icon" type="image/svg+xml" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'><path fill='%231565c0' d='M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4z'/><path fill='%23fff' d='M10 17l-4-4 1.41-1.41L10 14.17l6.59-6.59L18 9l-8 8z'/></svg>">
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;font-size:14px;line-height:1.6;color:#212121;background:#f0f2f5}
a{color:#1565c0;text-decoration:none}
a:hover{text-decoration:underline}

header{background:linear-gradient(135deg,#1a237e,#283593);color:#fff;padding:28px 40px}
header h1{font-size:20px;font-weight:700;letter-spacing:.3px}
header .meta{font-size:12px;opacity:.75;margin-top:6px}
header .meta span{margin-right:20px}

.container{max-width:960px;margin:0 auto;padding:32px 20px}

.report-intro{background:#fff;border-radius:10px;box-shadow:0 1px 4px rgba(0,0,0,.08);padding:18px 24px;margin-bottom:24px;font-size:13px;color:#37474f;line-height:1.8;border-left:4px solid #1565c0}

/* Summary cards */
.summary{display:flex;gap:12px;margin-bottom:24px;flex-wrap:wrap}
.summary-card{flex:1;min-width:100px;background:#fff;border-radius:10px;padding:20px 12px;text-align:center;box-shadow:0 1px 4px rgba(0,0,0,.08)}
.summary-card .num{font-size:38px;font-weight:800;line-height:1}
.summary-card .lbl{font-size:10px;text-transform:uppercase;letter-spacing:.8px;font-weight:700;margin-top:5px;color:#757575;display:inline-flex;align-items:center;gap:4px;justify-content:center}
.card-h .num{color:#c62828}
.card-m .num{color:#d97706}
.card-l .num{color:#9e9d24}
.card-i .num{color:#1565c0}
.card-total .num{color:#37474f}
.card-endpoints .num{color:#00695c}
.info-icon{display:inline-block;width:14px;height:14px;border-radius:50%;background:#b0bec5;cursor:default;position:relative;flex-shrink:0}
.info-icon::before{content:'';position:absolute;width:2px;height:2px;background:#fff;border-radius:50%;top:2px;left:50%;transform:translateX(-50%)}
.info-icon::after{content:'';position:absolute;width:2px;height:5px;background:#fff;border-radius:1px;bottom:2px;left:50%;transform:translateX(-50%)}
.info-icon:hover .info-tooltip{display:block}
.info-tooltip{display:none;position:absolute;bottom:calc(100% + 6px);left:50%;transform:translateX(-50%);background:#37474f;color:#fff;font-size:11px;font-weight:400;padding:7px 10px;border-radius:6px;width:220px;line-height:1.5;z-index:10;pointer-events:none;box-shadow:0 2px 8px rgba(0,0,0,.2);text-transform:none;letter-spacing:normal;white-space:normal}
.info-tooltip::after{content:'';position:absolute;top:100%;left:50%;transform:translateX(-50%);border:5px solid transparent;border-top-color:#37474f}

/* Meta section */
.meta-section{background:#fff;border-radius:10px;box-shadow:0 1px 4px rgba(0,0,0,.08);padding:20px 24px;margin-bottom:24px}
.meta-section-title{font-size:11px;text-transform:uppercase;letter-spacing:.7px;color:#9e9e9e;font-weight:700;margin-bottom:14px}
.config-row{display:flex;border-bottom:1px solid #f5f5f5;padding:8px 0}
.config-row:last-child{border-bottom:none}
.config-key{font-size:12px;color:#757575;font-weight:600;width:150px;flex-shrink:0}
.config-val{font-size:13px;color:#212121}

/* Risk summary prescan items */
.prescan-list{display:flex;flex-direction:column;gap:8px}
.prescan-item{display:flex;align-items:flex-start;gap:12px;padding:11px 14px;border-left:4px solid;border-radius:0 8px 8px 0;background:#fff;box-shadow:0 1px 3px rgba(0,0,0,.06)}
.prescan-item.action{border-color:#e53935}
.prescan-item.review{border-color:#1976d2}
.prescan-item.clear{border-color:#43a047}
.prescan-status{font-size:10px;font-weight:700;padding:3px 8px;border-radius:4px;white-space:nowrap;flex-shrink:0;margin-top:2px}
.prescan-item.action .prescan-status{background:#ffebee;color:#c62828}
.prescan-item.review .prescan-status{background:#e3f2fd;color:#1565c0}
.prescan-item.clear  .prescan-status{background:#e8f5e9;color:#2e7d32}
.prescan-check{font-size:13px;font-weight:600;color:#212121}
.prescan-detail{font-size:12px;color:#9e9e9e;margin-top:2px}

/* Risk section headings */
.risk-section{margin-bottom:32px}
.risk-heading{font-size:14px;font-weight:700;padding:10px 16px;border-left:4px solid;margin-bottom:12px;display:flex;align-items:center;gap:10px;background:#fff;border-radius:0 8px 8px 0;box-shadow:0 1px 3px rgba(0,0,0,.07)}
.risk-pill{color:#fff;font-size:11px;padding:3px 10px;border-radius:10px;font-weight:700}
.risk-count{color:#616161;font-weight:400}

/* Finding cards */
.finding{border-left:4px solid #e0e0e0;border-radius:0 10px 10px 0;margin-bottom:10px;box-shadow:0 1px 4px rgba(0,0,0,.07);overflow:hidden}
.finding-summary{padding:14px 18px;cursor:pointer;display:flex;align-items:center;gap:10px;list-style:none;user-select:none}
.finding-summary::-webkit-details-marker{display:none}
.chevron{font-size:10px;color:#bdbdbd;flex-shrink:0;transition:transform .15s;display:inline-block}
details.finding[open] .chevron{transform:rotate(90deg)}
.finding-title{font-weight:600;font-size:14px;flex:1;color:#212121}
.finding-badges{display:flex;align-items:center;gap:6px;flex-wrap:wrap;flex-shrink:0}
.instance-count{font-size:12px;color:#9e9e9e;white-space:nowrap;margin-left:4px}

.badge{font-size:11px;padding:2px 8px;border-radius:4px;font-weight:600;white-space:nowrap}
a.badge{cursor:pointer}
.risk-badge{color:#fff}
.conf-badge{background:#f5f5f5;color:#616161}
.meta-badge{background:#e8eaf6;color:#3949ab}
a.meta-badge:hover{background:#c5cae9}

/* Finding body - single column */
.finding-body{padding:0 18px 18px;display:flex;flex-direction:column;gap:0;border-top:1px solid #f5f5f5}
.finding-section{padding:14px 0;border-bottom:1px solid #f9f9f9}
.finding-section:last-child{border-bottom:none;padding-bottom:0}
.section-label{font-size:10px;text-transform:uppercase;letter-spacing:.7px;color:#9e9e9e;font-weight:700;margin-bottom:8px;display:flex;align-items:center;gap:8px}
.url-label-count{background:#eeeeee;color:#616161;font-size:10px;font-weight:700;padding:1px 7px;border-radius:10px;letter-spacing:0;text-transform:none}
.section-content{font-size:13px;color:#37474f;line-height:1.7}
.section-content p{margin-bottom:6px}
.section-content p:last-child{margin-bottom:0}
.section-content ul{padding-left:18px}
.section-content li{margin-bottom:4px}
.solution-list{padding-left:18px;display:flex;flex-direction:column;gap:6px}
.solution-list li{font-size:13px;color:#37474f;line-height:1.6}
.desc-content{background:#fafafa;border-radius:6px;padding:12px 14px}
.desc-enriched{font-size:13px;color:#37474f;line-height:1.7;margin-bottom:8px}
.desc-technical{margin-top:8px}
.desc-technical-toggle{display:inline-flex;align-items:center;gap:6px;cursor:pointer;list-style:none;user-select:none;padding:4px 10px;border:1px solid #e0e0e0;border-radius:4px;background:#f5f5f5;transition:background .15s}
.desc-technical-toggle::-webkit-details-marker{display:none}
.desc-technical-toggle:hover{background:#eeeeee}
.desc-technical-label{font-size:11px;color:#757575;font-weight:600}
.desc-tech-chevron{font-size:9px;color:#90a4ae;transition:transform .2s;display:inline-block}
details.desc-technical[open] .desc-tech-chevron{transform:rotate(180deg)}
.desc-technical-body{font-size:12px;color:#9e9e9e;margin-top:8px;line-height:1.6;padding:10px 12px;border-left:2px solid #e0e0e0;background:#fafafa;border-radius:0 4px 4px 0}
.refs-section{margin-top:0}
.refs-content{font-size:12px;line-height:1.8}

/* URL list */
.url-list{list-style:none;display:flex;flex-direction:column;gap:6px;margin-top:2px}
.url-list li{background:#fafafa;border:1px solid #eeeeee;border-radius:6px;padding:8px 12px;font-size:12px}
.url-row{display:flex;align-items:center;gap:6px;flex-wrap:wrap}
.http-method{font-weight:700;font-size:10px;padding:2px 6px;background:#e8eaf6;color:#283593;border-radius:3px;flex-shrink:0}
.uri{color:#37474f;word-break:break-all;flex:1}
.uri-clipped,.text-clipped{color:#bdbdbd;font-style:italic}
.param-tag{font-size:10px;background:#fce4ec;color:#b71c1c;padding:1px 6px;border-radius:3px;flex-shrink:0}
.instance-detail{margin-top:6px;font-size:11px;color:#757575;padding-top:5px;border-top:1px dashed #eeeeee}
.instance-detail code{background:#f5f5f5;padding:1px 5px;border-radius:3px;font-family:'Consolas','Monaco',monospace;font-size:11px;word-break:break-all;color:#37474f}
.instance-other{font-style:italic}
.no-instances{color:#9e9e9e;font-size:12px;font-style:italic}
.instances-wrap{display:flex;flex-direction:column;gap:6px}
.more-instances-toggle{display:inline-flex;align-items:center;gap:5px;font-size:12px;color:#1565c0;cursor:pointer;list-style:none;user-select:none;padding:2px 0}
.more-instances-toggle::-webkit-details-marker{display:none}
.more-instances-toggle:hover .more-text{text-decoration:underline}
.more-chevron{font-size:9px;transition:transform .2s;display:inline-block}
details.more-instances[open] .more-chevron{transform:rotate(180deg)}
.more-closed{display:inline}.more-open{display:none}
details.more-instances[open] .more-closed{display:none}
details.more-instances[open] .more-open{display:inline}
.url-list-more{border-radius:6px}

.no-findings{text-align:center;padding:60px;color:#388e3c;font-size:18px;font-weight:600;background:#fff;border-radius:10px;box-shadow:0 1px 4px rgba(0,0,0,.08)}

/* How to read legend */
.legend{background:#fff;border-radius:10px;box-shadow:0 1px 4px rgba(0,0,0,.07);margin-bottom:28px;overflow:hidden}
.legend-summary{padding:13px 18px;cursor:pointer;font-size:13px;font-weight:600;color:#546e7a;list-style:none;user-select:none;display:flex;align-items:center;gap:8px}
.legend-summary::-webkit-details-marker{display:none}
.legend-summary:hover{background:#fafafa}
.legend-chevron{font-size:10px;color:#b0bec5;transition:transform .15s;display:inline-block}
details.legend[open] .legend-chevron{transform:rotate(90deg)}
.legend-body{border-top:1px solid #f0f0f0;padding:20px}
.legend-group-title{font-size:10px;text-transform:uppercase;letter-spacing:.7px;color:#9e9e9e;font-weight:700;margin-bottom:12px}

.risk-legend{display:flex;flex-direction:column;gap:8px;margin-bottom:24px}
.risk-legend-row{display:flex;align-items:center;gap:14px;padding:10px 14px;border-left:4px solid;border-radius:0 8px 8px 0;background:#fafafa}
.risk-legend-name{font-size:12px;font-weight:700;width:88px;flex-shrink:0}
.risk-legend-action{font-size:10px;font-weight:700;padding:2px 8px;border-radius:10px;white-space:nowrap;flex-shrink:0}
.risk-legend-desc{font-size:12px;color:#616161;line-height:1.5}

.conf-legend{display:grid;grid-template-columns:repeat(4,1fr);gap:8px}
.conf-card{background:#f5f5f5;border-radius:8px;padding:10px 12px}
.systemic-badge{background:#f3e5f5;color:#7b1fa2;font-size:11px;padding:2px 8px;border-radius:4px;font-weight:600}
.owasp-badge{background:#e8f5e9;color:#2e7d32}
a.owasp-badge:hover{background:#c8e6c9}
.inputvec-label{font-size:10px;font-weight:600;color:#00695c;background:#e0f2f1;padding:1px 8px;border-radius:10px;margin-left:6px;letter-spacing:0;text-transform:none}
.filter-bar{display:flex;gap:8px;margin-bottom:20px;flex-wrap:wrap}
.filter-btn{font-size:12px;font-weight:600;padding:5px 14px;border-radius:20px;border:2px solid #e0e0e0;background:#fff;color:#546e7a;cursor:pointer;transition:all .15s}
.filter-btn:hover{border-color:#b0bec5;color:#37474f}
.filter-btn.active{border-color:#1565c0;background:#1565c0;color:#fff}
.conf-card-label{font-size:11px;font-weight:700;color:#37474f;margin-bottom:4px}
.conf-card-desc{font-size:11px;color:#757575;line-height:1.4}
@media(max-width:640px){.conf-legend{grid-template-columns:1fr 1fr}}
.badge-legend{display:flex;flex-direction:column;gap:10px}
.badge-legend-item{display:flex;align-items:center;gap:12px}
.badge-legend-desc{font-size:12px;color:#616161;line-height:1.5}

/* Findings section divider */
.findings-header{font-size:11px;text-transform:uppercase;letter-spacing:.7px;color:#9e9e9e;font-weight:700;margin-bottom:16px;padding-bottom:8px;border-bottom:1px solid #e8e8e8}

/* Finding hover */
.finding-summary:hover{background:#fafafa}

footer{text-align:center;padding:24px;color:#bdbdbd;font-size:12px;border-top:1px solid #e8e8e8;margin-top:12px}

@media(max-width:600px){
  header{padding:20px}
  .finding-badges{display:none}
  .summary-card .num{font-size:28px}
}
@media print{
  body{background:#fff}
  .container{padding:20px 0 0;max-width:100%}
  header{-webkit-print-color-adjust:exact;print-color-adjust:exact}
  details.finding{overflow:visible!important}
  .more-instances-toggle,.filter-bar{display:none!important}
  .findings-header{display:block!important}
  .finding-badges{display:flex!important}
  .finding,.meta-section,.summary-card,.prescan-item,.legend,.risk-section{box-shadow:none;-webkit-print-color-adjust:exact;print-color-adjust:exact}
  .summary{display:flex!important}
  .summary-card{border:1px solid #e0e0e0!important}
  .info-icon,.no-print{display:none!important}
  @page{margin:1.2cm;size:A4}
}
</style>
</head>
<body>

<header>
  <h1>${esc(title)}</h1>
  <div class="meta">
    <span>Generated: ${esc(generated)}</span>
    <span>Target: ${esc(target)}</span>
  </div>
</header>

<div class="container">

  <div class="report-intro">
    This report presents the results of an automated security scan performed against <strong>${esc(target)}</strong> using OWASP ZAP,
    an industry-standard security testing tool. The scan actively tests the target for security weaknesses.
    Findings are grouped by severity. <strong>High</strong> and <strong>Medium</strong> findings require immediate attention.
    Low and informational findings are worth reviewing but pose no immediate risk.
    ${!hasFindings ? '<br><br>No security findings were identified. The target appears clean under the tested conditions.' : ''}
  </div>

  <div class="summary">
    <div class="summary-card card-h">
      <div class="num">${counts[3]}</div>
      <div class="lbl">High</div>
    </div>
    <div class="summary-card card-m">
      <div class="num">${counts[2]}</div>
      <div class="lbl">Medium</div>
    </div>
    <div class="summary-card card-l">
      <div class="num">${counts[1]}</div>
      <div class="lbl">Low</div>
    </div>
    <div class="summary-card card-i">
      <div class="num">${counts[0]}</div>
      <div class="lbl">Info</div>
    </div>
    <div class="summary-card card-total">
      <div class="num">${totalAlerts}</div>
      <div class="lbl">Total</div>
    </div>
    <div class="summary-card card-endpoints">
      <div class="num">${totalInstances}</div>
      <div class="lbl">Affected URLs<span class="info-icon"><span class="info-tooltip">Total number of affected URLs across all findings. One finding can affect multiple URLs.</span></span></div>

    </div>
  </div>

  <details class="legend" open>
    <summary class="legend-summary">
      <span class="legend-chevron">&#9654;</span>
      How to read this report
    </summary>
    <div class="legend-body">

      <div class="legend-group-title">Risk Level</div>
      <div class="risk-legend">
        <div class="risk-legend-row" style="border-color:#e53935">
          <span class="risk-legend-name" style="color:#c62828">High</span>
          <span class="risk-legend-action" style="background:#ffebee;color:#c62828">Fix immediately</span>
          <span class="risk-legend-desc">Serious vulnerability that could be actively exploited. Prioritised for resolution before the next release.</span>
        </div>
        <div class="risk-legend-row" style="border-color:#f59e0b">
          <span class="risk-legend-name" style="color:#d97706">Medium</span>
          <span class="risk-legend-action" style="background:#fffbeb;color:#d97706">Fix this sprint</span>
          <span class="risk-legend-desc">Notable security issue. Recommended to address in the current or next sprint.</span>
        </div>
        <div class="risk-legend-row" style="border-color:#cddc39">
          <span class="risk-legend-name" style="color:#9e9d24">Low</span>
          <span class="risk-legend-action" style="background:#f9fbe7;color:#9e9d24">Schedule</span>
          <span class="risk-legend-desc">Minor issue with low immediate risk. Suggested to plan into a future sprint.</span>
        </div>
        <div class="risk-legend-row" style="border-color:#1976d2">
          <span class="risk-legend-name" style="color:#1565c0">Informational</span>
          <span class="risk-legend-action" style="background:#e3f2fd;color:#1565c0">Review</span>
          <span class="risk-legend-desc">No direct risk. Flagged for awareness. Useful context for developers and architects.</span>
        </div>
      </div>

      <div class="legend-group-title">Confidence</div>
      <div class="conf-legend">
        <div class="conf-card">
          <div class="conf-card-label">High</div>
          <div class="conf-card-desc">Very likely a real issue. Near-certain or manually verified.</div>
        </div>
        <div class="conf-card">
          <div class="conf-card-label">Medium</div>
          <div class="conf-card-desc">Probably real. Worth investigating before dismissing.</div>
        </div>
        <div class="conf-card">
          <div class="conf-card-label">Low</div>
          <div class="conf-card-desc">Possible issue. Needs manual verification before taking action.</div>
        </div>
        <div class="conf-card">
          <div class="conf-card-label">False Positive</div>
          <div class="conf-card-desc">Scanner flagged it but it is not a real vulnerability.</div>
        </div>
      </div>

      <div class="legend-group-title" style="margin-top:20px">Reference Badges</div>
      <div class="badge-legend">
        <div class="badge-legend-item">
          <span class="badge meta-badge">CWE-[ID]</span>
          <span class="badge-legend-desc">Common Weakness Enumeration. An industry-standard ID for the vulnerability class. <span class="no-print">Click to open the full definition and remediation guidance.</span></span>
        </div>
        <div class="badge-legend-item">
          <span class="badge meta-badge">WASC-[ID]</span>
          <span class="badge-legend-desc">Web Application Security Consortium threat classification. Used as a reference category.</span>
        </div>
        <div class="badge-legend-item">
          <span class="badge systemic-badge">Systemic</span>
          <span class="badge-legend-desc">The vulnerability was found across multiple endpoints, indicating a systemic issue in how the application is built rather than an isolated mistake. These require a fix at the root level, not just patching individual URLs.</span>
        </div>
        <div class="badge-legend-item">
          <span class="badge owasp-badge">OWASP A[XX]</span>
          <span class="badge-legend-desc">Maps this finding to an OWASP Top 10 category, the industry-standard list of the most critical web security risks. <span class="no-print">Click to open the official OWASP description.</span></span>
        </div>
      </div>

    </div>
  </details>

  ${hasFindings ? `
  <div class="findings-header">Findings</div>
  <div class="filter-bar">
    <button class="filter-btn active" onclick="filterRisk('all')">All</button>
    ${counts[3] > 0 ? `<button class="filter-btn" onclick="filterRisk('high')" style="--c:#c62828">High</button>` : ''}
    ${counts[2] > 0 ? `<button class="filter-btn" onclick="filterRisk('medium')" style="--c:#d97706">Medium</button>` : ''}
    ${counts[1] > 0 ? `<button class="filter-btn" onclick="filterRisk('low')" style="--c:#9e9d24">Low</button>` : ''}
    ${counts[0] > 0 ? `<button class="filter-btn" onclick="filterRisk('informational')" style="--c:#1565c0">Informational</button>` : ''}
  </div>
  ${byRisk}
  <script>
    function filterRisk(level) {
      document.querySelectorAll('.risk-section').forEach(s => {
        s.style.display = (level === 'all' || s.dataset.risk === level) ? '' : 'none';
      });
      document.querySelectorAll('.filter-btn').forEach(b => {
        b.classList.toggle('active', b.textContent.toLowerCase() === level || (level === 'all' && b.textContent === 'All'));
      });
    }

    (function () {
      var saved = [];
      function openAll() {
        saved = [];
        document.querySelectorAll('details').forEach(function (d) {
          saved.push(d.open);
          d.open = true;
        });
      }
      function restoreAll() {
        document.querySelectorAll('details').forEach(function (d, i) {
          d.open = saved[i] !== undefined ? saved[i] : false;
        });
      }
      window.addEventListener('beforeprint', openAll);
      window.addEventListener('afterprint',  restoreAll);
    })();
  </script>` : '<div class="no-findings">&#10003;&nbsp; No security findings identified.</div>'}

</div>

<footer>ZAP ${esc(raw['@version'] || 'Unknown')} &bull; Generated by zap-clean-report</footer>
</body>
</html>`;
}

module.exports = { generateReport };
