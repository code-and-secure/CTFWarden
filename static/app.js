'use strict';
// Every value shown here can come from attackers (user agents, paths, container names) -> always esc().
const $ = s => document.querySelector(s);
const esc = v => String(v ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const hb = n => { if (n == null) return '–'; n = +n; const u = ['B','KB','MB','GB','TB']; let i = 0; while (n >= 1024 && i < 4) { n /= 1024; i++; } return n.toFixed(i ? 1 : 0) + ' ' + u[i]; };
const ago = t => { if (!t) return '–'; const s = Math.max(0, Date.now() / 1000 - t); if (s < 60) return Math.round(s) + 's ago'; if (s < 3600) return Math.round(s / 60) + 'm ago'; if (s < 86400) return (s / 3600).toFixed(1) + 'h ago'; return (s / 86400).toFixed(1) + 'd ago'; };
const tm = t => t ? new Date(t * 1000).toLocaleString() : '–';
const when = t => `<span title="${esc(tm(t))}">${ago(t)}</span>`;
const R = {'': -1, info: 0, low: 1, medium: 2, high: 3};
const sev = s => s ? `<span class="b ${esc(s)}">${esc(s)}</span>` : '';
const ipl = ip => `<a data-ip="${esc(ip)}">${esc(ip)}</a>`;
const ctl = n => `<a data-ct="${esc(n)}">${esc(n)}</a>`;
const looksIP = s => /^[0-9a-f:.]+$/i.test(s || '') && /[.:]/.test(s);
const tgt = (t, ty) => (ty === 'ip' || (!ty && looksIP(t))) ? ipl(t) : (ty === 'container' ? ctl(t) : esc(t));
const pct = (v, warn = 80) => v == null ? '–' : `${(+v).toFixed(1)}%<span class="bar"><i style="width:${Math.min(100, v)}%;background:${v >= warn ? 'var(--high)' : 'var(--accent)'}"></i></span>`;
const pairs = (o, link) => Object.entries(o || {}).map(([k, n]) => `${link ? link(k) : esc(k)}<span class="muted">×${n}</span>`).join(', ');

const S = {tab: 'overview', data: {}, sort: {}, susp: false, modal: null, page: {}, size: 25};

async function api(p) {
  const r = await fetch(p, {cache: 'no-store', credentials: 'same-origin'});
  if (r.status === 401) { location.replace('/login'); throw new Error('login required'); }
  if (!r.ok) throw new Error(p + ' → HTTP ' + r.status);
  return r.json();
}

function pager(id, cur, pages, from, total) {
  const nums = [];
  for (let p = 1; p <= pages; p++) {
    if (p === 1 || p === pages || Math.abs(p - cur) <= 1) nums.push(p);
    else if (nums[nums.length - 1] !== '…') nums.push('…');
  }
  const btn = p => `<button data-pg="${id}:${p}" class="${p === cur ? 'on' : ''}" ${p === cur ? 'aria-current="page"' : ''}>${p}</button>`;
  return `<div class="pager">
      <span class="muted">${total ? from + 1 : 0}–${Math.min(from + S.size, total)} of ${total}</span>
      <div class="pages">
        <button data-pg="${id}:${cur - 1}" ${cur <= 1 ? 'disabled' : ''}>‹ Prev</button>
        ${nums.map(n => n === '…' ? '<span class="muted">…</span>' : btn(n)).join('')}
        <button data-pg="${id}:${cur + 1}" ${cur >= pages ? 'disabled' : ''}>Next ›</button>
      </div>
      <label class="muted">Rows <select data-psz>${[10, 25, 50, 100].map(n => `<option value="${n}" ${n === S.size ? 'selected' : ''}>${n}</option>`).join('')}</select></label>
    </div>`;
}

function grid(id, cols, rows, opt = {}) {
  rows = rows || [];
  const f = opt.nofilter ? '' : $('#filter').value.trim().toLowerCase();
  if (f) rows = rows.filter(x => JSON.stringify(x).toLowerCase().includes(f));
  const s = S.sort[id];
  if (s) {
    const c = cols.find(c => c.k === s.k), v = c.v || (x => x[c.k]);
    rows = [...rows].sort((a, b) => { const A = v(a) ?? -1e18, B = v(b) ?? -1e18; return (A > B ? 1 : A < B ? -1 : 0) * s.d; });
  }
  let shown = rows, more = '', pg = '';
  if (opt.nofilter) {                       // small fixed lists (overview, detail views): no paging
    const max = opt.max || 2000;
    shown = rows.slice(0, max);
    if (rows.length > max) more = `<p class="muted">showing ${max} of ${rows.length} rows – use the filter</p>`;
  } else {
    const pages = Math.max(1, Math.ceil(rows.length / S.size));
    const cur = Math.min(Math.max(1, S.page[id] || 1), pages);
    const from = (cur - 1) * S.size;
    shown = rows.slice(from, from + S.size);
    pg = pager(id, cur, pages, from, rows.length);
  }
  const head = cols.map(c => `<th data-k="${c.k}">${esc(c.l)}${s && s.k === c.k ? (s.d > 0 ? ' ▲' : ' ▼') : ''}</th>`).join('');
  const body = shown.map(x => `<tr>${cols.map(c => `<td class="${c.c || ''}" data-label="${esc(c.l)}">${c.f ? c.f(x) : esc(x[c.k])}</td>`).join('')}</tr>`).join('')
    || `<tr><td colspan="${cols.length}" class="muted">nothing yet</td></tr>`;
  return `<div class="wrap wide"><table data-grid="${id}"><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table></div>${more}${pg}`;
}

// ---------------------------------------------------------------- columns
const AL = [
  {k: 'ts', l: 'Time', f: x => when(x.ts)},
  {k: 'sev', l: 'Sev', f: x => sev(x.sev), v: x => R[x.sev]},
  {k: 'kind', l: 'Kind'},
  {k: 'target', l: 'Target', f: x => tgt(x.target, x.ttype)},
  {k: 'msg', l: 'Message', c: 'w'},
];
const IPC = [
  {k: 'ip', l: 'IP', f: x => ipl(x.ip) + (x.trusted ? ' <span class="b info">trusted</span>' : '')},
  {k: 'score', l: 'Score', f: x => `${x.score} ${sev(x.maxsev)}`},
  {k: 'geo', l: 'Location / network', c: 'geo', f: x => geoCell(x.geo), v: x => x.geo ? (x.geo.cc || '') + (x.geo.org || '') : ''},
  {k: 'ssh_fails', l: 'SSH fails', v: x => x.ssh_fails || 0, f: x => x.ssh_fails || ''},
  {k: 'total', l: 'HTTP req'}, {k: 'conns', l: 'TCP sess'}, {k: 's4xx', l: '4xx'}, {k: 's404', l: '404'}, {k: 'peak', l: 'Peak/min'},
  {k: 'reasons', l: 'Reasons', c: 'w', f: x => pairs(x.reasons), v: x => Object.keys(x.reasons || {}).length},
  {k: 'containers', l: 'Targets', c: 'w', f: x => pairs(x.containers, ctl), v: x => Object.keys(x.containers || {}).length},
  {k: 'last', l: 'Last seen', f: x => when(x.last)},
  {k: 'last_req', l: 'Last request', c: 'w'},
];
const flagEmoji = cc => /^[A-Z]{2}$/.test(cc || '') ? String.fromCodePoint(...[...cc].map(c => 0x1F1A5 + c.charCodeAt(0))) : '';
const tagBadge = t => `<span class="b ${/^(Tor|VPN|proxy)/.test(t) ? 'high' : /^abuse/.test(t) ? 'medium' : 'info'}">${esc(t)}</span>`;
const geoCell = g => !g ? '<span class="muted">…</span>' :
  `${flagEmoji(g.cc)} ${esc(g.cc || '?')} <span class="muted">${esc(g.city || '')}</span> · ${esc(g.org || '')} ${(g.tags || []).map(tagBadge).join('')}`;
const yes = (v, label) => v ? `<span class="b high">${esc(label)}</span>` : '';
const ext = (u, t) => `<a href="${esc(u)}" target="_blank" rel="noopener noreferrer">${esc(t)}</a>`;

function intelBlock(ip, t, i) {
  if (!t || !t.public) return `<h3>Who is this</h3><p class="muted">private / local / trusted address – no lookup.</p>`;
  if (!t.intel_on) return `<h3>Who is this</h3><p class="muted">lookups disabled (CTFMON_INTEL=0).</p>`;
  const tags = [];
  if (t.tor || t.ab_tor) tags.push('<span class="b high">Tor exit node</span>');
  if (t.vpn_name || String(t.pc_type || '').toUpperCase() === 'VPN') tags.push(`<span class="b high">VPN${t.vpn_name ? ': ' + esc(t.vpn_name) : ''}</span>`);
  else if (t.proxy || t.pc_proxy === 'yes') tags.push('<span class="b high">proxy / VPN</span>');
  if (t.hosting) tags.push('<span class="b medium">datacenter / cloud server</span>');
  if (t.mobile) tags.push('<span class="b info">mobile network</span>');
  if (!tags.length && t.cc) tags.push('<span class="b ok">looks residential / ISP</span>');
  const loc = [t.city, t.zip, t.region, t.country].filter(Boolean).join(', ');
  const map = t.lat != null ? ext(`https://www.openstreetmap.org/?mlat=${t.lat}&mlon=${t.lon}#map=10/${t.lat}/${t.lon}`, `${t.lat}, ${t.lon}`) + ' <span class="muted">(approximate – city level at best)</span>' : '–';
  const ssh = i.ssh || null;
  const sshRows = ssh ? `
      <div>SSH failed attempts</div><div>${ssh.fails || 0} <span class="muted">(${tm(ssh.first)} → ${tm(ssh.last)})</span></div>
      <div>Usernames tried</div><div>${pairs(ssh.users) || '–'}</div>
      <div>Successful logins</div><div>${(ssh.logins || []).map(l => `<span class="bad">${esc(l.user)}</span> via ${esc(l.method)} ${esc(l.key)} <span class="muted">${tm(l.ts)}</span>`).join('<br>') || '<span class="ok">none</span>'}</div>
      <div>SSH client notes</div><div>${(ssh.notes || []).map(esc).join('<br>') || '–'}</div>` : '';
  return `<h3>Who is this</h3><div class="kv">
      <div>Location</div><div>${flagEmoji(t.cc)} ${esc(loc || t.geo_error || 'looking up…')} ${t.continent ? `<span class="muted">(${esc(t.continent)})</span>` : ''}</div>
      <div>Coordinates</div><div>${map}</div>
      <div>Timezone</div><div>${esc(t.tz || '–')}</div>
      <div>ISP</div><div>${esc(t.isp || '–')}</div>
      <div>Organisation</div><div>${esc(t.org || t.ab_domain || '–')}</div>
      <div>ASN</div><div>${esc(t.asn || '–')} ${t.asname ? `<span class="muted">${esc(t.asname)}</span>` : ''}</div>
      <div>Reverse DNS</div><div>${esc(t.rdns || t.rdns_local || (t.ab_hostnames || []).join(', ') || '–')}</div>
      <div>Connection type</div><div>${tags.join('')} ${t.pc_type ? `<span class="muted">proxycheck: ${esc(t.pc_type)}${t.pc_provider ? ' · ' + esc(t.pc_provider) : ''}${t.pc_risk != null ? ' · risk ' + esc(t.pc_risk) + '%' : ''}</span>` : ''}</div>
      ${t.vpn_name ? `<div>VPN provider</div><div>${t.vpn_url ? ext(t.vpn_url, t.vpn_name) : esc(t.vpn_name)} <span class="muted">${esc(t.vpn_anon || '')}</span></div>` : ''}
      ${t.pc_port ? `<div>Open proxy port</div><div>${esc(t.pc_port)} <span class="muted">${esc(t.pc_seen || '')}</span></div>` : ''}
      <div>Abuse reputation</div><div>${t.ab_score != null ? `<span class="b ${t.ab_score >= 50 ? 'high' : t.ab_score > 0 ? 'medium' : 'ok'}">${esc(t.ab_score)}% confidence</span> ${esc(t.ab_reports)} reports from ${esc(t.ab_users)} users${t.ab_last ? ', last ' + esc(t.ab_last) : ''} ${esc(t.ab_usage || '')}<br><span class="muted">${(t.ab_cats || []).map(esc).join(', ')}</span>` : '<span class="muted">add CTFMON_ABUSEIPDB_KEY for worldwide reports</span>'}</div>
      ${sshRows}
      <div>Look it up</div><div>${ext('https://www.abuseipdb.com/check/' + ip, 'AbuseIPDB')} · ${ext('https://www.shodan.io/host/' + ip, 'Shodan')} · ${ext('https://www.virustotal.com/gui/ip-address/' + ip, 'VirusTotal')} · ${ext('https://viz.greynoise.io/ip/' + ip, 'GreyNoise')} · ${ext('https://ipinfo.io/' + ip, 'ipinfo')} · ${ext('https://search.censys.io/hosts/' + ip, 'Censys')}</div>
      <div>Abuse contact</div><div>${ext('https://rdap.org/ip/' + ip, 'RDAP / WHOIS')} <span class="muted">– the ISP's abuse e-mail is listed there, report the attack to them</span></div>
    </div>`;
}

const CTC = [
  {k: 'name', l: 'Container', f: x => ctl(x.name) + (x.role === 'platform' ? ' <span class="b info">platform</span>' : '')},
  {k: 'image', l: 'Image'},
  {k: 'state', l: 'State', f: x => `<span class="${x.state === 'running' ? 'ok' : 'muted'}">${esc(x.state)}</span> <span class="muted">${esc(x.status)}</span>`},
  {k: 'cpu', l: 'CPU', f: x => pct(x.cpu)},
  {k: 'mem', l: 'Memory', f: x => x.mem == null ? '–' : `${hb(x.mem)} ${pct(x.mem_pct)}`},
  {k: 'pids', l: 'PIDs'},
  {k: 'net_rx', l: 'Net rx / tx', f: x => `${hb(x.net_rx)} / ${hb(x.net_tx)}`},
  {k: 'blk_w', l: 'Disk r / w', f: x => `${hb(x.blk_r)} / ${hb(x.blk_w)}`},
  {k: 'size_rw', l: 'Size rw / total', f: x => `${hb(x.size_rw)} / ${hb(x.size_root)}`},
  {k: 'accessors', l: 'Client IPs', f: x => `${x.accessors}${x.proxied ? ` <span class="muted">+${x.proxied} via proxy</span>` : ''}`},
  {k: 'last_access', l: 'Last access', f: x => when(x.last_access)},
  {k: 'ports', l: 'Ports', c: 'w', f: x => pub(x) + esc(x.ports), v: x => (x.public_ports || [])[0]},
  {k: 'risks', l: 'Risks', c: 'w', f: x => (x.risks || []).map(r => sev2(r.r, r.sev)).join(''), v: x => Math.max(-1, ...(x.risks || []).map(r => R[r.sev]))},
];
const pub = x => (x.public_ports || []).map(p => `<span class="b ok">public :${esc(p)}</span>`).join('') + ' ';
const sev2 = (t, s) => `<span class="b ${esc(s)}">${esc(t)}</span>`;
const EVC = [
  {k: 'ts', l: 'Time', f: x => when(x.ts)},
  {k: 'sev', l: 'Sev', f: x => sev(x.sev), v: x => R[x.sev]},
  {k: 'action', l: 'Action'},
  {k: 'container', l: 'Container', f: x => x.container === 'host' ? 'host' : ctl(x.container)},
  {k: 'image', l: 'Image'},
  {k: 'detail', l: 'Detail', c: 'w'},
];
const HIT = [
  {k: 'ts', l: 'Time', f: x => when(x.ts)},
  {k: 'sev', l: 'Sev', f: x => sev(x.sev), v: x => R[x.sev]},
  {k: 'ip', l: 'IP', f: x => ipl(x.ip)},
  {k: 'rule', l: 'Rule'},
  {k: 'target', l: 'Target', f: x => ctl(x.target)},
  {k: 'req', l: 'Request', c: 'w'},
  {k: 'ua', l: 'User agent', c: 'w'},
];
const ACC = [
  {k: 'ip', l: 'Client IP', f: x => ipl(x.ip)},
  {k: 'via', l: 'Path', f: x => ['localhost', 'host/proxy'].includes(x.via) ? `<span class="muted">${esc(x.via)}</span>` : esc(x.via)},
  {k: 'score', l: 'IP score'},
  {k: 'flows', l: 'Hits'},
  {k: 'first', l: 'First', f: x => when(x.first)},
  {k: 'last', l: 'Last', f: x => when(x.last)},
];
const LNK = [
  {k: 'src', l: 'From', f: x => ctl(x.src)},
  {k: 'dst', l: 'To', f: x => looksIP(x.dst) ? esc(x.dst) : ctl(x.dst)},
  {k: 'port', l: 'Port'},
  {k: 'flows', l: 'Connections'},
  {k: 'last', l: 'Last', f: x => when(x.last)},
];

// ---------------------------------------------------------------- views
function card(k, v, s, tone = '') { return `<div class="card ${tone}"><div class="k">${esc(k)}</div><div class="v">${esc(v)}</div><div class="s">${esc(s)}</div></div>`; }
const ICON_OK = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l7 3v5c0 4.5-3 8.2-7 10-4-1.8-7-5.5-7-10V6l7-3z"/><path d="M9 12l2 2 4-4"/></svg>';
const ICON_WARN = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l10 18H2L12 3z"/><path d="M12 10v5M12 18h.01"/></svg>';
const hero = c => c.suspicious > 0
  ? `<div class="hero danger"><div class="ic">${ICON_WARN}</div><div><b>${c.suspicious} suspicious ${c.suspicious === 1 ? 'IP' : 'IPs'} need a look</b><span>${c.alerts_1h} alerts in the last hour${c.high_1h ? ` · ${c.high_1h} high severity` : ''}</span></div></div>`
  : `<div class="hero calm"><div class="ic">${ICON_OK}</div><div><b>All quiet</b><span>No suspicious IPs right now · ${c.alerts_1h} alerts in the last hour</span></div></div>`;

const VIEWS = {
  overview: {url: () => '/api/overview', render: d => {
    const h = d.host || {}, c = d.counts, df = d.df || {};
    const memUsed = h.mem_total ? h.mem_total - h.mem_avail : null;
    const memPct = h.mem_total ? Math.round(100 * memUsed / h.mem_total) : null;
    const diskPct = h.disk_total ? Math.round(100 * (1 - h.disk_free / h.disk_total)) : null;
    const tone = v => v == null ? '' : v >= 90 ? 't-high' : v >= 75 ? 't-warn' : 't-ok';
    return `${hero(c)}<div class="cards">
      ${card('Host CPU', h.cpu == null ? '–' : h.cpu + '%', `${h.ncpu || '?'} cores · load ${(h.load || []).join(' ')}`, tone(h.cpu))}
      ${card('Host memory', memPct == null ? '–' : memPct + '%', `${hb(memUsed)} / ${hb(h.mem_total)}`, tone(memPct))}
      ${card('Host disk', diskPct == null ? '–' : diskPct + '%', `${hb(h.disk_free)} free`, tone(diskPct))}
      ${card('Docker disk', hb((df.images_size || 0) + (df.containers_rw || 0) + (df.volumes_size || 0)), `${df.images ?? '?'} images · ${df.volumes ?? '?'} volumes`)}
      ${card('Containers', `${c.running}/${c.total}`, `${c.challenges} challenge instances running`, 't-ok')}
      ${card('Requests', c.requests, `${c.req_per_min} last minute · ${c.sessions} TCP sessions`)}
      ${card('Unique IPs', c.ips, `${c.active_ips} active in 5 min`)}
      ${card('Suspicious IPs', c.suspicious, `score ≥ ${d.threshold}`, c.suspicious > 0 ? 't-high' : 't-ok')}
      ${card('Alerts (1h)', c.alerts_1h, `${c.high_1h} high`, c.high_1h > 0 ? 't-high' : '')}
    </div>
    <h3>Recent alerts</h3>${grid('ov-al', AL, d.alerts, {nofilter: 1})}
    <h3>Most suspicious IPs</h3>${grid('ov-ip', IPC, d.top_suspicious, {nofilter: 1})}
    <h3>Busiest containers</h3>${grid('ov-ct', CTC.slice(0, 7), d.top_cpu, {nofilter: 1})}
    <h3>Data sources</h3>${grid('ov-src', [{k: 'name', l: 'Source'}, {k: 'status', l: 'Status', c: 'w', f: x => `<span class="${String(x.status).startsWith('ok') ? 'ok' : 'bad'}">${esc(x.status)}</span>`}], d.sources, {nofilter: 1})}`;
  }},
  containers: {url: () => '/api/containers', render: d => grid('ct', CTC, d)},
  ips: {url: () => '/api/ips?limit=5000' + (S.susp ? '&suspicious=1' : ''), render: d =>
    `<div class="seg" role="group" aria-label="IP filter"><button data-susp="0" aria-pressed="${!S.susp}" class="${S.susp ? '' : 'on'}">All IPs</button><button data-susp="1" aria-pressed="${S.susp}" class="${S.susp ? 'on' : ''}">Suspicious only</button></div>${grid('ip', IPC, d)}`},
  alerts: {url: () => '/api/alerts?limit=1000', render: d => grid('al', AL, d)},
  events: {url: () => '/api/events?limit=2000', render: d => grid('ev', EVC, d)},
  hits: {url: () => '/api/hits?limit=2000', render: d => grid('hit', HIT, d)},
};

function render() { const d = S.data[S.tab]; if (d) $('#content').innerHTML = VIEWS[S.tab].render(d); }

async function load() {
  if (S.modal) return;                       // don't refresh under an open detail view
  const tab = S.tab;
  try {
    const d = await api(VIEWS[tab].url());
    S.data[tab] = d;
    if (tab === S.tab) render();
    $('#upd').textContent = 'updated ' + new Date().toLocaleTimeString();
    $('#live').classList.remove('off');
  } catch (e) {
    $('#upd').innerHTML = `<span class="bad">${esc(e.message)}</span>`;
    $('#live').classList.add('off');
  }
}

// ---------------------------------------------------------------- detail modals
function renderModal() {
  const m = S.modal; if (!m) return;
  const d = m.data;
  if (m.kind === 'ip') {
    const i = d.ip, v6 = String(i.ip).includes(':') ? 'ip6tables' : 'iptables';
    $('#mbody').innerHTML = `<h2>${esc(i.ip)} ${sev(i.maxsev)}</h2><div class="kv">
      <div>Score</div><div>${i.score ?? 0}${i.trusted ? ' <span class="b info">trusted</span>' : ''}</div>
      <div>First / last seen</div><div>${tm(i.first)} → ${tm(i.last)}</div>
      <div>Requests</div><div>${i.total ?? 0} HTTP, ${i.conns ?? 0} TCP sessions (4xx ${i.s4xx ?? 0}, 5xx ${i.s5xx ?? 0}, 404 ${i.s404 ?? 0}, peak ${i.peak ?? 0}/min)</div>
      <div>Reasons</div><div>${pairs(i.reasons) || '–'}</div>
      <div>Targets</div><div>${pairs(i.containers, ctl) || '–'}</div>
      <div>User agents</div><div>${(i.uas || []).map(esc).join('<br>') || '–'}</div>
      <div>Last request</div><div>${esc(i.last_req || '–')}</div>
      <div>Block it</div><div><code>${v6} -I DOCKER-USER -s ${esc(i.ip)} -j DROP</code> (containers)<br><code>${v6} -I INPUT -s ${esc(i.ip)} -j DROP</code> (host / SSH)</div>
    </div>
    ${intelBlock(i.ip, d.intel, i)}
    <h3>Containers this IP connected to</h3>${grid('m-acc', [{k: 'container', l: 'Container', f: x => ctl(x.container)}, ...ACC.slice(1)], d.access, {nofilter: 1})}
    <h3>Detections</h3>${grid('m-hit', HIT, d.hits, {nofilter: 1})}`;
  } else {
    const c = d.c;
    $('#mbody').innerHTML = `<h2>${esc(c.name)} <span class="b info">${esc(c.role)}</span></h2><div class="kv">
      <div>Image</div><div>${esc(c.image || '–')}</div>
      <div>State</div><div>${esc(c.state)} <span class="muted">${esc(c.status || '')}</span></div>
      <div>Created</div><div>${tm(c.created)}</div>
      <div>Container IPs</div><div>${esc((c.ips || []).join(', ') || '–')}</div>
      <div>Public (nginx)</div><div>${pub(c) || '–'}</div>
      <div>Ports</div><div>${esc(c.ports || '–')}</div>
      <div>CPU / memory / PIDs</div><div>${c.cpu ?? '–'}% · ${hb(c.mem)} of ${hb(c.mem_limit)} · ${c.pids ?? '–'}</div>
      <div>Disk (rw / total)</div><div>${hb(c.size_rw)} / ${hb(c.size_root)}</div>
      <div>Risks</div><div>${(c.risks || []).map(r => sev2(r.r, r.sev)).join('') || '–'}</div>
    </div>
    <h3>Who connected (${d.access.length})</h3>${grid('m-acc', ACC, d.access, {nofilter: 1})}
    <h3>Connections to / from other containers & internet</h3>${grid('m-lnk', LNK, d.links, {nofilter: 1})}
    <h3>Docker events</h3>${grid('m-ev', EVC, d.events, {nofilter: 1})}
    <h3>Web detections against it</h3>${grid('m-hit', HIT, d.hits, {nofilter: 1})}`;
  }
}

async function openModal(kind, key) {
  try {
    const data = await api(kind === 'ip' ? '/api/ip?ip=' + encodeURIComponent(key) : '/api/container?name=' + encodeURIComponent(key));
    S.modal = {kind, data};
    $('#modal').hidden = false;
    renderModal();
  } catch (e) { alert(e.message); }
}
function closeModal() { S.modal = null; $('#modal').hidden = true; load(); }

// ---------------------------------------------------------------- events
document.addEventListener('click', e => {
  if (e.target.id === 'modal' || e.target.id === 'close') return closeModal();
  const t = e.target.closest('[data-tab],[data-ip],[data-ct],th[data-k],[data-susp],[data-pg]');
  if (!t) return;
  if (t.dataset.tab) {
    S.tab = t.dataset.tab;
    document.querySelectorAll('#tabs button').forEach(b => b.classList.toggle('on', b === t));
    render(); load();
  } else if (t.dataset.ip) { openModal('ip', t.dataset.ip); }
  else if (t.dataset.ct) { openModal('ct', t.dataset.ct); }
  else if (t.dataset.susp !== undefined) { S.susp = t.dataset.susp === '1'; load(); }
  else if (t.dataset.pg) {
    const [id, n] = t.dataset.pg.split(':');
    S.page[id] = +n; render();
  }
  else if (t.dataset.k) {
    const id = t.closest('table').dataset.grid, cur = S.sort[id];
    S.sort[id] = {k: t.dataset.k, d: cur && cur.k === t.dataset.k ? -cur.d : -1};
    id.startsWith('m-') ? renderModal() : render();
  }
});
document.addEventListener('keydown', e => { if (e.key === 'Escape' && S.modal) closeModal(); });
$('#filter').addEventListener('input', () => { S.page = {}; render(); });
document.addEventListener('change', e => {
  if (e.target.dataset.psz !== undefined) { S.size = +e.target.value; S.page = {}; render(); }
});
$('#logout').addEventListener('click', async () => {
  await fetch('/api/logout', {method: 'POST', credentials: 'same-origin'}).catch(() => {});
  location.replace('/login');
});

load();
setInterval(load, 5000);
