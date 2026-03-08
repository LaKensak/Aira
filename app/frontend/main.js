/* AIRA Frontend — main.js (redesign chat IA) */

// ── Session ID (persistant dans localStorage) ─────────────
function getSessionId() {
  let id = localStorage.getItem('aira_session_id');
  if (!id) {
    id = crypto.randomUUID();
    localStorage.setItem('aira_session_id', id);
  }
  return id;
}
const SESSION_ID = getSessionId();

// ── Health check ──────────────────────────────────────────
async function checkHealth() {
  try {
    const r = await fetch('/api/health');
    if (r.ok) {
      const dot = document.getElementById('healthDot');
      dot.classList.add('ok');
      dot.title = 'API OK';
    }
  } catch (_) {}
}
checkHealth();

// ── Sidebar toggle ────────────────────────────────────────
document.getElementById('sidebarToggle').addEventListener('click', () => {
  document.getElementById('sidebar').classList.toggle('collapsed');
});

// ── Tabs ──────────────────────────────────────────────────
document.querySelectorAll('.tab').forEach(tab => {
  tab.addEventListener('click', () => {
    const name = tab.dataset.tab;
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
    tab.classList.add('active');
    const pane = document.getElementById('tab' + name.charAt(0).toUpperCase() + name.slice(1));
    if (pane) pane.classList.add('active');
  });
});

// ── Drag & drop / upload ──────────────────────────────────
const dropZone   = document.getElementById('dropZone');
const fileInput  = document.getElementById('fileInput');
const fileNameEl = document.getElementById('fileName');
const btnAnalyze = document.getElementById('btnAnalyze');
const btnYara    = document.getElementById('btnYara');
const spinEl     = document.getElementById('spinAnalyze');
const spinLabel  = document.getElementById('spinLabel');

let currentFile  = null;
let uploadedPath = null;

['dragenter', 'dragover'].forEach(ev =>
  dropZone.addEventListener(ev, e => { e.preventDefault(); dropZone.classList.add('drag'); })
);
['dragleave', 'drop'].forEach(ev =>
  dropZone.addEventListener(ev, e => { e.preventDefault(); dropZone.classList.remove('drag'); })
);
dropZone.addEventListener('drop', e => pickFile(e.dataTransfer.files[0]));
dropZone.addEventListener('click', () => fileInput.click());
fileInput.addEventListener('change', () => pickFile(fileInput.files[0]));

function pickFile(f) {
  if (!f) return;
  currentFile = f;
  const kb = (f.size / 1024).toFixed(1);
  fileNameEl.textContent = `${f.name}  (${kb} KB)`;
  btnAnalyze.disabled = false;
  btnYara.disabled    = false;
  document.getElementById('btnDeep').disabled = false;
  uploadedPath = null;
}

// ── WAR drag & drop / upload ─────────────────────────────
const dropZoneWar   = document.getElementById('dropZoneWar');
const warFileInput  = document.getElementById('warFileInput');
const warFileNameEl = document.getElementById('warFileName');
const btnWarAnalyze = document.getElementById('btnWarAnalyze');
const spinWar       = document.getElementById('spinWar');
const spinWarLabel  = document.getElementById('spinWarLabel');

let currentWarFile = null;

['dragenter', 'dragover'].forEach(ev =>
  dropZoneWar.addEventListener(ev, e => { e.preventDefault(); dropZoneWar.classList.add('drag'); })
);
['dragleave', 'drop'].forEach(ev =>
  dropZoneWar.addEventListener(ev, e => { e.preventDefault(); dropZoneWar.classList.remove('drag'); })
);
dropZoneWar.addEventListener('drop', e => pickWarFile(e.dataTransfer.files[0]));
dropZoneWar.addEventListener('click', () => warFileInput.click());
warFileInput.addEventListener('change', () => pickWarFile(warFileInput.files[0]));

function pickWarFile(f) {
  if (!f) return;
  currentWarFile = f;
  const kb = (f.size / 1024).toFixed(1);
  warFileNameEl.textContent = `${f.name}  (${kb} KB)`;
  btnWarAnalyze.disabled = false;
}

function setWarSpin(active, label = '') {
  spinWar.classList.toggle('active', active);
  spinWarLabel.classList.toggle('active', active);
  spinWarLabel.textContent = label;
}

btnWarAnalyze.addEventListener('click', runWarAnalysis);

async function runWarAnalysis() {
  if (!currentWarFile) return;
  btnWarAnalyze.disabled = true;
  setWarSpin(true, 'Analyse WAR…');

  try {
    const form = new FormData();
    form.append('file', currentWarFile);
    form.append('session_id', SESSION_ID);

    const r = await fetch('/api/analyze/war', { method: 'POST', body: form });
    if (!r.ok) {
      const d = await r.json().catch(() => ({ detail: r.statusText }));
      throw new Error(d.detail || r.statusText);
    }
    const data = await r.json();
    uploadedPath = data.path || uploadedPath;
    renderWarResults(data);
    appendMsg('system', `WAR analysé : **${currentWarFile.name}** — ${data.verdict || 'Analyse terminée'}`);
  } catch (e) {
    appendMsg('system', 'Erreur analyse WAR : ' + e.message);
  } finally {
    setWarSpin(false);
    btnWarAnalyze.disabled = false;
  }
}

// ── Analyse statique ──────────────────────────────────────
btnAnalyze.addEventListener('click', () => runAnalysis(false));
btnYara.addEventListener('click',    () => runAnalysis(true));

function setSpin(active, label = '') {
  spinEl.classList.toggle('active', active);
  spinLabel.classList.toggle('active', active);
  spinLabel.textContent = label;
}

async function runAnalysis(withYara) {
  if (!currentFile) return;
  btnAnalyze.disabled = true;
  btnYara.disabled = true;
  setSpin(true, withYara ? 'Scan YARA…' : 'Analyse…');

  try {
    const form = new FormData();
    form.append('file', currentFile);
    if (withYara) form.append('yara', 'true');

    const r = await fetch('/api/upload/analyze', { method: 'POST', body: form });
    if (!r.ok) {
      const d = await r.json().catch(() => ({ detail: r.statusText }));
      throw new Error(d.detail || r.statusText);
    }
    const data = await r.json();
    uploadedPath = data.path;
    renderResults(data, withYara);
    // Injecter contexte binaire dans le chat
    appendMsg('system', `Binaire chargé : **${currentFile.name}** (${(currentFile.size/1024).toFixed(1)} KB)`);
  } catch (e) {
    appendMsg('system', 'Erreur analyse : ' + e.message);
  } finally {
    setSpin(false);
    btnAnalyze.disabled = false;
    btnYara.disabled = false;
  }
}

function hex(n) {
  if (n == null || n === 0) return '0x0';
  return '0x' + n.toString(16);
}
function esc(str) {
  return String(str).replace(/[&<>"]/g, c =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c])
  );
}

function renderResults(data, withYara) {
  const info = data.info;
  if (!info) return;

  document.getElementById('resultsSection').style.display = '';

  const badge = document.getElementById('fmtBadge');
  const fmt = (info.format || '').toLowerCase();
  badge.className = 'badge ' + fmt;
  badge.textContent = info.format || '?';

  // Infos
  const grid = document.getElementById('infoGrid');
  grid.innerHTML = '';
  const rows = [
    ['Format',          info.format        || '—'],
    ['Arch',            info.architecture  || '—'],
    ['Imagebase',       info.imagebase_hex || hex(info.imagebase)],
    ['EP (VA)',         info.entrypoint_hex || hex(info.entrypoint)],
    ['EP (RVA)',        info.entrypoint_rva_hex || (info.entrypoint_rva != null ? hex(info.entrypoint_rva) : '—')],
    ['EP offset',       info.entrypoint_file_offset != null ? hex(info.entrypoint_file_offset) : '—'],
    ['Sections',        (info.sections || []).length],
    ['Imports',         (info.imports  || []).length],
  ];
  rows.forEach(([label, val]) => {
    const lDiv = document.createElement('div');
    lDiv.className = 'ig-label';
    lDiv.textContent = label;
    const vDiv = document.createElement('div');
    const isHex = typeof val === 'string' && val.startsWith('0x');
    vDiv.className = 'ig-value' + (isHex ? ' hex' : '');
    vDiv.textContent = val;
    grid.appendChild(lDiv);
    grid.appendChild(vDiv);
  });

  // Sections
  const sb = document.getElementById('sectionsBody');
  sb.innerHTML = '';
  (info.sections || []).forEach(s => {
    const tr = document.createElement('tr');
    tr.innerHTML = `<td>${esc(s.name || '—')}</td><td>${s.virtual_address_hex || hex(s.virtual_address)}</td><td>${s.size || s.virtual_size || 0}</td><td>${hex(s.file_offset)}</td>`;
    sb.appendChild(tr);
  });

  // Imports
  const ib = document.getElementById('importsBody');
  ib.innerHTML = '';
  (info.imports || []).forEach(i => {
    const tr = document.createElement('tr');
    tr.innerHTML = `<td>${esc(i.library || '—')}</td><td>${esc(i.symbol || '—')}</td><td>${hex(i.address)}</td>`;
    ib.appendChild(tr);
  });

  // YARA
  const yr = document.getElementById('yaraResults');
  if (!withYara) {
    yr.innerHTML = '<div class="yara-pending">Cliquez "YARA" pour détecter les techniques anti-debug.</div>';
  } else if (!data.yara_matches || data.yara_matches.length === 0) {
    yr.innerHTML = '<div class="yara-none">✓ Aucune technique anti-debug détectée.</div>';
  } else {
    yr.innerHTML = data.yara_matches.map(m => {
      const meta = Object.entries(m.meta || {}).map(([k, v]) => `${k}: ${v}`).join(' | ');
      return `<div class="yara-match"><div class="rule">⚠ ${esc(m.rule)}</div><div class="yara-meta">${meta}</div></div>`;
    }).join('');
  }

  document.querySelector('.tab[data-tab="info"]').click();
}

// ── Deep Scan ─────────────────────────────────────────────
document.getElementById('btnDeep').addEventListener('click', runDeepScan);

async function runDeepScan() {
  if (!currentFile) return;
  const btnDeep = document.getElementById('btnDeep');
  btnDeep.disabled = true;
  setSpin(true, 'Deep scan…');

  try {
    const form = new FormData();
    form.append('file', currentFile);
    form.append('session_id', SESSION_ID);

    const r = await fetch('/api/analyze/deep', { method: 'POST', body: form });
    if (!r.ok) {
      const d = await r.json().catch(() => ({ detail: r.statusText }));
      throw new Error(d.detail || r.statusText);
    }
    const data = await r.json();
    uploadedPath = data.path || uploadedPath;
    renderDeepResults(data);
    appendMsg('system', `Deep scan terminé en **${data.analysis_time_s}s** — ${_deepSummary(data)}`);
  } catch (e) {
    appendMsg('system', 'Erreur deep scan : ' + e.message);
  } finally {
    setSpin(false);
    btnDeep.disabled = false;
  }
}

function _deepSummary(d) {
  const parts = [];
  const api = d.api_behavior;
  if (api && api.summary) parts.push(api.summary);
  const packer = d.packer;
  if (packer && packer.detected) parts.push(`Packer: ${packer.detected}`);
  const ent = d.entropy;
  if (ent && ent.overall_verdict !== 'normal') parts.push(`Entropy: ${ent.overall_verdict}`);
  const yara = d.yara;
  if (yara && yara.total_hits > 0) parts.push(`YARA: ${yara.total_hits} hit(s)`);
  const c2 = d.c2;
  if (c2 && c2.score >= 20) parts.push(`C2: ${c2.score}/100`);
  const sc = d.shellcode;
  if (sc && sc.score >= 20) parts.push(`Shellcode: ${sc.score}/100`);
  const hp = d.hidden_process;
  if (hp && hp.confidence >= 40) parts.push(`Hidden process: ${hp.confidence}%`);
  return parts.join(' | ') || 'Aucune menace majeure détectée';
}

function renderDeepResults(data) {
  document.getElementById('deepSection').style.display = '';

  // Risk badge
  const api   = data.api_behavior || {};
  const level = (api.risk_level || 'AUCUN').toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '');
  const badge = document.getElementById('deepRiskBadge');
  badge.textContent = api.risk_level || 'N/A';
  badge.className   = `risk-badge ${level}`;

  // ── Hashes tab ──────────────────────────────────────────
  const h = data.hashes || {};
  const packer = data.packer || {};
  document.getElementById('dtabHashes').innerHTML = `
    <div class="hash-row"><span class="hash-label">Type</span><span class="hash-value">${esc(h.file_type || '—')}</span></div>
    <div class="hash-row"><span class="hash-label">Size</span><span class="hash-value">${h.size_kb || '—'} KB</span></div>
    <div class="hash-row"><span class="hash-label">MD5</span><span class="hash-value">${h.md5 || '—'}</span></div>
    <div class="hash-row"><span class="hash-label">SHA1</span><span class="hash-value">${h.sha1 || '—'}</span></div>
    <div class="hash-row"><span class="hash-label">SHA256</span><span class="hash-value">${h.sha256 || '—'}</span></div>
    <div class="hash-row"><span class="hash-label">Imphash</span><span class="hash-value">${h.imphash || '—'}</span></div>
    <div style="margin-top:10px; padding-top:8px; border-top:1px solid var(--border)">
      <div class="str-cat-label">Packer / Protecteur</div>
      ${packer.detected
        ? `<div style="color:var(--red);font-size:12px;font-weight:700;">${esc(packer.detected)} <span style="color:var(--text3);font-weight:400;">(${packer.confidence || 0}%)</span></div>
           ${(packer.indicators || []).map(i => `<div style="font-size:10.5px;color:var(--text2);margin-top:3px;">• ${esc(i)}</div>`).join('')}`
        : `<div style="color:var(--green);font-size:12px;">✓ Aucun packer détecté</div>`
      }
    </div>`;

  // ── Entropy tab ─────────────────────────────────────────
  const ent = data.entropy || {};
  const entHtml = (ent.sections || []).map(s => {
    const pct = Math.min(100, (s.entropy / 8) * 100).toFixed(1);
    return `<div class="entropy-section-row">
      <div class="entropy-name">
        <span>${esc(s.name)}</span>
        <span class="val">${s.entropy} <span style="color:var(--text3);font-size:9px;">[${s.verdict}]</span></span>
      </div>
      <div class="entropy-bar-bg">
        <div class="entropy-bar-fill ${s.verdict}" style="width:${pct}%"></div>
      </div>
    </div>`;
  }).join('');
  document.getElementById('dtabEntropy').innerHTML = `
    <div style="margin-bottom:8px">
      <span class="str-cat-label">Verdict global : </span>
      <span style="color:${_entropyColor(ent.overall_verdict)};font-weight:700;font-size:11px;">${ent.overall_verdict || '—'}</span>
      <span style="color:var(--text3);font-size:10px;margin-left:6px;">(entropie fichier : ${ent.file_entropy || '—'})</span>
    </div>
    ${entHtml || '<div style="color:var(--text3)">Aucune section</div>'}`;

  // ── APIs tab ─────────────────────────────────────────────
  const cats = api.categories || {};
  const apiHtml = Object.entries(cats).map(([id, cat]) => `
    <div class="api-category">
      <div class="api-cat-header" onclick="this.nextElementSibling.style.display = this.nextElementSibling.style.display === 'none' ? 'flex' : 'none'">
        <div class="api-cat-dot" style="background:${cat.color}"></div>
        <span class="api-cat-name">${esc(cat.label)}</span>
        <span class="api-risk-chip ${cat.risk}">${cat.risk}</span>
        <span class="api-cat-count">${cat.count}</span>
      </div>
      <div class="api-cat-body">
        ${cat.matched.map(fn => `<span class="api-pill">${esc(fn)}</span>`).join('')}
      </div>
    </div>`).join('');
  document.getElementById('dtabApis').innerHTML = apiHtml ||
    '<div style="color:var(--green);font-size:12px;padding:6px 0;">✓ Aucun comportement suspect détecté</div>';

  // ── Strings tab ─────────────────────────────────────────
  const sc = data.strings_classified || {};
  const strLabels = {
    flags_ctf: '🚩 Flags / Passwords',
    urls: 'URLs',
    ips: 'Adresses IP',
    domains: 'Domaines',
    registry_keys: 'Clés registre',
    commands: 'Commandes shell',
    base64: 'Base64',
    interesting_strings: 'Chaînes intéressantes',
    emails: 'Emails',
    file_paths: 'Chemins fichiers',
    hex_blobs: 'Blobs hex',
    guids: 'GUIDs',
  };
  const strHtml = Object.entries(sc).map(([cat, items]) => `
    <div class="str-category">
      <div class="str-cat-label">${strLabels[cat] || cat}</div>
      ${items.slice(0, 10).map(s => `<div class="str-item">${esc(s)}</div>`).join('')}
      ${items.length > 10 ? `<div style="color:var(--text3);font-size:10px;padding-top:3px;">+${items.length - 10} autres…</div>` : ''}
    </div>`).join('');
  document.getElementById('dtabStrings').innerHTML = strHtml ||
    '<div style="color:var(--text3);font-size:12px;padding:6px 0;">Aucune chaîne classifiée trouvée</div>';

  // ── Threats tab (C2, Shellcode, PE Anomalies, Obfuscation, Hidden Process) ──
  renderThreatsTab(data);

  // ── YARA+ tab ────────────────────────────────────────────
  const yara = data.yara || {};
  const yara2Html = Object.entries(yara.matches || {}).map(([cat, matches]) => {
    if (!Array.isArray(matches) || matches.length === 0) return '';
    return `<div class="yara2-category">
      <div class="yara2-cat-label">${cat.replace(/_/g,' ')}</div>
      ${matches.map(m => {
        if (m.error) return `<div style="color:var(--red);font-size:11px;">⚠ ${esc(m.error)}</div>`;
        const meta = Object.entries(m.meta || {}).map(([k,v]) => `${k}: ${v}`).join(' | ');
        return `<div class="yara-match"><div class="rule">⚠ ${esc(m.rule || '?')}</div><div class="yara-meta">${esc(meta)}</div></div>`;
      }).join('')}
    </div>`;
  }).join('');
  document.getElementById('dtabYara2').innerHTML = yara2Html ||
    '<div style="color:var(--green);font-size:12px;padding:6px 0;">✓ Aucune signature YARA détectée</div>';

  // Activer le premier deep-tab
  document.querySelector('.deep-tab[data-dtab="hashes"]').click();
}

function _severityColor(sev) {
  return { critical: '#f85149', high: '#ffa657', medium: '#e3b341', low: '#7ee787', info: 'var(--text3)' }[sev] || 'var(--text2)';
}

function _scoreBar(score, label) {
  const pct = Math.min(100, score || 0);
  const color = pct >= 70 ? '#f85149' : pct >= 40 ? '#ffa657' : pct >= 20 ? '#e3b341' : '#7ee787';
  return `<div style="margin-bottom:10px">
    <div style="display:flex;justify-content:space-between;font-size:11px;color:var(--text2);margin-bottom:4px;">
      <span>${esc(label)}</span><span style="color:${color};font-weight:700;">${pct}/100</span>
    </div>
    <div style="height:5px;background:var(--surface2);border-radius:3px;overflow:hidden;">
      <div style="width:${pct}%;height:100%;background:${color};border-radius:3px;transition:width .4s"></div>
    </div>
  </div>`;
}

function _threatBlock(title, score, verdict, items, renderItem) {
  const color = _severityColor(score >= 70 ? 'critical' : score >= 40 ? 'high' : score >= 20 ? 'medium' : 'info');
  const itemsHtml = (items || []).map(renderItem).filter(Boolean).join('');
  return `<div class="threat-block">
    <div class="threat-block-header">
      <span class="threat-title">${title}</span>
      <span class="threat-score" style="color:${color}">${score || 0}/100</span>
    </div>
    <div style="font-size:10.5px;color:var(--text3);margin-bottom:6px;">${esc(verdict || '—')}</div>
    ${itemsHtml || '<div style="color:var(--text3);font-size:11px;">Aucun indicateur</div>'}
  </div>`;
}

function renderThreatsTab(data) {
  const sections = [];

  // ── C2 Detection ──────────────────────────────────────────
  const c2 = data.c2 || {};
  if (!c2.error) {
    const c2Items = (c2.indicators || []).map(ind => {
      const valStr = Array.isArray(ind.value) ? ind.value.slice(0, 4).join(', ') :
                     typeof ind.value === 'object' ? JSON.stringify(ind.value).slice(0, 80) :
                     String(ind.value || '').slice(0, 80);
      return `<div class="threat-indicator">
        <span class="threat-sev-dot" style="background:${_severityColor(ind.severity)}"></span>
        <div>
          <div style="font-size:11px;color:var(--text2);font-weight:600;">${esc(ind.type)}</div>
          <div style="font-size:10px;color:var(--text3);">${esc(ind.description || '')} ${valStr ? '— ' + esc(valStr) : ''}</div>
        </div>
      </div>`;
    });
    if (c2.public_ips && c2.public_ips.length > 0) {
      c2Items.push(`<div style="margin-top:6px;font-size:10px;color:var(--text3);">
        IPs publiques : ${c2.public_ips.slice(0,8).map(ip => `<code style="font-size:9px;background:var(--surface2);padding:1px 4px;border-radius:3px;">${esc(ip)}</code>`).join(' ')}
      </div>`);
    }
    sections.push(_threatBlock('C2 / Command & Control', c2.score, c2.verdict, c2Items, i => i));
  }

  // ── Shellcode Detection ───────────────────────────────────
  const sc = data.shellcode || {};
  if (!sc.error) {
    const scItems = (sc.findings || []).map(f =>
      `<div class="threat-indicator">
        <span class="threat-sev-dot" style="background:${_severityColor(f.severity)}"></span>
        <div>
          <div style="font-size:11px;color:var(--text2);font-weight:600;">${esc(f.type)}</div>
          <div style="font-size:10px;color:var(--text3);">${esc(f.description || '')}
            ${f.offsets ? ' — offsets: ' + f.offsets.slice(0,3).join(', ') : ''}</div>
        </div>
      </div>`
    );
    sections.push(_threatBlock('Shellcode / Exploit', sc.score, sc.verdict, scItems, i => i));
  }

  // ── PE Anomalies ─────────────────────────────────────────
  const pea = data.pe_anomalies || {};
  if (!pea.error) {
    const peItems = (pea.anomalies || []).map(a =>
      `<div class="threat-indicator">
        <span class="threat-sev-dot" style="background:${_severityColor(a.severity)}"></span>
        <div>
          <div style="font-size:11px;color:var(--text2);font-weight:600;">${esc(a.type)}</div>
          <div style="font-size:10px;color:var(--text3);">${esc(a.detail || '')}</div>
        </div>
      </div>`
    );
    const rh = pea.rich_header || {};
    const rhBadge = rh.present
      ? (rh.valid ? `<span style="color:var(--green);font-size:10px;">Rich Header valide (${rh.compids?.length || 0} compid(s))</span>`
                  : `<span style="color:var(--red);font-size:10px;">Rich Header invalide — ${esc(rh.note || '')}</span>`)
      : `<span style="color:var(--yellow);font-size:10px;">Rich Header absent — ${esc(rh.note || '')}</span>`;
    sections.push(_threatBlock('PE Anomalies', pea.score, pea.verdict,
      [`<div style="margin-bottom:8px;">${rhBadge}</div>`, ...peItems], i => i));
  }

  // ── String Obfuscation ────────────────────────────────────
  const ob = data.obfuscation || {};
  if (!ob.error) {
    const obItems = (ob.findings || []).map(f => {
      let extra = '';
      if (f.xor_keys) extra = f.xor_keys.slice(0,3).map(k => `<span style="font-size:9px;background:var(--surface2);padding:1px 4px;border-radius:3px;margin-right:3px;">key=${k.key} (${Math.round(k.ratio*100)}%)</span>`).join('');
      if (f.algorithms) extra = f.algorithms.slice(0,3).map(a => `<span style="font-size:9px;background:var(--surface2);padding:1px 4px;border-radius:3px;margin-right:3px;">${esc(a)}</span>`).join('');
      return `<div class="threat-indicator">
        <span class="threat-sev-dot" style="background:${_severityColor(f.severity)}"></span>
        <div>
          <div style="font-size:11px;color:var(--text2);font-weight:600;">${esc(f.type)} <span style="color:var(--text3);font-weight:400;">(×${f.count || 1})</span></div>
          <div style="font-size:10px;color:var(--text3);">${esc(f.description || '')}</div>
          ${extra ? `<div style="margin-top:3px;">${extra}</div>` : ''}
        </div>
      </div>`;
    });
    sections.push(_threatBlock('Obfuscation', ob.score, ob.verdict, obItems, i => i));
  }

  // ── Hidden Process ────────────────────────────────────────
  const hp = data.hidden_process || {};
  if (!hp.error) {
    const hpItems = (hp.indicators || []).map(ind =>
      `<div class="threat-indicator">
        <span class="threat-sev-dot" style="background:${_severityColor('high')}"></span>
        <div style="font-size:10.5px;color:var(--text2);">${esc(String(ind).slice(0, 120))}</div>
      </div>`
    );
    if (hp.shells_found && hp.shells_found.length > 0) {
      hpItems.push(`<div style="margin-top:4px;font-size:10px;color:var(--text3);">Shells: ${hp.shells_found.map(s => `<code style="font-size:9px;background:var(--surface2);padding:1px 4px;border-radius:3px;">${esc(s)}</code>`).join(' ')}</div>`);
    }
    // Convertit confidence en score pour l'affichage
    sections.push(_threatBlock('Processus cachés', hp.confidence, hp.verdict, hpItems, i => i));
  }

  const html = sections.length > 0 ? sections.join('') :
    '<div style="color:var(--green);font-size:12px;padding:8px 0;">✓ Aucune menace avancée détectée</div>';
  document.getElementById('dtabThreats').innerHTML = html;
}

function _entropyColor(verdict) {
  return { 'packed/encrypted': '#f85149', 'suspicious': '#ffa657', 'compressed': '#e3b341', 'normal': '#7ee787' }[verdict] || 'var(--text2)';
}

// Deep tabs navigation
document.querySelectorAll('.deep-tab').forEach(tab => {
  tab.addEventListener('click', () => {
    const name = tab.dataset.dtab;
    document.querySelectorAll('.deep-tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.deep-pane').forEach(p => p.classList.remove('active'));
    tab.classList.add('active');
    const pane = document.getElementById('dtab' + name.charAt(0).toUpperCase() + name.slice(1));
    if (pane) pane.classList.add('active');
  });
});

// ══════════════════════════════════════════════════════════
// WAR RESULTS RENDERING
// ══════════════════════════════════════════════════════════

// WAR tabs navigation
document.querySelectorAll('.war-tab').forEach(tab => {
  tab.addEventListener('click', () => {
    const name = tab.dataset.wtab;
    document.querySelectorAll('.war-tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.war-pane').forEach(p => p.classList.remove('active'));
    tab.classList.add('active');
    const pane = document.getElementById('wtab' + name.charAt(0).toUpperCase() + name.slice(1));
    if (pane) pane.classList.add('active');
  });
});

function renderWarResults(data) {
  document.getElementById('warSection').style.display = '';

  // Risk badge
  const riskLevel = (data.risk_level || 'AUCUN').toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '');
  const badge = document.getElementById('warRiskBadge');
  badge.textContent = data.risk_level || 'N/A';
  badge.className = `risk-badge ${riskLevel}`;

  // ── Overview tab ──
  const structure = data.structure || {};
  const overviewHtml = `
    <div class="war-overview-grid">
      <span class="war-ov-label">Fichier</span><span class="war-ov-value">${esc(data.filename || '?')}</span>
      <span class="war-ov-label">Taille</span><span class="war-ov-value">${((data.size_bytes || 0) / 1024).toFixed(1)} KB</span>
      <span class="war-ov-label">MD5</span><span class="war-ov-value">${esc(data.md5 || '?')}</span>
      <span class="war-ov-label">SHA256</span><span class="war-ov-value">${esc((data.sha256 || '?').substring(0, 32))}…</span>
      <span class="war-ov-label">Entropie</span><span class="war-ov-value">${data.file_entropy || '?'}</span>
      <span class="war-ov-label">Verdict</span><span class="war-ov-value" style="color:${data.risk_score >= 70 ? '#f85149' : data.risk_score >= 40 ? '#ffa657' : data.risk_score >= 20 ? '#e3b341' : '#7ee787'}; font-weight:700;">${esc(data.verdict || '?')}</span>
      <span class="war-ov-label">Fichiers</span><span class="war-ov-value">${data.total_files || 0} total</span>
      <span class="war-ov-label">Classes</span><span class="war-ov-value">${(data.java_classes || []).length}</span>
      <span class="war-ov-label">JSPs</span><span class="war-ov-value">${(data.jsp_files || []).length}</span>
      <span class="war-ov-label">JARs</span><span class="war-ov-value">${(data.lib_jars || []).length}</span>
    </div>
    ${_warTreeSection('Classes Java', structure.classes || [])}
    ${_warTreeSection('Fichiers JSP', structure.jsps || [])}
    ${_warTreeSection('Bibliothèques (JARs)', structure.jars || [])}
    ${_warTreeSection('Configuration', structure.configs || [])}
    ${data.manifest && Object.keys(data.manifest).length > 0 ? `
      <div class="war-tree">
        <div class="war-tree-header">Manifest</div>
        <div class="war-tree-list">${Object.entries(data.manifest).map(([k,v]) => `<div class="war-tree-item"><span style="color:var(--text3)">${esc(k)}:</span> ${esc(v)}</div>`).join('')}</div>
      </div>` : ''}
  `;
  document.getElementById('wtabOverview').innerHTML = overviewHtml;

  // ── Vulns tab ──
  const vulns = data.vulnerable_libs || [];
  const yaraJava = data.yara_java || [];
  let vulnsHtml = '';
  if (vulns.length > 0) {
    vulnsHtml += `<div style="font-size:11px;color:var(--red);font-weight:700;margin-bottom:8px;">${vulns.length} bibliothèque(s) vulnérable(s)</div>`;
    vulnsHtml += vulns.map(v => `
      <div class="war-vuln-card">
        <div class="war-vuln-jar">${esc(v.jar)}</div>
        <div class="war-vuln-cve">${esc(v.cve)}</div>
        <div class="war-vuln-desc">${esc(v.desc)} <span class="war-api-risk ${v.risk}">${v.risk}</span></div>
      </div>`).join('');
  } else {
    vulnsHtml += '<div style="color:var(--green);font-size:12px;padding:6px 0;">Aucune bibliothèque vulnérable connue</div>';
  }
  if (yaraJava.length > 0) {
    vulnsHtml += `<div style="margin-top:10px;font-size:10px;font-weight:700;text-transform:uppercase;color:var(--text3);letter-spacing:.5px;margin-bottom:6px;">YARA Java (${yaraJava.length})</div>`;
    vulnsHtml += yaraJava.map(m => {
      const meta = Object.entries(m.meta || {}).map(([k,v]) => `${k}: ${v}`).join(' | ');
      return `<div class="yara-match"><div class="rule">${esc(m.rule || '?')}</div><div class="yara-meta">${esc(meta)}</div></div>`;
    }).join('');
  }
  document.getElementById('wtabVulns').innerHTML = vulnsHtml;

  // ── Webshells tab ──
  const ws = data.webshell_indicators || [];
  let wsHtml = '';
  if (ws.length > 0) {
    wsHtml += `<div style="font-size:11px;color:var(--red);font-weight:700;margin-bottom:8px;">${ws.length} indicateur(s) de webshell</div>`;
    wsHtml += ws.map(w => `
      <div class="war-ws-card">
        <div class="war-ws-pattern"><span class="war-api-risk ${w.risk}">${w.risk}</span> ${esc(w.pattern)}</div>
        <div class="war-ws-source">${esc(w.source)}</div>
        ${w.matches ? `<div style="font-size:9.5px;color:var(--text3);margin-top:3px;font-family:var(--font-mono);">${w.matches.map(m => esc(m)).join(', ')}</div>` : ''}
      </div>`).join('');
  } else {
    wsHtml = '<div style="color:var(--green);font-size:12px;padding:6px 0;">Aucun webshell detecte</div>';
  }
  document.getElementById('wtabWebshells').innerHTML = wsHtml;

  // ── APIs tab ──
  const apis = data.dangerous_apis || [];
  let apisHtml = '';
  if (apis.length > 0) {
    const critCount = apis.filter(a => a.risk === 'critical').length;
    const highCount = apis.filter(a => a.risk === 'high').length;
    apisHtml += `<div style="font-size:11px;color:var(--text2);margin-bottom:8px;font-weight:600;">${apis.length} API(s) dangereuse(s) — <span style="color:#f85149">${critCount} critique(s)</span>, <span style="color:#ffa657">${highCount} haute(s)</span></div>`;
    // Group by category
    const byCat = {};
    apis.forEach(a => {
      if (!byCat[a.category]) byCat[a.category] = [];
      byCat[a.category].push(a);
    });
    const catLabels = {
      rce: 'Exec. de commande', deserialization: 'Deserialization', jndi: 'JNDI Injection',
      reflection: 'Reflection', file_write: 'Ecriture fichier', network: 'Reseau',
      sqli: 'SQL Injection', xxe: 'XXE', template_injection: 'Template Injection',
      weak_crypto: 'Crypto faible'
    };
    Object.entries(byCat).forEach(([cat, items]) => {
      apisHtml += `<div style="margin-top:6px;font-size:10px;font-weight:700;color:var(--text3);text-transform:uppercase;letter-spacing:.4px;">${catLabels[cat] || cat}</div>`;
      items.forEach(a => {
        apisHtml += `<div class="war-api-item">
          <span class="war-api-risk ${a.risk}">${a.risk}</span>
          <div>
            <div style="font-weight:600;color:var(--text2);">${esc(a.api)}</div>
            <div style="color:var(--text3);font-size:10px;">${esc(a.description)} — <span style="font-family:var(--font-mono)">${esc(a.source)}</span></div>
          </div>
        </div>`;
      });
    });
  } else {
    apisHtml = '<div style="color:var(--green);font-size:12px;padding:6px 0;">Aucune API dangereuse detectee</div>';
  }
  document.getElementById('wtabApis').innerHTML = apisHtml;

  // ── Secrets tab ──
  const secrets = data.secrets_found || [];
  const strings = data.interesting_strings || [];
  let secretsHtml = '';
  if (secrets.length > 0) {
    secretsHtml += `<div style="font-size:11px;color:#ffa657;font-weight:700;margin-bottom:8px;">${secrets.length} secret(s) / credential(s)</div>`;
    secrets.forEach(s => {
      secretsHtml += `<div class="war-secret-item">
        <div class="war-secret-type">${esc(s.type)}</div>
        <div class="war-secret-source">${esc(s.source)}</div>
      </div>`;
    });
  } else {
    secretsHtml += '<div style="color:var(--green);font-size:12px;padding:6px 0;">Aucun secret detecte</div>';
  }
  if (strings.length > 0) {
    secretsHtml += `<div style="margin-top:10px;font-size:10px;font-weight:700;text-transform:uppercase;color:var(--text3);letter-spacing:.5px;margin-bottom:6px;">Strings interessantes (${strings.length})</div>`;
    strings.slice(0, 20).forEach(s => {
      secretsHtml += `<div class="str-item">${esc(s)}</div>`;
    });
    if (strings.length > 20) secretsHtml += `<div style="color:var(--text3);font-size:10px;padding-top:3px;">+${strings.length - 20} autres…</div>`;
  }
  document.getElementById('wtabSecrets').innerHTML = secretsHtml;

  // ── Config tab ──
  const webXml = data.web_xml || {};
  const misconfigs = data.security_misconfigs || [];
  let configHtml = '';

  // Servlets
  const servlets = webXml.servlets || [];
  if (servlets.length > 0) {
    configHtml += `<div style="font-size:10px;font-weight:700;text-transform:uppercase;color:var(--text3);letter-spacing:.4px;margin-bottom:6px;">Servlets (${servlets.length})</div>`;
    servlets.forEach(s => {
      configHtml += `<div class="war-servlet-row">
        <div class="war-servlet-name">${esc(s.name)}</div>
        <div class="war-servlet-class">${esc(s.class || s['class'] || '?')}</div>
        ${(s.url_patterns || []).length > 0 ? `<div class="war-servlet-url">${s.url_patterns.map(u => esc(u)).join(', ')}</div>` : ''}
      </div>`;
    });
  }

  // Filters
  const filters = webXml.filters || [];
  if (filters.length > 0) {
    configHtml += `<div style="margin-top:8px;font-size:10px;font-weight:700;text-transform:uppercase;color:var(--text3);letter-spacing:.4px;margin-bottom:6px;">Filters (${filters.length})</div>`;
    filters.forEach(f => {
      configHtml += `<div class="war-servlet-row">
        <div class="war-servlet-name">${esc(f.name)}</div>
        <div class="war-servlet-class">${esc(f.class || f['class'] || '?')}</div>
      </div>`;
    });
  }

  // Listeners
  const listeners = webXml.listeners || [];
  if (listeners.length > 0) {
    configHtml += `<div style="margin-top:8px;font-size:10px;font-weight:700;text-transform:uppercase;color:var(--text3);letter-spacing:.4px;margin-bottom:6px;">Listeners (${listeners.length})</div>`;
    listeners.forEach(l => {
      configHtml += `<div style="font-family:var(--font-mono);font-size:10px;color:var(--accent-h);padding:2px 0;">${esc(l)}</div>`;
    });
  }

  // Security issues
  const issues = webXml.issues || [];
  const allIssues = [...issues, ...misconfigs.map(m => m.issue || m.detail || '')].filter(Boolean);
  if (allIssues.length > 0) {
    configHtml += `<div style="margin-top:10px;font-size:10px;font-weight:700;text-transform:uppercase;color:var(--red);letter-spacing:.4px;margin-bottom:6px;">Problemes de securite (${allIssues.length})</div>`;
    allIssues.forEach(issue => {
      configHtml += `<div class="war-issue">${esc(issue)}</div>`;
    });
  }

  if (!configHtml) {
    configHtml = '<div style="color:var(--text3);font-size:12px;">Pas de web.xml trouve</div>';
  }
  document.getElementById('wtabConfig').innerHTML = configHtml;

  // Active first tab
  document.querySelector('.war-tab[data-wtab="overview"]').click();
}

function _warTreeSection(title, items) {
  if (!items || items.length === 0) return '';
  const shown = items.slice(0, 30);
  const more = items.length > 30 ? `<div class="war-tree-item" style="color:var(--text3);">+${items.length - 30} autres…</div>` : '';
  return `<div class="war-tree">
    <div class="war-tree-header" onclick="this.nextElementSibling.style.display = this.nextElementSibling.style.display === 'none' ? 'block' : 'none'">${esc(title)} (${items.length})</div>
    <div class="war-tree-list" style="display:none">
      ${shown.map(f => `<div class="war-tree-item">${esc(f)}</div>`).join('')}
      ${more}
    </div>
  </div>`;
}

// ══════════════════════════════════════════════════════════
// CHAT
// ══════════════════════════════════════════════════════════
const chatEl = document.getElementById('chat');

// Suggestion chips
document.querySelectorAll('.chip').forEach(chip => {
  chip.addEventListener('click', () => {
    document.getElementById('input').value = chip.dataset.msg;
    autoResize();
    send();
  });
});

// ── Restauration de l'historique au chargement ────────────
async function restoreHistory() {
  try {
    const r = await fetch(`/api/chat/history/${SESSION_ID}`);
    if (!r.ok) return;
    const data = await r.json();
    if (!data.messages || data.messages.length === 0) return;

    if (data.binary_path) {
      uploadedPath = data.binary_path;
    }

    removeWelcome();
    for (const msg of data.messages) {
      if (msg.role === 'user' || msg.role === 'assistant') {
        _renderMsg(msg.role, msg.content);
      }
    }

    const sep = document.createElement('div');
    sep.className = 'msg-row system';
    sep.style.justifyContent = 'center';
    sep.innerHTML = '<div class="bubble-wrap"><div class="bubble" style="font-size:11px;color:var(--text3);padding:4px 0;background:transparent;border:none;">— Session restaurée —</div></div>';
    chatEl.appendChild(sep);
    chatEl.scrollTop = chatEl.scrollHeight;
  } catch (_) {}
}

// Rendu d'un message (sans modifier le store serveur)
function _renderMsg(role, content) {
  const row = document.createElement('div');
  row.className = `msg-row ${role}`;

  const av = document.createElement('div');
  av.className = 'avatar ' + (role === 'user' ? 'user-av' : 'ai-av');
  if (role === 'user') {
    av.textContent = 'U';
  } else {
    av.innerHTML = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2L2 7l10 5 10-5-10-5z"/><path d="M2 12l10 5 10-5"/></svg>`;
  }

  const wrap = document.createElement('div');
  wrap.className = 'bubble-wrap';
  const bubble = document.createElement('div');
  bubble.className = 'bubble';
  bubble.innerHTML = formatMessage(content);
  wrap.appendChild(bubble);
  row.appendChild(av);
  row.appendChild(wrap);
  chatEl.appendChild(row);
}

// Formatage Markdown léger
function fmtInline(text) {
  return text
    .replace(/`([^`\n]+)`/g, '<code>$1</code>')
    .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
    .replace(/\*(.+?)\*/g, '<em>$1</em>');
}

function fmtBlock(para) {
  const lines = para.split('\n').map(l => l.trimEnd());
  const trimmed = lines.map(l => l.trim());

  if (trimmed.length === 1 && /^-{3,}$/.test(trimmed[0])) return '<hr>';

  // Bloc de code
  if (trimmed[0].startsWith('```')) {
    const lang = trimmed[0].replace('```', '').trim();
    const code = trimmed.slice(1).filter((l, i, a) => !(i === a.length - 1 && l === '```')).join('\n');
    return `<pre><code class="lang-${lang}">${esc(code)}</code></pre>`;
  }

  if (trimmed.every(l => /^\d+\.\s+/.test(l)))
    return '<ol>' + trimmed.map(l => `<li>${fmtInline(esc(l.replace(/^\d+\.\s+/, '')))}</li>`).join('') + '</ol>';
  if (trimmed.every(l => /^[-*]\s+/.test(l)))
    return '<ul>' + trimmed.map(l => `<li>${fmtInline(esc(l.replace(/^[-*]\s+/, '')))}</li>`).join('') + '</ul>';

  return '<p>' + lines.map(l => fmtInline(esc(l))).join('<br>') + '</p>';
}

function formatMessage(text) {
  if (!text) return '';
  // Gérer blocs ```...``` multi-lignes avant le split
  const parts = [];
  const codeBlockRe = /```[\s\S]*?```/g;
  let last = 0, m;
  while ((m = codeBlockRe.exec(text)) !== null) {
    const before = text.slice(last, m.index).replace(/\r\n/g, '\n');
    if (before.trim()) parts.push(...before.split(/\n\s*\n+/).map(fmtBlock));
    parts.push(fmtBlock(m[0].replace(/\r\n/g, '\n')));
    last = m.index + m[0].length;
  }
  const rest = text.slice(last).replace(/\r\n/g, '\n');
  if (rest.trim()) parts.push(...rest.split(/\n\s*\n+/).map(fmtBlock));
  return parts.join('');
}

function removeWelcome() {
  const w = chatEl.querySelector('.welcome');
  if (w) w.remove();
}

function appendMsg(role, content) {
  removeWelcome();

  if (role === 'system') {
    const row = document.createElement('div');
    row.className = 'msg-row system';
    row.style.justifyContent = 'center';
    const wrap = document.createElement('div');
    wrap.className = 'bubble-wrap';
    const bubble = document.createElement('div');
    bubble.className = 'bubble';
    bubble.innerHTML = formatMessage(content);
    wrap.appendChild(bubble);
    row.appendChild(wrap);
    chatEl.appendChild(row);
    chatEl.scrollTop = chatEl.scrollHeight;
    return row;
  }

  _renderMsg(role, content);
  chatEl.scrollTop = chatEl.scrollHeight;
}

function showTyping() {
  const row = document.createElement('div');
  row.className = 'msg-row assistant';
  row.id = 'typingRow';

  const av = document.createElement('div');
  av.className = 'avatar ai-av';
  av.innerHTML = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2L2 7l10 5 10-5-10-5z"/><path d="M2 12l10 5 10-5"/></svg>`;

  const wrap = document.createElement('div');
  wrap.className = 'bubble-wrap';

  const bubble = document.createElement('div');
  bubble.className = 'bubble typing-bubble';
  bubble.innerHTML = '<div class="typing-dot"></div><div class="typing-dot"></div><div class="typing-dot"></div>';

  wrap.appendChild(bubble);
  row.appendChild(av);
  row.appendChild(wrap);
  chatEl.appendChild(row);
  chatEl.scrollTop = chatEl.scrollHeight;
}

function removeTyping() {
  const t = document.getElementById('typingRow');
  if (t) t.remove();
}

// ── Envoyer ───────────────────────────────────────────────
const inputEl   = document.getElementById('input');
const btnSend   = document.getElementById('btnSend');
const btnClear  = document.getElementById('btnClear');

function autoResize() {
  inputEl.style.height = 'auto';
  inputEl.style.height = Math.min(inputEl.scrollHeight, 160) + 'px';
  btnSend.disabled = inputEl.value.trim().length === 0;
}

inputEl.addEventListener('input', autoResize);
autoResize();

inputEl.addEventListener('keydown', e => {
  if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send(); }
});
btnSend.addEventListener('click', send);

btnClear.addEventListener('click', async () => {
  // Effacer l'historique côté serveur
  try {
    await fetch(`/api/chat/history/${SESSION_ID}`, { method: 'DELETE' });
  } catch (_) {}

  chatEl.innerHTML = '';
  uploadedPath = null;

  const welcome = document.createElement('div');
  welcome.className = 'welcome';
  welcome.innerHTML = `
    <div class="welcome-icon">
      <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
        <path d="M12 2L2 7l10 5 10-5-10-5z"/>
        <path d="M2 17l10 5 10-5"/>
        <path d="M2 12l10 5 10-5"/>
      </svg>
    </div>
    <h2>AIRA — AI Reversing Assistant</h2>
    <p>Uploadez un binaire dans la sidebar, puis posez vos questions.</p>
    <div class="suggestion-chips">
      <button class="chip" data-msg="Quelles sont les fonctions suspectes dans ce binaire ?">Fonctions suspectes</button>
      <button class="chip" data-msg="Y a-t-il des techniques anti-debug ?">Anti-debug</button>
      <button class="chip" data-msg="Explique l'entrypoint de ce binaire.">Analyse entrypoint</button>
      <button class="chip" data-msg="Quelles bibliothèques sont importées ?">Imports</button>
    </div>`;
  chatEl.appendChild(welcome);
  welcome.querySelectorAll('.chip').forEach(chip => {
    chip.addEventListener('click', () => {
      inputEl.value = chip.dataset.msg;
      autoResize();
      send();
    });
  });
});

async function send() {
  const content = inputEl.value.trim();
  if (!content) return;

  appendMsg('user', content);
  inputEl.value = '';
  autoResize();
  btnSend.disabled = true;

  const provider = document.getElementById('provider').value;
  const model    = document.getElementById('model').value || undefined;

  // Mode session : on envoie juste le nouveau message + session_id + binary_path
  // Le backend gère l'historique complet
  const payload = {
    session_id:   SESSION_ID,
    provider,
    model,
    message:      content,
    binary_path:  uploadedPath || undefined,
    temperature:  0.2,
    top_p:        1.0,
  };

  showTyping();

  try {
    // Pas de timeout : on attend la réponse complète (l'IA peut prendre du temps)
    const res = await fetch('/api/chat', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify(payload),
    });
    removeTyping();
    if (!res.ok) {
      const t = await res.json().catch(() => ({ detail: res.statusText }));
      const detail = t.detail;
      const msg = Array.isArray(detail)
        ? detail.map(e => e.msg || JSON.stringify(e)).join(', ')
        : (typeof detail === 'string' ? detail : res.statusText);
      throw new Error(msg);
    }
    const data = await res.json();
    appendMsg('assistant', data.output_text || data.message || '(réponse vide)');
  } catch (e) {
    removeTyping();
    appendMsg('system', 'Erreur : ' + e.message);
  } finally {
    btnSend.disabled = inputEl.value.trim().length === 0;
    inputEl.focus();
  }
}

// Lancer la restauration de l'historique après que le DOM soit prêt
restoreHistory();
