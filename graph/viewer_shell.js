/* global SESSION_STORAGE_NAME, activeEdgeKinds, activeNodeKinds, apiFetch */
/* global buildFilters, closeInspector, closeResults, computeVisibility */
/* global edgeKinds, el, exitFocusMode, exitPathMode, exportPNG */
/* global highlightQueryResult, inspectNode, isLive, kindMeta, liveRefresh */
/* global liveShowOwned, liveTierClassify, markDirty, resetZoom, resizeCanvas */
/* global selectedNode, setLiveStatus, startLiveSession, toggleAttackPaths */
/* global toggleClustering, toggleLabels, togglePathMode, toggleVulnFilter */
/* global searchTerm:writable, toggleOwned:writable */
/* exported searchTerm, toggleOwned */

// ── Custom Cypher console ────────────────────────────────────────────────
function runCustomCypher() {
  if (!isLive) return;
  const input = document.getElementById('cypher-input');
  const cypher = input.value.trim();
  if (!cypher) {
    setLiveStatus('Enter a read-only Cypher query before running it.', 'error');
    input.focus();
    return;
  }

  // Save to history (localStorage, last 10)
  const historyStorageName = 'rootstock.cypherHistory';
  let history = [];
  try { history = JSON.parse(localStorage.getItem(historyStorageName) || '[]'); } catch(e) {}
  history = [cypher, ...history.filter(h => h !== cypher)].slice(0, 10);
  localStorage.setItem(historyStorageName, JSON.stringify(history));
  _updateCypherHistory(history);

  const panel = document.getElementById('results-panel');
  const body = document.getElementById('results-body');
  const meta = document.getElementById('results-meta');
  document.getElementById('results-title').textContent = 'Custom Cypher';
  meta.textContent = 'Running...';
  body.textContent = '';
  document.getElementById('inspector').classList.remove('open');
  document.getElementById('detail-empty').hidden = true;
  panel.classList.add('open');
  const runButton = document.getElementById('run-cypher');
  runButton.disabled = true;
  runButton.textContent = 'Running…';

  apiFetch('/api/cypher', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({cypher: cypher, params: {}})
  })
    .then(r => {
      if (r.status === 403) return r.json().then(d => { throw new Error(d.detail || 'Write operations not allowed'); });
      if (!r.ok) return r.json().then(d => { throw new Error(d.detail || 'Query failed'); });
      return r.json();
    })
    .then(data => {
      meta.textContent = data.count + ' row(s)';
      if (!data.rows || data.rows.length === 0) {
        body.appendChild(el('div', {textContent: 'No results.', className: 'prop-row'}));
        return;
      }
      const headers = data.columns || Object.keys(data.rows[0]);
      const table = document.createElement('table');
      table.appendChild(el('caption', {className: 'sr-only', textContent: 'Custom Cypher results'}));
      const thead = document.createElement('thead');
      const hrow = document.createElement('tr');
      headers.forEach(h => { const th = document.createElement('th'); th.textContent = h; hrow.appendChild(th); });
      hrow.appendChild(el('th', {textContent: 'Action', scope: 'col'}));
      thead.appendChild(hrow);
      table.appendChild(thead);
      const tbody = document.createElement('tbody');
      data.rows.forEach(row => {
        const tr = document.createElement('tr');
        const rowValues = new Map(Object.entries(row));
        headers.forEach(h => {
          const td = document.createElement('td');
          const val = rowValues.get(h);
          td.textContent = Array.isArray(val) ? val.join(', ') : String(val ?? '');
          td.title = td.textContent;
          tr.appendChild(td);
        });
        const actionCell = document.createElement('td');
        actionCell.appendChild(el('button', {type: 'button', textContent: 'Highlight node', onclick: () => highlightQueryResult(row)}));
        tr.appendChild(actionCell);
        tbody.appendChild(tr);
      });
      table.appendChild(tbody);
      body.textContent = '';
      body.appendChild(table);
    })
    .catch(err => {
      meta.textContent = 'Error: ' + err.message;
      body.textContent = '';
      body.appendChild(el('div', {className: 'empty-state', textContent: 'Query failed: ' + err.message}));
    })
    .finally(() => {
      runButton.disabled = false;
      runButton.textContent = 'Run query';
    });
}

function _updateCypherHistory(history) {
  const sel = document.getElementById('cypher-history-select');
  if (!sel) return;
  // Clear existing options safely
  while (sel.options.length > 1) sel.remove(1);
  history.forEach(q => {
    const opt = document.createElement('option');
    opt.value = q;
    opt.textContent = q.length > 40 ? q.substring(0, 40) + '...' : q;
    sel.appendChild(opt);
  });
}

// Load history on startup
try {
  const legacyHistoryStorageName = '__rs_cypher_history__';
  if (!localStorage.getItem('rootstock.cypherHistory') && localStorage.getItem(legacyHistoryStorageName)) {
    localStorage.setItem('rootstock.cypherHistory', localStorage.getItem(legacyHistoryStorageName));
    localStorage.removeItem(legacyHistoryStorageName);
  }
  const h = JSON.parse(localStorage.getItem('rootstock.cypherHistory') || '[]');
  if (h.length) _updateCypherHistory(h);
} catch(e) {}

// Allow Ctrl+Enter to run
document.getElementById('cypher-input')?.addEventListener('keydown', function(e) {
  if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') { e.preventDefault(); runCustomCypher(); }
});

// Override toggleOwned in live mode to persist to API
if (isLive) {
  toggleOwned = function(d) {
    const wasOwned = d.properties?.owned === true;
    const body = {};
    if (d.properties?.bundle_id) body.bundle_ids = [d.properties.bundle_id];
    else if (d.properties?.name && d.kind === 'rs_User') body.usernames = [d.properties.name];
    else {
      setLiveStatus('Owned update failed: node has no supported identifier.', 'error');
      return;
    }

    const path = wasOwned ? '/api/clear-owned' : '/api/mark-owned';
    const action = wasOwned ? 'Clear owned' : 'Mark owned';
    setLiveStatus(action + ' pending...', 'pending');
    apiFetch(path, {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(body)
    })
      .then(r => r.json())
      .then(data => {
        const responseCount = wasOwned ? data?.cleared : data?.marked;
        if (typeof responseCount !== 'number') {
          throw new Error('Malformed owned update response');
        }
        if (responseCount <= 0) {
          throw new Error('No matching nodes changed');
        }
        if (!d.properties) d.properties = {};
        d.properties.owned = !wasOwned;
        markDirty();
        if (selectedNode?.id === d.id) inspectNode(d);
        setLiveStatus(action + ' saved for ' + responseCount + ' node(s).', 'ok');
      })
      .catch(err => {
        if (!d.properties) d.properties = {};
        d.properties.owned = wasOwned;
        markDirty();
        if (selectedNode?.id === d.id) inspectNode(d);
        setLiveStatus(action + ' failed: ' + err.message, 'error');
      });
  };
}

// Keyboard: Escape closes results panel
document.addEventListener('keydown', e => {
  if (e.key === 'Escape' && document.getElementById('results-panel').classList.contains('open')) {
    closeResults();
    e.stopPropagation();
  }
}, true);

// ── Semantic shell controls ────────────────────────────────────────────────
function selectWorkbenchTab(name) {
  const explore = name === 'explore';
  document.getElementById('tab-explore').setAttribute('aria-selected', String(explore));
  document.getElementById('tab-queries').setAttribute('aria-selected', String(!explore));
  document.getElementById('explore-panel').hidden = !explore;
  document.getElementById('queries-panel').hidden = explore;
  resizeCanvas();
}

document.getElementById('tab-explore').addEventListener('click', () => selectWorkbenchTab('explore'));
document.getElementById('tab-queries').addEventListener('click', () => selectWorkbenchTab('queries'));
document.querySelector('[role="tablist"]').addEventListener('keydown', event => {
  if (event.key !== 'ArrowLeft' && event.key !== 'ArrowRight') return;
  event.preventDefault();
  const next = event.key === 'ArrowRight' ? document.getElementById('tab-queries') : document.getElementById('tab-explore');
  selectWorkbenchTab(next.id === 'tab-queries' ? 'queries' : 'explore');
  next.focus();
});

document.getElementById('clear-search').addEventListener('click', () => {
  const search = document.getElementById('search');
  search.value = '';
  searchTerm = '';
  computeVisibility();
  markDirty();
  search.focus();
});

document.getElementById('clear-filters').addEventListener('click', () => {
  activeNodeKinds.clear();
  kindMeta.forEach((_info, kind) => activeNodeKinds.add(kind));
  activeEdgeKinds.clear();
  edgeKinds.forEach((_info, kind) => activeEdgeKinds.add(kind));
  searchTerm = '';
  document.getElementById('search').value = '';
  buildFilters();
  computeVisibility();
  markDirty();
});

const themeSelect = document.getElementById('theme-select');
const savedTheme = localStorage.getItem('rootstock.theme') || 'system';
themeSelect.value = ['system', 'light', 'dark'].includes(savedTheme) ? savedTheme : 'system';
function applyTheme(value) {
  if (value === 'system') {
    document.documentElement.removeAttribute('data-theme');
    document.body.removeAttribute('data-theme');
  } else {
    document.documentElement.setAttribute('data-theme', value);
    document.body.setAttribute('data-theme', value);
  }
  localStorage.setItem('rootstock.theme', value);
  markDirty();
}
applyTheme(themeSelect.value);
themeSelect.addEventListener('change', event => applyTheme(event.target.value));

document.getElementById('btn-reset').addEventListener('click', resetZoom);
document.getElementById('btn-labels').addEventListener('click', toggleLabels);
document.getElementById('btn-cluster').addEventListener('click', toggleClustering);
document.getElementById('btn-attack').addEventListener('click', toggleAttackPaths);
document.getElementById('btn-path').addEventListener('click', togglePathMode);
document.getElementById('btn-vuln').addEventListener('click', toggleVulnFilter);
document.getElementById('btn-export').addEventListener('click', exportPNG);
document.getElementById('focus-exit').addEventListener('click', exitFocusMode);
document.getElementById('path-exit').addEventListener('click', exitPathMode);
document.getElementById('inspector-close').addEventListener('click', closeInspector);
document.getElementById('results-close').addEventListener('click', closeResults);
document.getElementById('run-cypher').addEventListener('click', runCustomCypher);
document.getElementById('live-refresh').addEventListener('click', liveRefresh);
document.getElementById('live-tier').addEventListener('click', liveTierClassify);
document.getElementById('live-owned').addEventListener('click', liveShowOwned);
document.getElementById('cypher-history-select').addEventListener('change', event => {
  if (event.target.value) document.getElementById('cypher-input').value = event.target.value;
});
document.getElementById('clear-history').addEventListener('click', () => {
  localStorage.removeItem('rootstock.cypherHistory');
  _updateCypherHistory([]);
  setLiveStatus('Local Cypher history cleared.', 'ok');
});

document.getElementById('connection-form').addEventListener('submit', event => {
  event.preventDefault();
  const input = document.getElementById('api-token');
  const token = input.value.trim();
  if (!token) return;
  sessionStorage.setItem(SESSION_STORAGE_NAME, token);
  input.value = '';
  startLiveSession();
});
