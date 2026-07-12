/* global API_BASE, centerOnNode, el, inspectNode, markDirty, nodes */
/* global replaceGraphData, resetZoom */
/* global selectedNode:writable */
/* exported closeResults, liveShowOwned, liveTierClassify */
/* exported selectedNode */

// ── Live API integration ─────────────────────────────────────────────────
const isLive = typeof __ROOTSTOCK_LIVE__ !== 'undefined';
const SESSION_STORAGE_NAME = '__rootstock_api_token__';

function getApiToken() {
  return sessionStorage.getItem(SESSION_STORAGE_NAME) || '';
}

function showConnectionGate(message = '') {
  if (!isLive) return;
  const gate = document.getElementById('connection-gate');
  const error = document.getElementById('connection-error');
  gate.hidden = false;
  error.textContent = message;
  error.hidden = !message;
  const status = document.getElementById('connection-status');
  status.textContent = message ? 'Connection required' : 'Not connected';
  status.className = 'status-chip' + (message ? ' error' : '');
  if (typeof requestAnimationFrame === 'function') {
    requestAnimationFrame(() => document.getElementById('api-token').focus());
  }
}

function hideConnectionGate() {
  document.getElementById('connection-gate').hidden = true;
  const status = document.getElementById('connection-status');
  status.textContent = 'Live · connected';
  status.className = 'status-chip connected';
}

async function responseErrorDetail(response) {
  const text = await response.text();
  if (!text) return '';
  try {
    const payload = JSON.parse(text);
    if (typeof payload.detail === 'string') return payload.detail;
    return payload.detail ? JSON.stringify(payload.detail) : text;
  } catch (_error) {
    return text;
  }
}

async function requireSuccessfulResponse(response) {
  if (response.status === 401) {
    sessionStorage.removeItem(SESSION_STORAGE_NAME);
    showConnectionGate('Session expired or token rejected. Enter the current API token.');
  }
  if (response.ok) return response;
  const detail = await responseErrorDetail(response);
  if (response.status === 401) throw new Error('Unauthorized');
  const status = 'HTTP ' + response.status + (response.statusText ? ' ' + response.statusText : '');
  throw new Error(detail ? status + ': ' + detail : status);
}

function apiFetch(path, options = {}) {
  const headers = new Headers(options.headers || {});
  const token = getApiToken();
  if (token) headers.set('Authorization', 'Bearer ' + token);
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 15000);
  return window.fetch(API_BASE + path, {
    ...options,
    headers,
    signal: options.signal || controller.signal,
  }).then(requireSuccessfulResponse).catch(error => {
    if (error?.name === 'AbortError') throw new Error('Request timed out after 15 seconds');
    throw error;
  }).finally(() => clearTimeout(timeoutId));
}

function loadLiveQueries() {
  const list = document.getElementById('query-list');
  list.textContent = '';
  list.appendChild(el('p', {className: 'empty-state', textContent: 'Loading saved queries…'}));
  return apiFetch('/api/queries')
    .then(r => r.json())
    .then(queries => {
      if (!Array.isArray(queries)) throw new Error('Malformed query-list response');
      list.textContent = '';
      const grouped = {
        'Red Team': queries.filter(q => q.category === 'Red Team'),
        'Blue Team': queries.filter(q => q.category === 'Blue Team'),
        'Forensic': queries.filter(q => q.category === 'Forensic'),
      };
      Object.entries(grouped).forEach(([cat, qs]) => {
        qs.forEach(q => {
          const sevClass = String(q.severity || '').toLowerCase();
          const item = el('button', {type: 'button', className: 'query-item', onclick: () => runLiveQuery(q)}, [
            el('span', {className: 'severity-dot ' + sevClass, 'aria-hidden': 'true'}),
            el('span', {className: 'query-name', textContent: '[' + q.id + '] ' + q.name}),
            el('span', {className: 'cat-badge', textContent: cat.split(' ')[0]}),
          ]);
          item.title = q.purpose || q.name;
          list.appendChild(item);
        });
      });
      if (!queries.length) list.appendChild(el('p', {className: 'empty-state', textContent: 'No saved queries are available.'}));
    })
    .catch(err => {
      list.textContent = '';
      list.appendChild(el('p', {className: 'empty-state', textContent: 'Saved queries failed to load: ' + err.message}));
      setLiveStatus('Saved queries failed to load: ' + err.message, 'error');
    });
}

function startLiveSession() {
  hideConnectionGate();
  loadLiveQueries();
  liveRefresh();
}

if (isLive) {
  document.getElementById('query-section').classList.add('live');
  document.getElementById('live-actions').classList.add('live');
  document.getElementById('custom-query-section').hidden = false;
  document.getElementById('connection-status').textContent = 'Not connected';
  if (getApiToken()) startLiveSession();
  else showConnectionGate();
} else {
  document.getElementById('connection-status').textContent = 'Offline · self-contained';
}

function runLiveQuery(q) {
  if (!isLive) return;
  const panel = document.getElementById('results-panel');
  const body = document.getElementById('results-body');
  const meta = document.getElementById('results-meta');
  document.getElementById('results-title').textContent = '[' + q.id + '] ' + q.name;
  meta.textContent = 'Loading...';
  body.textContent = '';
  document.getElementById('inspector').classList.remove('open');
  document.getElementById('detail-empty').hidden = true;
  panel.classList.add('open');

  apiFetch('/api/queries/' + q.id + '/run', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({params: {}})
  })
    .then(r => r.json())
    .then(data => {
      if (!data || !Array.isArray(data.rows) || typeof data.count !== 'number') {
        throw new Error('Malformed query response');
      }
      meta.textContent = data.count + ' row(s) \u00b7 ' + q.category + ' \u00b7 ' + q.severity;
      if (!data.rows || data.rows.length === 0) {
        body.textContent = '';
        body.appendChild(el('div', {textContent: 'No results.', className: 'prop-row'}));
        if (q.severity === 'Critical' || q.severity === 'High') {
          body.appendChild(el('div', {
            textContent: '\u2713 No findings \u2014 positive security result.',
            className: 'prop-row'
          }));
        }
        return;
      }
      // Build table
      const headers = Object.keys(data.rows[0]);
      const table = document.createElement('table');
      table.appendChild(el('caption', {className: 'sr-only', textContent: 'Results for ' + q.name}));
      const thead = document.createElement('thead');
      const hrow = document.createElement('tr');
      headers.forEach(h => {
        const th = document.createElement('th');
        th.textContent = h;
        hrow.appendChild(th);
      });
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
      body.appendChild(el('div', {className: 'prop-row'}, [
        el('strong', {textContent: 'Query failed'}),
        el('span', {textContent: err.message})
      ]));
    });
}

function highlightQueryResult(row) {
  const bid = [row.bundle_id, row.app_bundle_id].find(Boolean);
  const name = [row.app, row.name, row.attacker, row.victim_user].find(Boolean);
  const bundleMatch = bid ? nodes.find(node => node.properties?.bundle_id === bid) : null;
  const nameMatch = name ? nodes.find(node =>
    [node.label, node.properties?.name].includes(name)) : null;
  const node = bundleMatch || nameMatch;
  if (!node) return;
  centerOnNode(node);
  selectedNode = node;
  inspectNode(node);
  markDirty();
}

function closeResults() {
  document.getElementById('results-panel').classList.remove('open');
  document.getElementById('detail-empty').hidden = document.getElementById('inspector').classList.contains('open');
}

function setLiveStatus(message, state = '') {
  const status = document.getElementById('live-status');
  if (!status) return;
  status.textContent = message || '';
  status.className = 'live-status' + (state ? ' ' + state : '');
}

function liveRefresh() {
  if (!isLive) return;
  setLiveStatus('Refreshing graph...', 'pending');
  apiFetch('/api/graph')
    .then(r => r.json())
    .then(data => {
      if (!data || !data.graph || !Array.isArray(data.graph.nodes) || !Array.isArray(data.graph.edges)) {
        throw new Error('Malformed graph response');
      }
      replaceGraphData(data);
      resetZoom();
      setLiveStatus('Graph refreshed.', 'ok');
    })
    .catch(err => {
      setLiveStatus('Graph refresh failed: ' + err.message, 'error');
    });
}

function liveTierClassify() {
  if (!isLive) return;
  setLiveStatus('Classifying tiers...', 'pending');
  apiFetch('/api/tier-classify', {method: 'POST'})
    .then(r => r.json())
    .then(data => {
      if (!data || typeof data.tier0 !== 'number' || typeof data.tier1 !== 'number' ||
          typeof data.tier2 !== 'number' || typeof data.total !== 'number') {
        throw new Error('Malformed tier response');
      }
      if (data.total !== data.tier0 + data.tier1 + data.tier2) {
        throw new Error('Malformed tier response');
      }
      const message = 'Tier classification complete: T0=' + data.tier0 + ' T1=' + data.tier1 + ' T2=' + data.tier2;
      setLiveStatus(message, 'ok');
      alert(message);
      liveRefresh();
    })
    .catch(err => {
      setLiveStatus('Tier classification failed: ' + err.message, 'error');
    });
}

function liveShowOwned() {
  if (!isLive) return;
  setLiveStatus('Loading owned nodes...', 'pending');
  apiFetch('/api/owned')
    .then(r => r.json())
    .then(data => {
      if (!data || !Array.isArray(data.owned) || typeof data.count !== 'number') {
        throw new Error('Malformed owned response');
      }
      if (data.count !== data.owned.length) {
        throw new Error('Malformed owned response');
      }
      if (data.count === 0) {
        setLiveStatus('No owned nodes returned.', 'ok');
        alert('No owned nodes.');
        return;
      }
      // Highlight owned nodes by selecting all matching
      let highlighted = 0;
      data.owned.forEach(item => {
        const name = item.name;
        let matched = false;
        nodes.forEach(n => {
          if (n.properties?.name === name || n.properties?.bundle_id === name) {
            if (!n.properties) n.properties = {};
            n.properties.owned = true;
            matched = true;
          }
        });
        if (matched) highlighted++;
      });
      if (highlighted > 0) markDirty();
      if (highlighted === data.count) {
        setLiveStatus(data.count + ' owned node(s) highlighted.', 'ok');
        alert(data.count + ' owned node(s) highlighted.');
      } else {
        setLiveStatus('Owned list loaded, but only ' + highlighted + ' of ' + data.count + ' matched the current graph.', 'error');
      }
    })
    .catch(err => {
      setLiveStatus('Show owned failed: ' + err.message, 'error');
    });
}
