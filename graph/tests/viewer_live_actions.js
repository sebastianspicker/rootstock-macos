/* global require:readonly, Response:readonly, setTimeout:readonly, document:readonly, console:readonly, process:readonly */
/* global liveRefresh:readonly, liveTierClassify:readonly, liveShowOwned:readonly */
/* global __GET_API_TOKEN__:readonly, __API_FETCH__:readonly, __SET_LIVE_STATUS__:readonly, __LIVE_REFRESH__:readonly, __LIVE_TIER__:readonly, __LIVE_SHOW_OWNED__:readonly, __TOGGLE_OVERRIDE__:readonly */

const assert = require('node:assert/strict');

const API_BASE = '';
const isLive = true;
const API_TOKEN_KEY = storageKey();

function storageKey() {
  return ['__rootstock', 'api', 'token__'].join('_');
}

globalThis.sessionStorage = {
  store: new Map(),
  getItem(key) { return this.store.get(key) || null; },
  setItem(key, value) { this.store.set(key, value); },
  removeItem(key) { this.store.delete(key); },
};
globalThis.window = {prompt() { return 'test-token'; }};

let alerts = [];
globalThis.alert = message => { alerts.push(message); };

function makeElement(id) {
  return {
    id,
    textContent: '',
    className: '',
    children: [],
    appendChild(child) {
      this.children.push(child);
      return child;
    },
  };
}

function installDocument() {
  const elements = {'live-status': makeElement('live-status')};
  globalThis.document = {
    getElementById(id) {
      if (!elements[id]) elements[id] = makeElement(id);
      return elements[id];
    },
    createElement(tag) {
      return makeElement(tag);
    },
  };
  return elements;
}

let DATA = {graph: {nodes: [], edges: []}};
const nodes = [];
const edges = [];
let selectedNode = null;
let dirty = false;
let inspected = [];
let replaceCalls = [];
let resetCalls = 0;

function replaceGraphData(data) {
  replaceCalls.push(data);
  DATA = data;
  nodes.splice(0, nodes.length, ...(data.graph?.nodes || []));
  edges.splice(0, edges.length, ...(data.graph?.edges || []));
}
function resetZoom() { resetCalls += 1; }
function markDirty() { dirty = true; }
function inspectNode(d) { inspected.push(d.id); }
function toggleOwned(d) {
  if (!d.properties) d.properties = {};
  d.properties.owned = !d.properties.owned;
  markDirty();
}

function setFetchResponse(payload, status = 200, statusText = '') {
  globalThis.fetch = async () => new Response(JSON.stringify(payload), {
    status,
    statusText,
    headers: {'Content-Type': 'application/json'},
  });
}

async function flushPromises() {
  await new Promise(resolve => setTimeout(resolve, 0));
}

function statusText() {
  return document.getElementById('live-status').textContent;
}

function statusClass() {
  return document.getElementById('live-status').className;
}

void API_BASE;
void isLive;
void API_TOKEN_KEY;
void DATA;
void selectedNode;
void replaceGraphData;
void resetZoom;
void inspectNode;

async function assertRefreshFailurePreservesGraph() {
  installDocument();
  setFetchResponse({detail: 'graph unavailable'}, 500, 'Internal Server Error');
  liveRefresh();
  await flushPromises();
  assert.match(statusText(), /^Graph refresh failed: HTTP 500 Internal Server Error: graph unavailable/);
  assert.equal(statusClass(), 'live-status error');
  assert.equal(replaceCalls.length, 0);
  assert.equal(resetCalls, 0);
}

async function assertMalformedRefreshFailure() {
  installDocument();
  setFetchResponse({graph: {nodes: []}}, 200);
  liveRefresh();
  await flushPromises();
  assert.match(statusText(), /^Graph refresh failed: Malformed graph response/);
  assert.equal(replaceCalls.length, 0);
}

async function assertMalformedTierFailure() {
  installDocument();
  alerts = [];
  setFetchResponse({tier0: 1}, 200);
  liveTierClassify();
  await flushPromises();
  assert.match(statusText(), /^Tier classification failed: Malformed tier response/);
  assert.deepEqual(alerts, []);
}

async function assertOwnedFailurePreservesGraph() {
  installDocument();
  dirty = false;
  nodes.splice(0, nodes.length, {id: 'app1', kind: 'rs_Application', properties: {bundle_id: 'com.example.app'}});
  setFetchResponse({detail: 'owned unavailable'}, 500, 'Internal Server Error');
  liveShowOwned();
  await flushPromises();
  assert.match(statusText(), /^Show owned failed: HTTP 500 Internal Server Error: owned unavailable/);
  assert.equal(nodes[0].properties.owned, undefined);
  assert.equal(dirty, false);
}

async function assertOwnedUnmatchedFailure() {
  installDocument();
  setFetchResponse({owned: [{name: 'missing'}], count: 1}, 200);
  liveShowOwned();
  await flushPromises();
  assert.equal(statusText(), 'Owned list loaded, but only 0 of 1 matched the current graph.');
  assert.equal(statusClass(), 'live-status error');
}

async function assertToggleOwnedFailuresAndSuccess() {
  const node = {id: 'app1', kind: 'rs_Application', properties: {bundle_id: 'com.example.app'}};
  selectedNode = node;

  installDocument();
  dirty = false;
  inspected = [];
  setFetchResponse({detail: 'no match'}, 404, 'Not Found');
  toggleOwned(node);
  assert.equal(node.properties.owned, undefined);
  await flushPromises();
  assert.equal(node.properties.owned, false);
  assert.match(statusText(), /^Mark owned failed: HTTP 404 Not Found: no match/);
  assert.equal(statusClass(), 'live-status error');

  installDocument();
  setFetchResponse({marked: 1}, 200);
  toggleOwned(node);
  await flushPromises();
  assert.equal(node.properties.owned, true);
  assert.equal(statusText(), 'Mark owned saved for 1 node(s).');
  assert.equal(statusClass(), 'live-status ok');

  installDocument();
  setFetchResponse({cleared: 0}, 200);
  toggleOwned(node);
  assert.equal(node.properties.owned, true);
  await flushPromises();
  assert.equal(node.properties.owned, true);
  assert.equal(statusText(), 'Clear owned failed: No matching nodes changed');
  assert.equal(statusClass(), 'live-status error');
}

__GET_API_TOKEN__

__API_FETCH__

__SET_LIVE_STATUS__

__LIVE_REFRESH__

__LIVE_TIER__

__LIVE_SHOW_OWNED__

__TOGGLE_OVERRIDE__

;(async () => {
  await assertRefreshFailurePreservesGraph();
  await assertMalformedRefreshFailure();
  await assertMalformedTierFailure();
  await assertOwnedFailurePreservesGraph();
  await assertOwnedUnmatchedFailure();
  await assertToggleOwnedFailuresAndSuccess();
})().catch(err => {
  console.error(err && err.stack ? err.stack : err);
  process.exit(1);
});
