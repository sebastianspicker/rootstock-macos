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

function makeElement(id) {
  return {
    id,
    textContent: '',
    children: [],
    classList: {
      classes: new Set(),
      add(name) { this.classes.add(name); },
      remove(name) { this.classes.delete(name); },
    },
    appendChild(child) {
      this.children.push(child);
      return child;
    },
  };
}

function installDocument() {
  const elements = {};
  for (const id of ['results-panel', 'results-body', 'results-meta', 'results-title']) {
    elements[id] = makeElement(id);
  }
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

function el(tag, attrs = {}, children = []) {
  const childList = Array.isArray(children) ? children : [];
  return {
    tag,
    children: childList,
    textContent: attrs.textContent || '',
    className: attrs.className || '',
    ...attrs,
  };
}

function textOf(node) {
  if (!node) return '';
  const own = node.textContent || '';
  const childText = Array.isArray(node.children) ? node.children.map(textOf).join(' ') : '';
  return (own + ' ' + childText).trim();
}

__GET_API_TOKEN__

__API_FETCH__

__RUN_LIVE_QUERY__

async function flushPromises() {
  await new Promise(resolve => setTimeout(resolve, 0));
}

async function runScenario(payload, status, statusText = '') {
  const elements = installDocument();
  globalThis.fetch = async () => new Response(JSON.stringify(payload), {
    status,
    statusText,
    headers: {'Content-Type': 'application/json'},
  });
  runLiveQuery({id: '79', name: 'Critical query', category: 'Red Team', severity: 'Critical'});
  await flushPromises();
  return elements;
}

(async () => {
  let elements = await runScenario({detail: 'Query execution failed'}, 500, 'Internal Server Error');
  let bodyText = elements['results-body'].children.map(textOf).join(' ');
  assert.match(elements['results-meta'].textContent, /^Error: HTTP 500 Internal Server Error: Query execution failed/);
  assert.match(bodyText, /Query failed/);
  assert.doesNotMatch(bodyText, /No findings|positive security result/);

  elements = await runScenario({detail: 'wrong shape'}, 200);
  bodyText = elements['results-body'].children.map(textOf).join(' ');
  assert.match(elements['results-meta'].textContent, /^Error: Malformed query response/);
  assert.match(bodyText, /Query failed/);
  assert.doesNotMatch(bodyText, /No findings|positive security result/);

  elements = await runScenario({rows: [], count: 0}, 200);
  bodyText = elements['results-body'].children.map(textOf).join(' ');
  assert.match(elements['results-meta'].textContent, /^0 row\(s\)/);
  assert.match(bodyText, /No results/);
  assert.match(bodyText, /positive security result/);
})().catch(err => {
  console.error(err && err.stack ? err.stack : err);
  process.exit(1);
});
