const http = require('node:http');
const fs = require('node:fs');
const {test, expect} = require('@playwright/test');
const AxeBuilder = require('@axe-core/playwright').default;

const graph = {
  metadata: {hostname: 'synthetic-browser-fixture', generated_at: '2026-07-11T00:00:00Z'},
  graph: {
    nodes: [
      {id: 'app', kind: 'rs_Application', label: 'Demo App', x: 200, y: 180, properties: {bundle_id: 'com.example.demo', _color: '#0a61c9'}},
      {id: 'fda', kind: 'rs_TCCPermission', label: 'Full Disk Access', x: 420, y: 180, properties: {_color: '#bd2432'}},
    ],
    edges: [{source: 'app', target: 'fda', kind: 'rs_HAS_TCC_GRANT', properties: {_traversable: true}}],
  },
};

function assembledViewer(live) {
  let script = [
    fs.readFileSync('graph/viewer.js', 'utf8'),
    fs.readFileSync('graph/viewer_spatial.js', 'utf8'),
    fs.readFileSync('graph/viewer_render.js', 'utf8'),
    fs.readFileSync('graph/viewer_analysis.js', 'utf8'),
    fs.readFileSync('graph/viewer_controls.js', 'utf8'),
    fs.readFileSync('graph/viewer_live.js', 'utf8'),
    fs.readFileSync('graph/viewer_shell.js', 'utf8'),
  ].join('\n');
  const payload = live ? {metadata: {}, graph: {nodes: [], edges: []}} : graph;
  script = script.replace(
    'let DATA = null /* VIEWER_DATA */;',
    `${live ? "const __ROOTSTOCK_LIVE__ = true; const API_BASE = '';" : ''}\nlet DATA = ${JSON.stringify(payload)};`,
  );
  return fs.readFileSync('graph/viewer_template.html', 'utf8')
    .replace('{{VIEWER_TITLE}}', live ? 'Live fixture' : 'Static fixture')
    .replace('{{VIEWER_CSS}}', fs.readFileSync('graph/viewer.css', 'utf8'))
    .replace('{{VIEWER_JS}}', script);
}

let server;
let origin;
test.beforeAll(async () => {
  server = http.createServer((request, response) => {
    if (request.url === '/static' || request.url === '/live') {
      response.setHeader('Content-Type', 'text/html; charset=utf-8');
      return response.end(assembledViewer(request.url === '/live'));
    }
    if (request.headers.authorization !== 'Bearer browser-fixture-token') {
      response.writeHead(401, {'Content-Type': 'application/json'});
      return response.end(JSON.stringify({detail: 'Missing or invalid bearer token'}));
    }
    response.setHeader('Content-Type', 'application/json');
    if (request.url === '/api/graph') return response.end(JSON.stringify(graph));
    if (request.url === '/api/queries') return response.end(JSON.stringify([
      {id: '01', name: 'Fixture query', purpose: 'Browser result fixture', category: 'Blue Team', severity: 'Informational'},
    ]));
    if (request.url === '/api/queries/01/run') return response.end(JSON.stringify({rows: [{name: 'Demo App'}], count: 1}));
    if (request.url === '/api/owned') return response.end(JSON.stringify({owned: [], count: 0}));
    response.writeHead(404);
    return response.end(JSON.stringify({detail: 'Not found'}));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  origin = `http://127.0.0.1:${server.address().port}`;
});

test.afterAll(async () => {
  await new Promise(resolve => server.close(resolve));
});

async function expectNoSeriousAxeFindings(page) {
  const result = await new AxeBuilder({page}).analyze();
  expect(result.violations.filter(item => ['serious', 'critical'].includes(item.impact))).toEqual([]);
}

test('static graph supports keyboard selection, path building, and theme override', async ({page}) => {
  await page.goto(`${origin}/static`);
  await expect(page.getByRole('button', {name: /Demo App/})).toBeVisible();
  await page.getByRole('button', {name: /Demo App/}).focus();
  await page.keyboard.press('Enter');
  await expect(page.getByRole('heading', {name: 'Demo App'})).toBeVisible();
  await expectNoSeriousAxeFindings(page);
  await page.getByRole('button', {name: 'Build path'}).click();
  await page.getByRole('button', {name: /Demo App/}).click();
  await page.getByRole('button', {name: /Full Disk Access/}).click();
  await expect(page.getByText('1 hop', {exact: true})).toBeVisible();
  await page.getByLabel('Theme').selectOption('dark');
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  await expectNoSeriousAxeFindings(page);
});

test('live viewer uses an inline session-only token gate', async ({page}) => {
  await page.goto(`${origin}/live`);
  await expect(page.getByRole('heading', {name: 'Connect to this Rootstock session'})).toBeVisible();
  await expectNoSeriousAxeFindings(page);
  await page.getByLabel('API token').fill('browser-fixture-token');
  await page.getByRole('button', {name: 'Connect'}).click();
  await expect(page.getByText('Live · connected')).toBeVisible();
  await expect(page.getByRole('button', {name: /Demo App/})).toBeVisible();
  await page.getByRole('tab', {name: 'Queries'}).click();
  await page.getByRole('button', {name: /Fixture query/}).click();
  await expect(page.getByRole('heading', {name: /Fixture query/})).toBeVisible();
  await expect(page.getByRole('button', {name: 'Highlight node'})).toBeVisible();
  await expectNoSeriousAxeFindings(page);
});

test('narrow layout does not create page-level horizontal clipping', async ({page}) => {
  test.skip(test.info().project.name !== 'narrow');
  await page.goto(`${origin}/static`);
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  expect(overflow).toBeLessThanOrEqual(1);
  await expect(page.getByRole('tab', {name: 'Queries'})).toBeVisible();
  await expect(page.getByLabel('Theme')).toBeVisible();
  expect(await page.getByLabel('Theme').evaluate(element => element.getBoundingClientRect().height)).toBeGreaterThanOrEqual(44);
});
