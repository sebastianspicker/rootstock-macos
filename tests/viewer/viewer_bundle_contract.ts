import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";

const bundle = fs.readFileSync("graph/viewer.bundle.js", "utf8");
let domLookups = 0;
const windowObject: Record<string, unknown> = {};
const context = vm.createContext({
  window: windowObject,
  get document() {
    domLookups += 1;
    throw new Error("DOM accessed before mount");
  },
});

vm.runInContext(bundle, context);
assert.equal(domLookups, 0);
assert.deepEqual(Object.keys(windowObject), ["RootstockViewer"]);

const api = windowObject.RootstockViewer as {mount(input: unknown): void};
assert.equal(Object.isFrozen(api), true);
assert.deepEqual(Object.keys(api), ["mount"]);
assert.throws(() => api.mount({graph: {nodes: [], edges: [{}]}}), /Malformed graph response/);
assert.equal(domLookups, 0);

process.stdout.write("viewer bundle contract checks passed\n");
