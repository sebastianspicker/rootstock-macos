#!/usr/bin/env node

/** Verify the generated GitHub Pages artifact stays self-contained and static-only. */

import { readFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

import { demoGraph, PRIMARY_DOSSIER_ID } from "./viewer-demo-data.mjs";
import { tourSteps } from "./demo-tour.mjs";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const defaultArtifact = path.join(repositoryRoot, "graph", "generated", "pages-demo", "index.html");
const artifactPath = path.resolve(process.argv[2] ?? defaultArtifact);

const requiredMarkers = [
  'data-rootstock-pages-demo="synthetic-graphite-laboratory-bench"',
  "Graphite Laboratory Bench (synthetic)",
  "demo-primary-dossier",
  "SYN-GLB-N12",
  "SYN-GLB-E16",
  "SYN-GLB-N23",
  "SYN-GLB-E32",
  "RootstockViewer.mount(",
  'mode: "static"',
  "Network access is disabled in this static demo.",
  "Static demo · synthetic data",
  'link.href = "tour.html"',
];

const prohibitedPatterns = [
  { name: "unresolved template token", pattern: /{{[A-Z][A-Z0-9_]*}}/ },
  {
    name: "external script or stylesheet asset",
    pattern: /<(?:script|link)\b[^>]+(?:src|href)\s*=\s*["'](?!data:,["'])[^"']+["']/i,
  },
  // SVG's fixed XML namespace identifies elements; it does not request a resource.
  { name: "external network URL", pattern: /https?:\/\/(?!www\.w3\.org\/2000\/svg["'])/i },
  { name: "live API endpoint", pattern: /\/api\//i },
  {
    name: "live network primitive",
    pattern: /\b(?:fetch|XMLHttpRequest|WebSocket|EventSource)\s*\(/,
  },
];

function fail(message) {
  console.error(`ERROR: ${message}`);
  process.exitCode = 1;
}

function verifyGraphSize(nodes, edges) {
  if (nodes.length !== 30 || edges.length !== 33) {
    fail(`synthetic graph size changed unexpectedly: ${nodes.length} nodes, ${edges.length} edges`);
  }
}

function verifyNodeEvidence(nodes) {
  const nodeIds = new Set(nodes.map((node) => node.id));
  if (!nodeIds.has(PRIMARY_DOSSIER_ID)) fail("primary dossier node is missing");
  for (const node of nodes) {
    if (node.properties?.evidence_class !== "synthetic" || !node.properties?.evidence_id) {
      fail(`node lacks synthetic evidence markers: ${node.id}`);
    }
  }
  return nodeIds;
}

function verifyEdgeEvidence(edges, nodeIds) {
  for (const edge of edges) {
    if (!nodeIds.has(edge.source) || !nodeIds.has(edge.target)) {
      fail(`edge references an unknown node: ${edge.source} -> ${edge.target}`);
    }
    if (edge.properties?.evidence_class !== "synthetic" || !edge.properties?.evidence_id) {
      fail(`edge lacks synthetic evidence markers: ${edge.source} -> ${edge.target}`);
    }
  }
}

function verifySyntheticGraph() {
  const { nodes, edges } = demoGraph.graph;
  verifyGraphSize(nodes, edges);
  verifyEdgeEvidence(edges, verifyNodeEvidence(nodes));
}

async function verifyTour() {
  const directory = path.dirname(artifactPath);
  const tour = await readFile(path.join(directory, "tour.html"), "utf8");
  for (const { name, pattern } of prohibitedPatterns) {
    if (pattern.test(tour)) fail(`tour contains ${name}`);
  }
  if (!tour.includes('href="./"') || !tour.includes("Synthetic data")) {
    fail("tour must link back to the demo and disclose synthetic data");
  }
  for (const step of tourSteps) {
    if (!tour.includes(`src="screenshots/${step.file}" alt="${step.alt}"`)) {
      fail(`tour is missing its accessible screenshot: ${step.file}`);
    }
    await verifyScreenshot(directory, step.file);
  }
}

async function verifyScreenshot(directory, file) {
  const screenshot = await readFile(path.join(directory, "screenshots", file));
  const source = await readFile(path.join(repositoryRoot, "docs/assets/screenshots", file));
  if (!screenshot.equals(source)) fail(`tour screenshot differs from source: ${file}`);
  if (screenshot.subarray(0, 8).toString("hex") !== "89504e470d0a1a0a") {
    fail(`tour screenshot is not a PNG: ${file}`);
  }
}

async function main() {
  verifySyntheticGraph();
  await verifyTour();
  const html = await readFile(artifactPath, "utf8");
  if (!html.includes('<div id="app">') || !html.includes('id="graph-canvas"')) {
    fail("artifact does not contain the interactive viewer mount");
  }
  for (const marker of requiredMarkers) {
    if (!html.includes(marker)) fail(`artifact is missing required marker: ${marker}`);
  }
  for (const { name, pattern } of prohibitedPatterns) {
    if (pattern.test(html)) fail(`artifact contains ${name}`);
  }
  if (process.exitCode) return;
  console.log(`Verified static Pages demo: ${artifactPath}`);
}

main().catch((error) => {
  fail(error instanceof Error ? error.message : String(error));
});
