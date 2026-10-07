/** Screenshot captions shared by the Pages builder and capture command. */
export const tourSteps = [
  {
    file: "scope.png",
    title: "Choose a question",
    text: "Check the source and the collection warning, pick a security question, then select Inspect snapshot. The demo reads its bundled data in the browser.",
    alt: "Scope screen with synthetic source metadata, a collection warning, and three security questions",
  },
  {
    file: "evidence.png",
    title: "Read the evidence",
    text: "The modeled injection path leads to Fixture Notes and its recorded Full Disk Access grant. Recorded values and inferred relationships are marked separately, next to the recommendations.",
    alt: "Fixture Notes evidence showing a modeled injection path, Full Disk Access grant, and recommendations",
  },
  {
    file: "report.png",
    title: "Export a summary",
    text: "Prepare report downloads a Markdown or HTML summary of the loaded snapshot. The full assessment report needs the local Neo4j workflow.",
    alt: "Snapshot summary screen with Markdown and HTML options, filename, and included context",
  },
  {
    file: "graph.png",
    title: "Explore the graph",
    text: "Graph tools opens triage, the graph, paths, and queries. Search or filter nodes, open its evidence, or trace a route between two endpoints. Saved Cypher queries need a live local session.",
    alt: "Interactive synthetic graph with node filters, search, and an evidence inspector",
  },
];

/** Layout for the tour only; everything else comes from the viewer's own stylesheet. */
const tourCss = `
.tour-content { grid-template-columns: minmax(0, 1fr); }
.tour-open {
  display: inline-flex;
  align-items: center;
  min-height: 34px;
  margin-left: auto;
  padding: 4px 14px;
  border: 1px solid var(--rule-strong);
  border-radius: var(--radius);
  color: var(--text);
  font: var(--size-2) / 1 var(--font-ui);
  text-decoration: none;
  white-space: nowrap;
}
.tour-open:hover { border-color: var(--text); background: var(--hover); }
.tour-open:focus-visible, .tour-step a:focus-visible { outline: 2px solid var(--focus-ring); outline-offset: 3px; }
.tour-step { margin: 0; padding: var(--space-6) 0; border-top: 1px solid var(--rule); }
.tour-step figcaption { max-width: 44em; }
.tour-step figcaption p { margin-top: var(--space-2); color: var(--muted); }
.tour-step img {
  display: block;
  width: 100%;
  height: auto;
  margin-top: var(--space-4);
  border: 1px solid var(--rule-strong);
  border-radius: var(--radius);
  box-sizing: border-box;
}
`;

function escapeHtml(text) {
  return text.replace(/[&<>"]/g, (character) => `&#${character.charCodeAt(0)};`);
}

function renderStep(step, index) {
  const id = step.file.replace(".png", "");
  return `<figure class="tour-step" id="${id}">
<figcaption><p class="folio-sheet">Step ${index + 1} of ${tourSteps.length}</p><h2>${escapeHtml(step.title)}</h2><p>${escapeHtml(step.text)}</p></figcaption>
<a href="screenshots/${step.file}" aria-label="View full-size capture: ${escapeHtml(step.title)}"><img src="screenshots/${step.file}" alt="${step.alt}" width="1440" height="1050" loading="lazy"></a>
</figure>`;
}

/** Renders tour.html with the viewer's stylesheet so it matches the product it shows. */
export function renderTour(viewerCss) {
  return `<!doctype html>
<html lang="en">
<head>
<link rel="icon" href="data:,">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="description" content="Screenshots of the Rootstock evidence viewer using synthetic data.">
<title>Rootstock - Screenshot tour</title>
<style>
${viewerCss}
${tourCss}
</style>
</head>
<body class="folio-enabled">
<div id="evidence-folio">
<header class="folio-topbar">
<div class="folio-brand"><span class="folio-mark-r" aria-hidden="true">R</span><span>Rootstock</span></div>
<p class="folio-top-meta">Graphite Laboratory Bench (synthetic) · screenshot tour</p>
<p class="folio-source-label">Synthetic data</p>
<a class="tour-open" href="./">Open the demo</a>
</header>
<main class="folio-content tour-content">
<section class="folio-main-column">
<header class="folio-intro">
<p class="folio-sheet">Rootstock viewer · four captures</p>
<h1>Screenshot tour</h1>
<p class="folio-lead">Rootstock collects macOS security metadata, builds a graph in Neo4j, and shows the evidence in this viewer. These captures use a fictional dataset. The demo scans no host and connects to no database.</p>
</header>
${tourSteps.map(renderStep).join("\n")}
</section>
</main>
<footer class="folio-footer">
<p class="folio-code">Synthetic data · nothing leaves this browser</p>
<p class="folio-code">Modeled exposure, not a confirmed compromise</p>
</footer>
</div>
</body>
</html>
`;
}
