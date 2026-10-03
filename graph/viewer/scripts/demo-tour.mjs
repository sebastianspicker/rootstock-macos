/** Screenshot captions shared by the Pages builder and capture command. */
export const tourSteps = [
  {
    file: "scope.png",
    title: "1. Choose a question",
    text: "Start with the source and collection warning. Choose a security question, then select Inspect snapshot. The demo inspects its bundled evidence locally.",
    alt: "Scope screen with synthetic source metadata, a collection warning, and three security questions",
  },
  {
    file: "evidence.png",
    title: "2. Read the evidence",
    text: "Follow the modeled injection path into Fixture Notes and its recorded Full Disk Access grant. The evidence table separates recorded values from inference; recommendations explain what to review.",
    alt: "Fixture Notes evidence showing a modeled injection path, Full Disk Access grant, and recommendations",
  },
  {
    file: "report.png",
    title: "3. Export a summary",
    text: "Select Prepare report to download a Markdown or HTML snapshot summary. This browser-only export summarizes the loaded data; the full assessment report requires the local Neo4j workflow.",
    alt: "Snapshot summary screen with Markdown and HTML options, filename, and included context",
  },
  {
    file: "graph.png",
    title: "4. Explore the graph",
    text: "Open Graph tools, then Graph, to inspect nodes and relationships. Search the node list, review a dossier, or use Paths to trace explicit endpoints. Saved Cypher queries require a live local session.",
    alt: "Interactive synthetic graph with node filters, search, and an evidence inspector",
  },
];

export function renderTour() {
  return `<!doctype html>
<html lang="en">
<head>
<link rel="icon" href="data:,">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="description" content="A screenshot tour of Rootstock's macOS security evidence viewer, using synthetic data.">
<title>Rootstock | Screenshot tour</title>
<style>
  :root { color-scheme: light dark; --paper: #f3efe6; --ink: #1d1b17; --muted: #4d483f; --rule: rgba(29, 27, 23, 0.16); --oxide: #b23f28; --serif: "Iowan Old Style", Charter, "Sitka Text", Cambria, Georgia, serif; font: 17px/1.6 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: var(--paper); color: var(--ink); }
  @media (prefers-color-scheme: dark) { :root { --paper: #151411; --ink: #ebe5d8; --muted: #bbb3a3; --rule: rgba(235, 229, 216, 0.14); --oxide: #d9644b; } }
  body { max-width: 1120px; margin: auto; padding: 28px 24px 64px; }
  a { color: var(--ink); text-decoration-color: var(--rule); text-underline-offset: 4px; }
  a:hover { text-decoration-color: currentColor; }
  a:focus-visible { outline: 2px solid var(--ink); outline-offset: 5px; }
  nav { display: flex; justify-content: space-between; gap: 24px; flex-wrap: wrap; border-bottom: 1px solid var(--rule); padding-bottom: 20px; }
  nav strong { color: var(--oxide); font: 400 19px var(--serif); }
  header { max-width: 780px; margin: 56px 0; }
  h1 { font: 400 clamp(32px, 6vw, 54px)/1.1 var(--serif); letter-spacing: -0.015em; }
  h2 { font: 400 27px/1.2 var(--serif); margin-bottom: 8px; }
  p { color: var(--muted); max-width: 780px; }
  .label { color: var(--muted); font: 17px var(--serif); font-variant-caps: all-small-caps; letter-spacing: 0.06em; }
  figure { margin: 0 0 72px; scroll-margin-top: 24px; }
  img { width: 100%; height: auto; display: block; border: 1px solid var(--rule); box-sizing: border-box; margin-top: 24px; }
  footer { border-top: 1px solid var(--rule); padding-top: 24px; }
</style>
</head>
<body>
<nav aria-label="Demo navigation"><strong>Rootstock</strong><a href="./">Open interactive demo →</a></nav>
<header><p class="label">Screenshot tour · Synthetic data</p>
<h1>From a security question to the evidence behind it.</h1>
<p>Rootstock connects macOS permissions, application hardening, and modeled exposure paths. These captures show the actual viewer with a fictional dataset. No host is scanned and no database connection is needed.</p>
<a href="./">Try the demo</a></header>
<main>
${tourSteps.map((step) => `<figure id="${step.file.replace(".png", "")}"><figcaption><h2>${step.title}</h2><p>${step.text}</p></figcaption><a href="screenshots/${step.file}" aria-label="View full-size capture: ${step.title}"><img src="screenshots/${step.file}" alt="${step.alt}" width="1440" height="1050" loading="lazy"></a></figure>`).join("\n")}
</main>
<footer><p>Modeled paths describe preconditions, not confirmed compromise. Collection gaps remain visible. This demo cannot collect host data, run Cypher, or change host settings.</p><a href="./">Explore the synthetic dataset →</a></footer>
</body></html>\n`;
}
