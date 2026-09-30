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
  :root { color-scheme: dark; font: 17px/1.6 system-ui, sans-serif; background: #0c1213; color: #f2f1ee; }
  body { max-width: 1120px; margin: auto; padding: 28px 24px 64px; }
  a { color: #b3d7ad; text-underline-offset: 4px; }
  a:focus-visible { outline: 2px solid #b3d7ad; outline-offset: 5px; }
  nav { display: flex; justify-content: space-between; gap: 24px; flex-wrap: wrap; border-bottom: 1px solid #303d3e; padding-bottom: 20px; }
  header { max-width: 780px; margin: 56px 0; }
  h1 { font-size: clamp(32px, 6vw, 56px); line-height: 1.12; letter-spacing: -1px; }
  h2 { font-size: 26px; margin-bottom: 8px; }
  p { color: #b7c4ce; max-width: 780px; }
  .label { color: #b3d7ad; }
  figure { margin: 0 0 64px; scroll-margin-top: 24px; }
  img { width: 100%; height: auto; display: block; border: 1px solid #303d3e; box-sizing: border-box; margin-top: 24px; }
  footer { border-top: 1px solid #303d3e; padding-top: 24px; }
</style>
</head>
<body>
<nav aria-label="Demo navigation"><strong>ROOTSTOCK / CORE</strong><a href="./">Open interactive demo →</a></nav>
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
