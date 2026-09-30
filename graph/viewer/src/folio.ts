import { renderScope } from "./folio-scope";
import { renderResults } from "./folio-results";
import { renderReport, prepareReport, validFilename } from "./folio-report";
/** Primary scope → evidence → report flow; graph tools remain a separate complete workspace. */
import type { Controller } from "./runtime";
import type { QueryResult, ViewerNode } from "./types";
import { apiFetch, errorMessage } from "./live";
import { parseQueryResult } from "./protocol";
import {
  scopeMetadata,
  questions,
  value,
  nodeName,
  localResult,
  recommendations,
  matchApplication,
} from "./folio-data";
import {
  el,
  retainFolioFocus,
  para,
  heading,
  button,
  facts,
  warning,
  intro,
  appIdentity,
  evidenceTable,
  modeledPath,
  recommendationList,
} from "./folio-ui";

type Stage = "scope" | "evidence" | "report" | "complete";
const instances = new WeakMap<Controller, EvidenceFolio>();
export function mountFolio(controller: Controller): void {
  const root = document.getElementById("evidence-folio");
  if (!root) return;
  const folio = new EvidenceFolio(controller, root);
  instances.set(controller, folio);
  folio.render();
}
export function refreshFolio(controller: Controller): void {
  instances.get(controller)?.reset();
}

class EvidenceFolio {
  private stage: Stage = "scope";
  private question = "01";
  private selected: ViewerNode | undefined;
  private result: QueryResult | undefined;
  private advice: ViewerNode[] | undefined;
  private adviceError = "";
  private busy = false;
  private error = "";
  private generation = 0;
  private format: "markdown" | "html" = "markdown";
  private filename = "rootstock-assessment.md";
  private downloadUrl = "";
  constructor(
    private controller: Controller,
    private root: HTMLElement,
  ) {}
  private get graph() {
    return this.controller.state.graph;
  }
  private get live() {
    return this.controller.state.live.enabled;
  }
  reset(): void {
    this.generation++;
    this.stage = "scope";
    this.selected = undefined;
    this.result = undefined;
    this.advice = undefined;
    this.busy = false;
    this.error = "";
    this.render();
  }
  private go(stage: Stage): void {
    this.stage = stage;
    this.error = "";
    this.render(true);
  }
  render(focus = false): void {
    const restoreFocus = retainFolioFocus(this.root);
    this.root.replaceChildren(this.header(), this.navigation());
    const content = el("main", {
      class: `folio-content folio-${this.stage}`,
      id: "folio-main",
      "aria-busy": String(this.busy),
    });
    if (this.stage === "scope") this.scope(content);
    else if (this.stage === "evidence") this.evidence(content);
    else if (this.stage === "report") this.report(content);
    else this.complete(content);
    if (this.error)
      content.append(
        el("div", { role: "alert", class: "folio-error" }, [
          para(this.error),
          button("Retry", () => {
            if (this.stage === "report") void this.exportReport();
            else void this.run();
          }),
        ]),
      );
    this.root.append(content, this.footer());
    if (focus) {
      this.root.querySelector<HTMLElement>("h1")?.focus({ preventScroll: true });
      window.scrollTo(0, 0);
    } else restoreFocus();
  }
  private header(): HTMLElement {
    const { host, collected, source } = scopeMetadata(this.graph);
    const controls = button("Graph tools", () => {
      document.body.classList.add("graph-tools-open");
      document.getElementById("graph-tools-toggle")?.setAttribute("aria-expanded", "true");
      this.controller.dom.workspaceTitle.focus();
      window.dispatchEvent(new Event("resize"));
    });
    return el("header", { class: "folio-topbar" }, [
      el("div", { class: "folio-brand" }, [
        el("span", { text: "ROOTSTOCK" }),
        el("span", { text: " / CORE" }),
      ]),
      para(host, "folio-top-meta"),
      para(collected, "folio-top-meta"),
      para(
        /synthetic|public.?demo/i.test(source)
          ? "SYNTHETIC EXAMPLE"
          : this.live
            ? "LOCAL GRAPH"
            : "OFFLINE SNAPSHOT",
        "folio-source-label",
      ),
      para("Modeled exposure · not a confirmed compromise", "folio-boundary"),
      controls,
    ]);
  }
  private navigation(): HTMLElement {
    const stages: [Stage, string][] = [
      ["scope", "Scope"],
      ["evidence", "Evidence"],
      ["report", "Report"],
    ];
    const nav = el("nav", { class: "folio-navigation", "aria-label": "Investigation stages" });
    stages.forEach(([stage, label], index) => {
      const control = button(`0x0${index + 1}   ${label}`, () => this.go(stage));
      control.disabled = this.busy || (stage !== "scope" && !this.result);
      if (this.stage === stage || (this.stage === "complete" && stage === "report"))
        control.setAttribute("aria-current", "step");
      nav.append(control);
    });
    nav.append(
      para(
        `${this.live ? "Local analysis" : "Offline snapshot"}  |  TCC · Signing · Hardening · Injection (modeled)`,
        "folio-code",
      ),
    );
    return nav;
  }
  private scope(content: HTMLElement): void {
    renderScope(content, {
      graph: this.graph,
      live: this.live,
      busy: this.busy,
      question: this.question,
      selectQuestion: (value) => {
        this.question = value;
      },
      run: () => void this.run(),
    });
  }
  private async query(id: string, params: Record<string, string> = {}): Promise<QueryResult> {
    const response = await apiFetch(this.controller, `/api/queries/${id}/run`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ params }),
    });
    return parseQueryResult(await response.json());
  }
  private async run(): Promise<void> {
    if (this.busy) return;
    const generation = ++this.generation;
    this.busy = true;
    this.error = "";
    this.selected = undefined;
    this.advice = undefined;
    this.adviceError = "";
    this.render();
    try {
      const result = this.live
        ? await this.query(this.question)
        : localResult(this.graph, this.question);
      if (generation !== this.generation) return;
      this.result = result;
      this.stage = "evidence";
      this.selectSingleResult(result);
    } catch (error) {
      if (generation === this.generation)
        this.error = `Analysis failed: ${errorMessage(error)}. Check the local connection and retry.`;
    } finally {
      this.finishQuery(generation);
    }
  }
  private selectSingleResult(result: QueryResult): void {
    if (this.question === "01" && result.rows.length === 1)
      this.selected = matchApplication(this.graph, result.rows[0] ?? {});
  }
  private finishQuery(generation: number): void {
    if (generation !== this.generation) return;
    this.busy = false;
    this.render(true);
    if (this.selected) void this.loadAdvice();
  }
  private evidence(content: HTMLElement): void {
    const selected = this.selected;
    const left = el("section", { class: "folio-main-column" }, [this.evidenceIntro()]);
    if (this.result?.truncated)
      left.append(
        el("p", {
          class: "folio-warning",
          role: "status",
          text: `Results truncated · ${this.result.rows.length} returned rows. This is not the complete result set.`,
        }),
      );
    if (selected) {
      left.append(
        modeledPath(this.graph, selected),
        evidenceTable(this.graph, selected),
        heading("Analysis notes"),
        para(
          "Dashed relationships represent modeled inference. Observed values describe recorded collection evidence; unknown values are not equivalent to false. Application identity includes the installation path.",
          "folio-note",
        ),
      );
      if ((this.result?.rows.length ?? 0) > 1)
        left.append(
          button("Back to results", () => {
            this.selected = undefined;
            this.render(true);
          }),
        );
    } else this.results(left);
    left.append(warning(this.graph));
    content.append(left, this.evidenceAside());
  }
  private evidenceIntro(): HTMLElement {
    const selected = this.selected;
    const title = selected
      ? "Why can this app reach Full Disk Access?"
      : this.question === "100"
        ? "Which recommendations need attention?"
        : "What does the loaded evidence show?";
    return intro(
      title,
      selected
        ? `Inspect the recorded facts and modeled relationships for ${nodeName(selected)}. This explains an exposure, not confirmation of compromise.`
        : (questions.find((question) => question.id === this.question)?.text ??
            "Review the analysis results."),
    );
  }
  private evidenceAside(): HTMLElement {
    const selected = this.selected;
    const aside = el("aside", { class: "folio-aside" });
    if (selected) {
      aside.append(
        appIdentity(selected),
        heading("Recommendations"),
        para(
          "Advice to reduce potential exposure. Review priority and applicability before taking action.",
          "folio-note",
        ),
      );
      if (this.live)
        aside.append(
          para(
            "Live remediation query is scoped by bundle ID and may include multiple installations.",
            "folio-code",
          ),
        );
      if (this.adviceError)
        aside.append(
          el("div", { role: "alert" }, [
            para(this.adviceError),
            button("Retry recommendations", () => void this.loadAdvice()),
          ]),
        );
      else if (this.live && !this.advice)
        aside.append(para("Loading recommendations…", "folio-note"));
      else
        aside.append(recommendationList(this.advice ?? recommendations(this.graph, selected.id)));
      aside.append(
        heading("Application details"),
        facts([
          ["Name", nodeName(selected)],
          ["Bundle ID", value(selected.properties.bundle_id)],
          ["File path", value(selected.properties.path)],
        ]),
      );
    } else {
      aside.append(
        heading("Reading the evidence"),
        para(
          this.live
            ? "Results come from the selected packaged read-only query. Graph tools provides saved queries, custom Cypher, and the full graph workspace."
            : "These results inspect relationships already present in this exported snapshot. They do not execute saved Cypher or refresh the evidence.",
          "folio-note",
        ),
      );
    }
    return aside;
  }
  private results(parent: HTMLElement): void {
    renderResults(parent, {
      graph: this.graph,
      live: this.live,
      result: this.result,
      select: (node) => {
        this.selected = node;
        this.advice = undefined;
        this.adviceError = "";
        this.render(true);
        void this.loadAdvice();
      },
    });
  }
  private currentAdvice(generation: number, selected: ViewerNode): boolean {
    return generation === this.generation && this.selected === selected;
  }
  private async loadAdvice(): Promise<void> {
    if (!this.live) return;
    if (!this.selected) return;
    const selected = this.selected;
    const generation = this.generation;
    this.adviceError = "";
    this.render();
    try {
      const result = await this.query("101", { bundle_id: value(selected.properties.bundle_id) });
      if (!this.currentAdvice(generation, selected)) return;
      this.advice = result.rows.map((row, index) => ({
        id: `advice-${index}`,
        kind: "Recommendation",
        x: 0,
        y: 0,
        properties: {
          key: row.recommendation_key,
          text: row.recommendation,
          priority: row.priority,
        },
      }));
      if (result.truncated)
        this.adviceError =
          "Recommendations were truncated. Use Graph tools to inspect the bounded query results.";
    } catch (error) {
      if (this.currentAdvice(generation, selected))
        this.adviceError = `Recommendations unavailable: ${errorMessage(error)}`;
    }
    this.renderAdvice(generation);
  }
  private renderAdvice(generation: number): void {
    if (generation === this.generation && this.stage === "evidence") this.render();
  }
  private report(content: HTMLElement): void {
    const self = this;
    renderReport(content, {
      live: this.live,
      graph: this.graph,
      selected: this.selected,
      busy: this.busy,
      get format() {
        return self.format;
      },
      set format(value) {
        self.format = value;
      },
      get filename() {
        return self.filename;
      },
      set filename(value) {
        self.filename = value;
      },
      render: () => this.render(),
    });
  }
  private async exportReport(): Promise<void> {
    if (this.busy) return;
    if (!validFilename(this.filename)) {
      this.error = "Enter a filename without directory separators or control characters.";
      this.render();
      return;
    }
    this.busy = true;
    this.error = "";
    this.render();
    const generation = this.generation;
    try {
      const blob = await prepareReport(this.controller, this.format);
      if (generation !== this.generation) return;
      this.completeDownload(blob);
    } catch (error) {
      if (generation === this.generation)
        this.error = `Report generation failed: ${errorMessage(error)}`;
    } finally {
      if (generation === this.generation) {
        this.busy = false;
        this.render(true);
      }
    }
  }
  private completeDownload(blob: Blob): void {
    if (this.downloadUrl) URL.revokeObjectURL(this.downloadUrl);
    this.downloadUrl = URL.createObjectURL(blob);
    const extension = this.format === "html" ? ".html" : ".md";
    this.filename = this.filename.replace(/\.(md|html)$/i, "") + extension;
    this.download();
    this.stage = "complete";
  }
  private download(): void {
    const link = el("a", { href: this.downloadUrl, download: this.filename });
    document.body.append(link);
    link.click();
    link.remove();
  }
  private complete(content: HTMLElement): void {
    content.append(
      intro(
        this.live ? "Assessment report download started" : "Snapshot summary download started",
        "Your browser handles the destination and completion. Recommendations still require review and action.",
        "/* paper trail prepared. */",
      ),
      facts([
        ["File", this.filename],
        ["Location", "Browser download destination · disk write not verified"],
        ["Format", this.format === "html" ? "HTML" : "Markdown"],
        ["Scope", this.live ? "Current loaded graph assessment" : "Local viewer snapshot summary"],
        ["Source scan", scopeMetadata(this.graph).collected],
      ]),
      warning(this.graph),
      heading("Recommendations still require review"),
      recommendationList(
        this.selected
          ? (this.advice ?? recommendations(this.graph, this.selected.id))
          : recommendations(this.graph),
      ),
      el("div", { class: "folio-actions" }, [
        button("Download again", () => this.download(), true),
        button("Return to evidence", () => this.go("evidence")),
        para("Host settings unchanged", "folio-code"),
      ]),
    );
  }
  private footer(): HTMLElement {
    const footer = el("footer", { class: "folio-footer" }, [
      para(
        this.live ? "127.0.0.1 / local analysis" : "Local snapshot / offline analysis",
        "folio-code",
      ),
      para("Evidence and inference remain distinct", "folio-code"),
    ]);
    if (this.stage === "evidence")
      footer.append(
        button(
          "Prepare report",
          () => {
            if (!this.live) this.filename = "rootstock-snapshot-summary.md";
            this.go("report");
          },
          true,
        ),
      );
    if (this.stage === "report") {
      const back = button("Back to evidence", () => this.go("evidence"));
      back.disabled = this.busy;
      const generate = button(
        this.busy
          ? "Generating report…"
          : this.live
            ? "Generate report"
            : "Generate snapshot summary",
        () => void this.exportReport(),
        true,
      );
      generate.disabled = this.busy;
      footer.append(back, generate);
    }
    return footer;
  }
}
