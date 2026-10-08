/** Scope and question form, kept independent of asynchronous investigation state. */
import type { GraphModel } from "./types";
import { scopeMetadata, questions } from "./folio-data";
import { el, intro, facts, warning, para, conventions, button, hostPostureBlock } from "./folio-ui";
interface ScopeView {
  graph: GraphModel;
  live: boolean;
  busy: boolean;
  question: string;
  selectQuestion(value: string): void;
  run(): void;
}
export function renderScope(content: HTMLElement, view: ScopeView): void {
  const left = el("section", { class: "folio-main-column" }, [
    intro(
      "Assessment scope",
      "Verify the scan source and collection coverage, then choose the question to run against this snapshot.",
      "Step 1 of 3 · Scope",
    ),
  ]);
  const metadata = scopeMetadata(view.graph);
  left.append(
    el("h2", { class: "folio-section-label", text: "Scan metadata" }),
    facts(
      [
        ["Source", metadata.source],
        ["Collected", metadata.collected],
        [
          "Analysis",
          view.live
            ? "Prepared graph · live read-only query access"
            : "Loaded snapshot · local inspection only",
        ],
        ["Scope", metadata.scope],
      ],
      true,
    ),
    warning(view.graph),
  );
  left.append(...hostPostureBlock(view.graph));
  const choices = el("fieldset", { class: "folio-choices" }, [
    el("legend", { text: "Choose a security question" }),
  ]);
  for (const question of questions) {
    const input = el("input", { type: "radio", name: "folio-question", value: question.id });
    input.checked = view.question === question.id;
    input.disabled = view.busy;
    input.addEventListener("change", () => {
      view.selectQuestion(question.id);
    });
    choices.append(
      el("label", {}, [
        input,
        el("code", { class: "folio-qid", text: `Q${question.id}`, "aria-hidden": "true" }),
        el("span", { class: "folio-qtext" }, [
          el("span", { text: question.text }),
          el("small", { class: "folio-qhelp", text: question.answers }),
        ]),
      ]),
    );
  }
  const run = button(runLabel(view), () => void view.run(), true);
  run.disabled = view.busy || (!view.live && !view.graph.nodes.length);
  left.append(
    choices,
    el("div", { class: "folio-actions" }, [
      run,
      para(
        view.live ? "Runs a packaged read-only query" : "Reads the loaded snapshot; no query runs",
        "folio-code",
      ),
    ]),
  );
  if (!view.graph.nodes.length)
    left.append(
      para(
        view.live
          ? "Connect to the local session and load the prepared graph before investigating."
          : "No prepared graph. Collect, import, and infer a graph, then export a viewer snapshot. Empty evidence does not establish safety.",
        "folio-note",
      ),
    );
  content.append(left, conventions());
}
function runLabel(view: ScopeView): string {
  if (view.busy) return view.live ? "Running read-only query…" : "Inspecting snapshot…";
  return view.live ? "Run selected query" : "Inspect snapshot";
}
