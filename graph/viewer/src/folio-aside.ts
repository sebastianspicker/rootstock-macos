/** Evidence-stage aside: application identity, recommendations, and reading guidance. */

import { nodeName, recommendations, value } from "./folio-data";
import {
  appIdentity,
  button,
  conventionList,
  el,
  facts,
  heading,
  para,
  recommendationList,
} from "./folio-ui";
import type { GraphModel, ViewerNode } from "./types";

export interface EvidenceAsideOptions {
  graph: GraphModel;
  live: boolean;
  selected: ViewerNode | undefined;
  advice: ViewerNode[] | undefined;
  adviceError: string;
  retryAdvice: () => void;
}

export function renderEvidenceAside(options: EvidenceAsideOptions): HTMLElement {
  const { graph, live, selected, advice, adviceError } = options;
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
    if (live)
      aside.append(
        para(
          "Live remediation query is scoped by bundle ID and may include multiple installations.",
          "folio-code",
        ),
      );
    if (adviceError)
      aside.append(
        el("div", { role: "alert" }, [
          para(adviceError),
          button("Retry recommendations", options.retryAdvice),
        ]),
      );
    else if (live && !advice) aside.append(para("Loading recommendations…", "folio-note"));
    else aside.append(recommendationList(advice ?? recommendations(graph, selected.id)));
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
        live
          ? "Results come from the selected packaged read-only query. Graph tools provides saved queries, custom Cypher, and the full graph workspace."
          : "These results inspect relationships already present in this exported snapshot. They do not execute saved Cypher or refresh the evidence.",
        "folio-note",
      ),
    );
  }
  aside.append(heading("Reading key"), conventionList(true));
  return aside;
}
