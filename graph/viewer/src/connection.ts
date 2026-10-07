/** Keyboard-accessible session gate, shared by the folio and graph tools. */
import type { Controller } from "./runtime";

function connectionBackgroundInert(inert: boolean): void {
  for (const id of ["evidence-folio", "workspace-shell", "status-bar"]) {
    const background = document.getElementById(id);
    if (background) background.inert = inert;
  }
}

export function showConnectionGate(controller: Controller, message = ""): void {
  controller.dom.connectionGate.hidden = false;
  connectionBackgroundInert(true);
  requestAnimationFrame(() => controller.dom.apiToken.focus());
  controller.dom.connectionError.textContent = message;
  controller.dom.connectionError.hidden = message.length === 0;
  controller.dom.connectionStatus.textContent = message ? "Connection required" : "Not connected";
  controller.dom.connectionStatus.className = `status-chip${message ? " error" : ""}`;
}

/** The chip only claims a connection once the first graph response has arrived. */
export function hideConnectionGate(controller: Controller): void {
  const hadFocus = controller.dom.connectionGate.contains(document.activeElement);
  controller.dom.connectionGate.hidden = true;
  connectionBackgroundInert(false);
  controller.dom.connectionStatus.textContent = "Connecting…";
  controller.dom.connectionStatus.className = "status-chip";
  if (hadFocus) returnFocusAfterGate(controller);
}

export function markConnectionFailed(controller: Controller): void {
  if (controller.dom.connectionGate.hidden === false) return;
  controller.dom.connectionStatus.textContent = "Live · request failed";
  controller.dom.connectionStatus.className = "status-chip error";
}

export function markConnected(controller: Controller): void {
  controller.dom.connectionStatus.textContent = "Live · connected";
  controller.dom.connectionStatus.className = "status-chip connected";
}

function returnFocusAfterGate(controller: Controller): void {
  const folioOpen =
    document.body.classList.contains("folio-enabled") &&
    !document.body.classList.contains("graph-tools-open");
  const target = folioOpen
    ? document.querySelector<HTMLElement>("#evidence-folio button, #evidence-folio h1")
    : controller.dom.search;
  target?.focus();
}
