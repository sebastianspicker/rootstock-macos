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

export function hideConnectionGate(controller: Controller): void {
  controller.dom.connectionGate.hidden = true;
  connectionBackgroundInert(false);
  controller.dom.connectionStatus.textContent = "Live · connected";
  controller.dom.connectionStatus.className = "status-chip connected";
}
