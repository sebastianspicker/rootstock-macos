/** Theme preference and cached canvas color invalidation. */
import { invalidateCanvasColors } from "./canvas-cache";
import type { Controller } from "./runtime";
import type { Theme } from "./types";
export const THEME_STORAGE_NAME = "rootstock.theme";

export function applyTheme(controller: Controller, value: Theme): void {
  if (value === "system") {
    document.documentElement.removeAttribute("data-theme");
    document.body.removeAttribute("data-theme");
  } else {
    document.documentElement.setAttribute("data-theme", value);
    document.body.setAttribute("data-theme", value);
  }
  invalidateCanvasColors();
  localStorage.setItem(THEME_STORAGE_NAME, value);
  controller.actions.markDirty(controller);
}
