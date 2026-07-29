/** Publishes the minimal browser entry point used by the rendered viewer template. */

import {mount} from "./app";

declare global {
  interface Window {
    RootstockViewer: Readonly<{mount: typeof mount}>;
  }
}

window.RootstockViewer = Object.freeze({mount});
