/** Names the browser-storage key used for local query history and holds the live API token in memory. */

export const HISTORY_STORAGE_NAME = "rootstock.cypherHistory";

/**
 * Holds the live API token for the current page only. The token is deliberately
 * kept in memory and never written to sessionStorage or localStorage, so the
 * credential is not persisted as clear text and does not survive a reload.
 */
let liveApiToken: string | null = null;

export function setApiToken(token: string): void {
  liveApiToken = token;
}

export function getApiToken(): string | null {
  return liveApiToken;
}

export function clearApiToken(): void {
  liveApiToken = null;
}

/** Storage can be blocked (private modes, sandboxed frames); preferences then simply do not persist. */
export function readLocal(key: string): string | null {
  try {
    return localStorage.getItem(key);
  } catch {
    return null;
  }
}

export function writeLocal(key: string, value: string): void {
  try {
    localStorage.setItem(key, value);
  } catch {
    // Persisting a preference is best effort.
  }
}

export function removeLocal(key: string): void {
  try {
    localStorage.removeItem(key);
  } catch {
    // Persisting a preference is best effort.
  }
}
