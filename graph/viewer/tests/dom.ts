/** Minimal element double for bounded list and option lifecycle tests. */
export class TestElement {
  children: TestElement[] = [];
  attributes = new Map<string, string>();
  listeners = new Map<string, () => void>();
  textContent = "";
  className = "";
  value = "";
  disabled = false;
  hidden = false;
  adjacent: TestElement | null = null;
  constructor(public tagName = "div") {}
  setAttribute(key: string, value: string): void { this.attributes.set(key, value); }
  getAttribute(key: string): string | null { return this.attributes.get(key) ?? null; }
  appendChild(child: TestElement): TestElement { this.children.push(child); return child; }
  replaceChildren(...children: TestElement[]): void { this.children = children; }
  add(child: TestElement): void { this.children.push(child); }
  before(child: TestElement): void { this.adjacent = child; }
  addEventListener(event: string, callback: () => void): void { this.listeners.set(event, callback); }
  click(): void { if (!this.disabled) this.listeners.get("click")?.(); }
  querySelectorAll(): TestElement[] {
    return this.children.flatMap((child) => [
      ...(child.tagName === "button" && child.getAttribute("data-node-id") ? [child] : []),
      ...child.querySelectorAll(),
    ]);
  }
}

export function installDom(): void {
  Object.assign(globalThis, {
    document: { createElement: (tag: string) => new TestElement(tag) },
    Option: class extends TestElement {
      constructor(text: string, value: string) { super("option"); this.textContent = text; this.value = value; }
    },
  });
}
