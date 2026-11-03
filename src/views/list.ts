import { codes, copyCode, vaultLock, type CodeView } from "../api";

const RING_R = 9;
const RING_C = 2 * Math.PI * RING_R;
const WARN_SECONDS = 5;

/** "123456" -> "123 456", "12345678" -> "1234 5678". */
export function groupCode(code: string): string {
  const half = Math.floor(code.length / 2);
  return `${code.slice(0, half)} ${code.slice(half)}`;
}

function el<K extends keyof HTMLElementTagNameMap>(tag: K, cls: string, text = ""): HTMLElementTagNameMap[K] {
  const e = document.createElement(tag);
  e.className = cls;
  e.textContent = text;
  return e;
}

function ring(remaining: number, period: number): SVGSVGElement {
  const ns = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(ns, "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.classList.add("ring");
  if (remaining <= WARN_SECONDS) svg.classList.add("low");
  const track = document.createElementNS(ns, "circle");
  const arc = document.createElementNS(ns, "circle");
  for (const c of [track, arc]) {
    c.setAttribute("cx", "12");
    c.setAttribute("cy", "12");
    c.setAttribute("r", String(RING_R));
  }
  track.classList.add("track");
  arc.classList.add("arc");
  arc.setAttribute("stroke-dasharray", String(RING_C));
  arc.setAttribute("stroke-dashoffset", String(RING_C * (1 - remaining / period)));
  svg.append(track, arc);
  return svg;
}

export function renderList(root: HTMLElement, locked: () => void): () => void {
  root.innerHTML = `
    <header class="bar">
      <input id="search" type="search" placeholder="Search" autocomplete="off" spellcheck="false" />
      <button id="lock" class="ghost" title="Lock">Lock</button>
    </header>
    <ul id="rows" class="rows"></ul>
    <div id="toast" class="toast" hidden>Copied</div>`;
  const search = root.querySelector<HTMLInputElement>("#search")!;
  const rows = root.querySelector<HTMLUListElement>("#rows")!;
  const toast = root.querySelector<HTMLElement>("#toast")!;
  let all: CodeView[] = [];
  let toastTimer = 0;
  search.focus();

  const visible = () => {
    const q = search.value.trim().toLowerCase();
    return q ? all.filter((c) => `${c.issuer} ${c.name}`.toLowerCase().includes(q)) : all;
  };

  const copy = async (id: string) => {
    try {
      await copyCode(id);
      toast.textContent = "Copied";
    } catch (e) {
      toast.textContent = String(e);
    }
    toast.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = window.setTimeout(() => (toast.hidden = true), 1500);
  };

  const draw = () => {
    const list = visible();
    if (list.length === 0) {
      rows.replaceChildren(el("li", "empty", all.length ? "No matches" : "No accounts yet"));
      return;
    }
    rows.replaceChildren(
      ...list.map((c) => {
        const li = el("li", "row");
        const text = el("div", "text");
        text.append(el("div", "issuer", c.issuer || c.name), el("div", "name", c.issuer ? c.name : ""));
        li.append(text, el("div", "code", groupCode(c.code)), ring(c.remaining, c.period));
        li.addEventListener("click", () => copy(c.id));
        return li;
      }),
    );
  };

  const poll = async () => {
    try {
      all = await codes();
      draw();
    } catch {
      locked();
    }
  };

  search.addEventListener("input", draw);
  search.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      const top = visible()[0];
      if (top) copy(top.id);
    } else if (e.key === "Escape") {
      search.value = "";
      draw();
    }
  });
  root.querySelector("#lock")!.addEventListener("click", async () => {
    await vaultLock();
    locked();
  });

  poll();
  const timer = window.setInterval(poll, 1000);
  return () => {
    clearInterval(timer);
    clearTimeout(toastTimer);
  };
}
