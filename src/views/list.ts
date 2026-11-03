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

interface Row {
  li: HTMLLIElement;
  update: (c: CodeView) => void;
}

/** A row is built once per account id and updated in place, so clicks and hover survive the 1 s poll. */
function createRow(onClick: () => void): Row {
  const ns = "http://www.w3.org/2000/svg";
  const li = el("li", "row");
  const text = el("div", "text");
  const issuer = el("div", "issuer");
  const name = el("div", "name");
  const code = el("div", "code");
  const svg = document.createElementNS(ns, "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.classList.add("ring");
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
  svg.append(track, arc);
  text.append(issuer, name);
  li.append(text, code, svg);
  li.addEventListener("click", onClick);

  const update = (c: CodeView) => {
    issuer.textContent = c.issuer || c.name;
    name.textContent = c.issuer ? c.name : "";
    code.textContent = groupCode(c.code);
    svg.classList.toggle("low", c.remaining <= WARN_SECONDS);
    arc.setAttribute("stroke-dashoffset", String(RING_C * (1 - c.remaining / c.period)));
  };
  return { li, update };
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

  const rowById = new Map<string, Row>();

  const draw = () => {
    const ids = new Set(all.map((c) => c.id));
    for (const id of rowById.keys()) if (!ids.has(id)) rowById.delete(id);

    const list = visible();
    if (list.length === 0) {
      rows.replaceChildren(el("li", "empty", all.length ? "No matches" : "No accounts yet"));
      return;
    }
    const wanted = list.map((c) => {
      let row = rowById.get(c.id);
      if (!row) {
        row = createRow(() => copy(c.id));
        rowById.set(c.id, row);
      }
      row.update(c);
      return row.li;
    });
    // Only touch the DOM structure when the visible set or its order changed.
    const current = Array.from(rows.children);
    if (current.length !== wanted.length || current.some((li, i) => li !== wanted[i])) {
      rows.replaceChildren(...wanted);
    }
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
