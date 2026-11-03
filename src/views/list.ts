import { accountDelete, accountRename, codes, copyCode, vaultLock, type CodeView } from "../api";
import type { Go } from "../main";
import { confirmDialog } from "./confirm";

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
  closeMenu: () => void;
}

interface RowActions {
  copy: () => void;
  rename: (issuer: string, name: string) => Promise<void>;
  remove: (c: CodeView) => void;
}

function button(cls: string, text: string, type: "button" | "submit" = "button"): HTMLButtonElement {
  const b = el("button", cls, text);
  b.type = type;
  return b;
}

/**
 * A row is built once per account id and updated in place, so clicks, hover, an open menu and
 * a rename form survive the 1 s poll. update() only touches the text, ring and code nodes.
 */
function createRow(actions: RowActions): Row {
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

  let current: CodeView | undefined;

  const more = button("ghost more", "\u22EF");
  more.title = "Menu";
  more.setAttribute("aria-haspopup", "menu");
  const menu = el("div", "menu");
  menu.hidden = true;
  menu.setAttribute("role", "menu");
  const renameItem = button("", "Rename");
  const deleteItem = button("danger", "Delete");
  menu.append(renameItem, deleteItem);

  const edit = document.createElement("form");
  edit.className = "edit";
  edit.hidden = true;
  const issuerInput = document.createElement("input");
  issuerInput.placeholder = "Issuer";
  const nameInput = document.createElement("input");
  nameInput.placeholder = "Name";
  for (const i of [issuerInput, nameInput]) {
    i.autocomplete = "off";
    i.spellcheck = false;
  }
  const editErr = el("p", "error");
  const save = button("", "Save", "submit");
  const cancel = button("ghost", "Cancel");
  edit.append(issuerInput, nameInput, editErr, cancel, save);

  const closeMenu = () => {
    menu.hidden = true;
  };
  const openMenu = () => {
    menu.hidden = false;
    renameItem.focus();
  };
  const stopEdit = () => {
    edit.hidden = true;
    li.classList.remove("editing");
  };

  li.append(text, code, svg, more, menu, edit);
  li.addEventListener("click", actions.copy);
  li.addEventListener("contextmenu", (e) => {
    e.preventDefault();
    if (!li.classList.contains("editing")) openMenu();
  });
  // Clicks on the controls must not copy the code.
  for (const e of [more, menu, edit]) e.addEventListener("click", (ev) => ev.stopPropagation());
  more.addEventListener("click", () => (menu.hidden ? openMenu() : closeMenu()));
  menu.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      e.stopPropagation();
      closeMenu();
      more.focus();
    }
  });
  renameItem.addEventListener("click", () => {
    closeMenu();
    if (!current) return;
    issuerInput.value = current.issuer;
    nameInput.value = current.name;
    editErr.textContent = "";
    li.classList.add("editing");
    edit.hidden = false;
    issuerInput.focus();
    issuerInput.select();
  });
  deleteItem.addEventListener("click", () => {
    closeMenu();
    if (current) actions.remove(current);
  });
  cancel.addEventListener("click", stopEdit);
  edit.addEventListener("keydown", (e) => {
    e.stopPropagation();
    if (e.key === "Escape") stopEdit();
  });
  edit.addEventListener("submit", async (e) => {
    e.preventDefault();
    save.disabled = true;
    try {
      await actions.rename(issuerInput.value, nameInput.value);
      stopEdit();
    } catch (err) {
      editErr.textContent = String(err);
    }
    save.disabled = false;
  });

  const update = (c: CodeView) => {
    current = c;
    issuer.textContent = c.issuer || c.name;
    name.textContent = c.issuer ? c.name : "";
    code.textContent = groupCode(c.code);
    svg.classList.toggle("low", c.remaining <= WARN_SECONDS);
    arc.setAttribute("stroke-dashoffset", String(RING_C * (1 - c.remaining / c.period)));
  };
  return { li, update, closeMenu };
}

export function renderList(root: HTMLElement, go: Go): () => void {
  root.innerHTML = `
    <header class="bar">
      <input id="search" type="search" placeholder="Search" autocomplete="off" spellcheck="false" />
      <button id="lock" class="ghost" title="Lock">Lock</button>
    </header>
    <ul id="rows" class="rows"></ul>
    <footer class="actions">
      <button id="import" class="ghost">Import / Re-import</button>
      <button id="add" class="ghost">Add account</button>
      <button id="settings" class="ghost">Settings</button>
    </footer>
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

  const showToast = (message: string) => {
    toast.textContent = message;
    toast.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = window.setTimeout(() => (toast.hidden = true), 1500);
  };

  const copy = async (id: string) => {
    try {
      await copyCode(id);
      showToast("Copied");
    } catch (e) {
      showToast(String(e));
    }
  };

  const rowById = new Map<string, Row>();

  const remove = async (c: CodeView) => {
    const label = c.issuer && c.name ? `${c.issuer} / ${c.name}` : c.issuer || c.name;
    if (!(await confirmDialog(`Delete ${label}? This cannot be undone.`, "Delete"))) return;
    try {
      await accountDelete(c.id);
    } catch (e) {
      showToast(String(e));
    }
    await poll();
  };

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
        row = createRow({
          copy: () => copy(c.id),
          rename: async (issuer, name) => {
            await accountRename(c.id, issuer, name);
            await poll();
          },
          remove,
        });
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
      go();
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
    go();
  });
  root.querySelector("#import")!.addEventListener("click", () => go("import"));
  root.querySelector("#add")!.addEventListener("click", () => go("add"));
  root.querySelector("#settings")!.addEventListener("click", () => go("settings"));

  const closeMenus = () => rowById.forEach((r) => r.closeMenu());
  document.addEventListener("click", closeMenus);

  poll();
  const timer = window.setInterval(poll, 1000);
  return () => {
    document.removeEventListener("click", closeMenus);
    clearInterval(timer);
    clearTimeout(toastTimer);
  };
}
