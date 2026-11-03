import { activity, getTheme, onLocked, onTheme, vaultStatus, type Palette } from "./api";
import { renderAdd } from "./views/add";
import { renderImport } from "./views/import";
import { renderList } from "./views/list";
import { renderSettings } from "./views/settings";
import { renderSetup } from "./views/setup";
import { renderUnlock } from "./views/unlock";

const ACTIVITY_THROTTLE_MS = 10_000;

const root = document.querySelector<HTMLElement>("#app")!;
let dispose = () => {};

function applyTheme(p: Palette) {
  for (const [name, value] of Object.entries(p)) {
    document.documentElement.style.setProperty(name, value);
  }
}

export type Screen = "list" | "import" | "add" | "settings";
export type Go = (to?: Screen) => void;

let screen: Screen = "list";
const screens = { list: renderList, import: renderImport, add: renderAdd, settings: renderSettings };

function show(render: (root: HTMLElement, next: Go) => () => void, next: Go) {
  dispose();
  dispose = render(root, next);
}

/** Re-checks the vault and shows `to` (default: the current screen) when it is unlocked. */
async function route(to?: Screen) {
  if (to) screen = to;
  const status = await vaultStatus();
  if (status !== "unlocked") screen = "list";
  if (status === "none") show(renderSetup, route);
  else if (status === "locked") show(renderUnlock, route);
  else show(screens[screen], route);
}

let lastActivity = 0;
const reportActivity = () => {
  const now = Date.now();
  if (now - lastActivity < ACTIVITY_THROTTLE_MS) return;
  lastActivity = now;
  activity();
};
window.addEventListener("keydown", reportActivity);
window.addEventListener("pointermove", reportActivity);

getTheme().then(applyTheme);
onTheme(applyTheme);
onLocked(() => route());
route();
