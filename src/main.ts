import { activity, getTheme, onLocked, onTheme, vaultStatus, type Palette } from "./api";
import { renderList } from "./views/list";
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

function show(render: (root: HTMLElement, next: () => void) => () => void, next: () => void) {
  dispose();
  dispose = render(root, next);
}

async function route() {
  const status = await vaultStatus();
  if (status === "none") show(renderSetup, route);
  else if (status === "locked") show(renderUnlock, route);
  else show(renderList, route);
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
onLocked(route);
route();
