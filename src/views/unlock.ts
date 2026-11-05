import {
  onTouchNeeded,
  unlockMethods,
  vaultReset,
  vaultUnlock,
  vaultUnlockFingerprint,
  vaultUnlockTwoFactor,
  vaultUnlockYubikey,
  type UnlockMethods,
} from "../api";
import { confirmDialog } from "./confirm";

const DAMAGED_PREFIX = "Vault file is damaged";

export function renderUnlock(root: HTMLElement, done: () => void): () => void {
  root.innerHTML = `
    <form class="card">
      <h1>Unlock</h1>
      <p class="dim" id="hint" hidden>Type your password, then touch your YubiKey.</p>
      <input id="pw" type="password" placeholder="Password" autocomplete="current-password" autofocus />
      <p class="dim" id="status"></p>
      <p class="error" id="err"></p>
      <button type="submit">Unlock</button>
      <button type="button" id="yubikey" class="ghost" hidden>Use YubiKey</button>
      <button type="button" id="finger" class="ghost" hidden>Use fingerprint</button>
      <button type="button" id="reset" class="ghost danger" hidden>Delete vault and start over</button>
    </form>`;
  const form = root.querySelector("form")!;
  const hint = root.querySelector<HTMLElement>("#hint")!;
  const pw = root.querySelector<HTMLInputElement>("#pw")!;
  const status = root.querySelector<HTMLElement>("#status")!;
  const err = root.querySelector<HTMLElement>("#err")!;
  const reset = root.querySelector<HTMLButtonElement>("#reset")!;
  const yubikey = root.querySelector<HTMLButtonElement>("#yubikey")!;
  const finger = root.querySelector<HTMLButtonElement>("#finger")!;
  const buttons = [...root.querySelectorAll("button")];
  pw.focus();

  // A failed read (for example a damaged file) leaves the plain password form; unlocking then
  // reports the problem.
  const methods: Promise<UnlockMethods | null> = unlockMethods().catch(() => null);
  methods.then((m) => {
    if (!m) return;
    hint.hidden = m.mode !== "password_yubikey";
    yubikey.hidden = !(m.mode === "any" && m.can_yubikey && m.yubikeys.length > 0);
    finger.hidden = !(m.mode === "any" && m.can_fingerprint && m.fingerprint);
  });

  // Only shown while a device call runs, so a late event cannot leave a stale line.
  let busy = false;
  const unlisten = onTouchNeeded((name) => {
    if (busy) status.textContent = name ? `Touch ${name}` : "Touch your YubiKey";
  });

  async function attempt(work: () => Promise<void>, statusText = "") {
    err.textContent = "";
    reset.hidden = true;
    busy = true;
    status.textContent = statusText;
    for (const b of buttons) b.disabled = true;
    try {
      await work();
      done();
      return;
    } catch (e) {
      err.textContent = String(e);
      reset.hidden = !err.textContent.startsWith(DAMAGED_PREFIX);
      pw.select();
    }
    busy = false;
    status.textContent = "";
    for (const b of buttons) b.disabled = false;
  }

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const m = await methods;
    const password = pw.value;
    if (m?.mode === "password_yubikey") attempt(() => vaultUnlockTwoFactor(password));
    else attempt(() => vaultUnlock(password));
  });
  yubikey.addEventListener("click", () => attempt(vaultUnlockYubikey));
  finger.addEventListener("click", () => attempt(vaultUnlockFingerprint, "Scan your finger"));

  reset.addEventListener("click", async () => {
    const ok = await confirmDialog(
      "Delete the vault file? Your accounts must be imported again. This cannot be undone.",
      "Delete vault",
    );
    if (!ok) return;
    try {
      await vaultReset();
      done();
    } catch (e) {
      err.textContent = String(e);
    }
  });
  return () => {
    unlisten.then((off) => off());
  };
}
