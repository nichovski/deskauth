import {
  fingerprintDisable,
  fingerprintEnable,
  onTouchNeeded,
  setMode,
  unlockMethods,
  vaultChangePassword,
  yubikeyAdd,
  yubikeyRemove,
  type Mode,
  type UnlockMethods,
} from "../api";
import type { Go } from "../main";
import { confirmDialog } from "./confirm";

const MIN_LENGTH = 8;
const DEFAULT_KEY_NAME = "YubiKey";
const NO_YUBIKEY = "No YubiKey support on this system.";

const MODES: { mode: Mode; label: string; line: string }[] = [
  { mode: "password", label: "Password only", line: "Only your password opens the vault." },
  {
    mode: "any",
    label: "Password, YubiKey or fingerprint",
    line: "Any one of them opens the vault. The password always works.",
  },
  {
    mode: "password_yubikey",
    label: "Password and YubiKey together",
    line: "You need the password and a touch of a registered YubiKey.",
  },
];

/** What a mode change asks for, and what it removes. */
function modeHint(from: UnlockMethods, to: Mode): string {
  const hasMethods = from.yubikeys.length > 0 || from.fingerprint;
  if (to === "password_yubikey") {
    const removed = hasMethods ? " Your other YubiKeys and the fingerprint are removed." : "";
    return `Type your password and name the new YubiKey, then touch it when asked.${removed}`;
  }
  if (from.mode === "password_yubikey") {
    return "Type your password, then touch a registered YubiKey when asked. Your YubiKeys are removed.";
  }
  if (to === "password" && hasMethods) return "Your YubiKeys and the fingerprint are removed.";
  return "";
}

export function renderSettings(root: HTMLElement, go: Go): () => void {
  root.innerHTML = `
    <div class="settings">
      <section class="card">
        <h1>Unlock methods</h1>
        <fieldset id="methods">
          <form id="mode-form" class="stack">
            ${MODES.map(
              (o) => `
              <label class="option">
                <input type="radio" name="mode" value="${o.mode}" />
                <span><span class="label">${o.label}</span><span class="dim line">${o.line}</span></span>
              </label>`,
            ).join("")}
            <p class="dim" id="mode-hint"></p>
            <input id="mode-pw" type="password" placeholder="Current password" autocomplete="current-password" hidden />
            <input id="mode-name" placeholder="Name for the YubiKey" value="${DEFAULT_KEY_NAME}" hidden />
            <div class="actions" id="mode-actions" hidden><button type="submit">Apply</button></div>
          </form>
          <p class="warn" id="one-key" hidden>Only one YubiKey is registered. If you lose it, you lose this vault. Add a backup key.</p>
          <div id="keys-section" class="stack">
            <h2>YubiKeys</h2>
            <ul class="keys" id="keys"></ul>
            <p class="dim" id="no-yubikey" hidden>${NO_YUBIKEY}</p>
            <form id="add-form" class="stack">
              <input id="add-name" placeholder="Name for the YubiKey" value="${DEFAULT_KEY_NAME}" />
              <input id="add-pw" type="password" placeholder="Current password" autocomplete="current-password" hidden />
              <div class="actions"><button type="submit">Add YubiKey</button></div>
            </form>
          </div>
          <div id="finger-section" class="stack">
            <h2>Fingerprint</h2>
            <label class="switch" id="finger-label"><input type="checkbox" id="finger" /> Unlock with fingerprint</label>
            <p class="dim" id="finger-note" hidden>Any program running as you can read the keyring item while you are logged in, so on Linux the fingerprint is convenience, not extra security.</p>
            <p class="dim" id="no-finger" hidden>No fingerprint reader found.</p>
          </div>
          <p class="dim" id="m-status"></p>
          <p class="error" id="m-err"></p>
          <p class="ok" id="m-ok"></p>
        </fieldset>
      </section>
      <form class="card" id="pw-form">
        <h1>Change password</h1>
        <input id="current" type="password" placeholder="Current password" autocomplete="current-password" />
        <input id="pw" type="password" placeholder="New password" autocomplete="new-password" />
        <input id="pw2" type="password" placeholder="Confirm new password" autocomplete="new-password" />
        <p class="dim" id="touch-each" hidden>You will touch each registered YubiKey.</p>
        <p class="dim" id="pw-status"></p>
        <p class="error" id="err"></p>
        <p class="ok" id="ok"></p>
        <div class="actions">
          <button type="button" id="back" class="ghost">Back</button>
          <button type="submit">Change password</button>
        </div>
      </form>
    </div>`;
  const $ = <T extends HTMLElement>(sel: string) => root.querySelector<T>(sel)!;

  // Unlock methods card.
  const methods = $<HTMLFieldSetElement>("#methods");
  const modeForm = $<HTMLFormElement>("#mode-form");
  const radios = [...root.querySelectorAll<HTMLInputElement>("input[name=mode]")];
  const modeHintEl = $("#mode-hint");
  const modePw = $<HTMLInputElement>("#mode-pw");
  const modeName = $<HTMLInputElement>("#mode-name");
  const modeActions = $("#mode-actions");
  const oneKey = $("#one-key");
  const keysSection = $("#keys-section");
  const keys = $("#keys");
  const noYubikey = $("#no-yubikey");
  const addForm = $<HTMLFormElement>("#add-form");
  const addName = $<HTMLInputElement>("#add-name");
  const addPw = $<HTMLInputElement>("#add-pw");
  const fingerSection = $("#finger-section");
  const fingerLabel = $("#finger-label");
  const finger = $<HTMLInputElement>("#finger");
  const fingerNote = $("#finger-note");
  const noFinger = $("#no-finger");
  const mStatus = $("#m-status");
  const mErr = $("#m-err");
  const mOk = $("#m-ok");

  // Change password card.
  const form = $<HTMLFormElement>("#pw-form");
  const current = $<HTMLInputElement>("#current");
  const pw = $<HTMLInputElement>("#pw");
  const pw2 = $<HTMLInputElement>("#pw2");
  const touchEach = $("#touch-each");
  const pwStatus = $("#pw-status");
  const err = $("#err");
  const ok = $("#ok");
  const submit = form.querySelector<HTMLButtonElement>("button[type=submit]")!;

  let m: UnlockMethods | null = null;
  let busy = false;
  // The status line of the device call that is running, if any.
  let activeStatus: HTMLElement | null = null;
  const unlisten = onTouchNeeded((name) => {
    if (activeStatus) activeStatus.textContent = name ? `Touch ${name}` : "Touch your YubiKey";
  });

  /** Runs one vault change with both cards disabled and the touch status in `statusEl`. */
  async function withDevice(statusEl: HTMLElement, work: () => Promise<void>, startText = "") {
    busy = methods.disabled = submit.disabled = true;
    activeStatus = statusEl;
    statusEl.textContent = startText;
    try {
      await work();
    } finally {
      busy = methods.disabled = submit.disabled = false;
      activeStatus = null;
      statusEl.textContent = "";
    }
  }

  const selectedMode = (): Mode | undefined =>
    MODES.find((o) => radios.some((r) => r.checked && r.value === o.mode))?.mode;

  function showModeForm() {
    const to = selectedMode();
    const from = m;
    const changing = from !== null && to !== undefined && to !== from.mode;
    modeHintEl.textContent = changing ? modeHint(from, to) : "";
    const needsPassword = changing && (to === "password_yubikey" || from.mode === "password_yubikey");
    modePw.hidden = !needsPassword;
    modeName.hidden = !(changing && to === "password_yubikey");
    modeActions.hidden = !changing;
  }

  function showKeys(info: UnlockMethods) {
    const twoFactor = info.mode === "password_yubikey";
    keys.replaceChildren();
    if (info.yubikeys.length === 0) {
      const li = document.createElement("li");
      li.className = "dim";
      li.textContent = "No YubiKey added yet.";
      keys.append(li);
    }
    for (const key of info.yubikeys) {
      const li = document.createElement("li");
      const name = document.createElement("span");
      name.className = "text";
      name.textContent = key.name;
      li.append(name);
      // The last key in two-factor mode cannot be removed.
      if (!(twoFactor && info.yubikeys.length === 1)) {
        const remove = document.createElement("button");
        remove.type = "button";
        remove.className = "ghost danger";
        remove.textContent = "Remove";
        remove.addEventListener("click", async () => {
          const yes = await confirmDialog(
            `Remove the YubiKey "${key.name}"? It will no longer unlock this vault.`,
            "Remove",
          );
          if (yes) change(() => yubikeyRemove(key.id), "YubiKey removed");
        });
        li.append(remove);
      }
      keys.append(li);
    }
  }

  function show(info: UnlockMethods) {
    m = info;
    for (const r of radios) {
      r.checked = r.value === info.mode;
      const blocked = r.value === "password_yubikey" && !info.can_yubikey && info.mode !== "password_yubikey";
      r.disabled = blocked;
      const line = r.parentElement!.querySelector<HTMLElement>(".line")!;
      line.textContent = blocked ? NO_YUBIKEY : MODES.find((o) => o.mode === r.value)!.line;
    }
    showModeForm();
    const twoFactor = info.mode === "password_yubikey";
    oneKey.hidden = !(twoFactor && info.yubikeys.length === 1);

    keysSection.hidden = info.mode === "password";
    showKeys(info);
    noYubikey.hidden = info.can_yubikey;
    addForm.hidden = !info.can_yubikey;
    addPw.hidden = !twoFactor;

    fingerSection.hidden = info.mode !== "any";
    // A set-up fingerprint can be turned off even when the reader is gone.
    fingerLabel.hidden = !(info.can_fingerprint || info.fingerprint);
    finger.checked = info.fingerprint;
    fingerNote.hidden = fingerLabel.hidden || info.platform !== "linux";
    noFinger.hidden = info.can_fingerprint;

    touchEach.hidden = !twoFactor;
  }

  async function refresh() {
    try {
      show(await unlockMethods());
    } catch (e) {
      mErr.textContent = String(e);
    }
  }

  /** Runs one change of the unlock methods, then shows the new state. */
  async function change(work: () => Promise<void>, okText: string, startText = "") {
    mErr.textContent = "";
    mOk.textContent = "";
    const focused = document.activeElement;
    try {
      await withDevice(mStatus, work, startText);
      mOk.textContent = okText;
      modePw.value = addPw.value = "";
    } catch (e) {
      mErr.textContent = String(e);
    }
    await refresh();
    if (focused instanceof HTMLElement && focused.isConnected && !focused.matches(":disabled")) focused.focus();
    else radios.find((r) => r.checked)?.focus();
  }

  for (const r of radios) r.addEventListener("change", showModeForm);
  modeForm.addEventListener("submit", (e) => {
    e.preventDefault();
    const to = selectedMode();
    if (!m || !to || to === m.mode) return;
    const needsPassword = to === "password_yubikey" || m.mode === "password_yubikey";
    if (needsPassword && !modePw.value) {
      mErr.textContent = "Type your password to continue";
      modePw.focus();
      return;
    }
    const password = needsPassword ? modePw.value : null;
    const name = to === "password_yubikey" ? modeName.value : null;
    change(() => setMode(to, password, name), "Unlock method changed");
  });

  addForm.addEventListener("submit", (e) => {
    e.preventDefault();
    if (!m) return;
    const twoFactor = m.mode === "password_yubikey";
    if (twoFactor && !addPw.value) {
      mErr.textContent = "Type your password to continue";
      addPw.focus();
      return;
    }
    const name = addName.value;
    const password = twoFactor ? addPw.value : null;
    change(() => yubikeyAdd(name, password), "YubiKey added");
  });

  finger.addEventListener("change", () => {
    if (finger.checked) change(fingerprintEnable, "Fingerprint unlock is on", "Scan your finger");
    else change(fingerprintDisable, "Fingerprint unlock is off");
  });

  // Change password card.
  const back = () => {
    if (!busy) go("list");
  };
  $("#back").addEventListener("click", back);
  const onKey = (e: KeyboardEvent) => {
    if (e.key === "Escape") back();
  };
  window.addEventListener("keydown", onKey);
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    err.textContent = "";
    ok.textContent = "";
    if (pw.value.length < MIN_LENGTH) {
      err.textContent = `Use at least ${MIN_LENGTH} characters`;
      return;
    }
    if (pw.value !== pw2.value) {
      err.textContent = "Passwords do not match";
      return;
    }
    try {
      await withDevice(pwStatus, () => vaultChangePassword(current.value, pw.value));
      current.value = pw.value = pw2.value = "";
      ok.textContent = "Password changed";
    } catch (e) {
      err.textContent = String(e);
      current.select();
    }
  });

  refresh().then(() => radios.find((r) => r.checked)?.focus());
  return () => {
    window.removeEventListener("keydown", onKey);
    unlisten.then((off) => off());
  };
}
