import {
  CANCELLED,
  NO_YUBIKEY_FOUND,
  TIMED_OUT,
  onFingerStatus,
  onTouchNeeded,
  unlockCancel,
  unlockMethods,
  vaultReset,
  vaultUnlock,
  vaultUnlockFingerprint,
  vaultUnlockTwoFactor,
  vaultUnlockYubikey,
  yubikeyPresent,
  type UnlockMethods,
} from "../api";
import { confirmDialog } from "./confirm";
import { fingerprintHtml, setFingerLine, setFingerState } from "./fingerprint";
import { promptHtml, showPrompt, touchText } from "./prompt";

const DAMAGED_PREFIX = "Vault file is damaged";
const KEY_POLL_MS = 2000;
const FINGER_RESTART_MS = 1000;
/** How long the icon shows the match before the list replaces the screen. */
const MATCH_SHOW_MS = 400;

/** One line naming what the screen listens for, or "" when only the password works. */
function listenHint(finger: boolean, key: boolean): string {
  if (finger && key) return "Scan your finger, touch your YubiKey, or type your password.";
  if (finger) return "Scan your finger or type your password.";
  if (key) return "Touch your YubiKey or type your password.";
  return "";
}

export function renderUnlock(root: HTMLElement, done: () => void): () => void {
  root.innerHTML = `
    <form class="card">
      <h1>Unlock</h1>
      ${fingerprintHtml("finger")}
      <p class="dim" id="hint" hidden></p>
      <input id="pw" type="password" placeholder="Password" autocomplete="current-password" autofocus />
      <p class="dim" id="key-line" hidden></p>
      ${promptHtml("key-prompt")}
      <p class="dim" id="status"></p>
      <p class="error" id="err"></p>
      <button type="submit">Unlock</button>
      <button type="button" id="yubikey" class="ghost" hidden>Use YubiKey</button>
      <button type="button" id="finger-again" class="ghost" hidden>Try fingerprint again</button>
      <button type="button" id="reset" class="ghost danger" hidden>Delete vault and start over</button>
    </form>`;
  const form = root.querySelector("form")!;
  const finger = root.querySelector<HTMLElement>("#finger")!;
  const hint = root.querySelector<HTMLElement>("#hint")!;
  const pw = root.querySelector<HTMLInputElement>("#pw")!;
  const keyLine = root.querySelector<HTMLElement>("#key-line")!;
  const keyPrompt = root.querySelector<HTMLElement>("#key-prompt")!;
  const status = root.querySelector<HTMLElement>("#status")!;
  const err = root.querySelector<HTMLElement>("#err")!;
  const reset = root.querySelector<HTMLButtonElement>("#reset")!;
  const yubikey = root.querySelector<HTMLButtonElement>("#yubikey")!;
  const fingerAgain = root.querySelector<HTMLButtonElement>("#finger-again")!;
  const buttons = [...root.querySelectorAll("button")];
  pw.focus();

  let disposed = false;
  let finished = false;
  // A password (or two-factor, or Windows YubiKey) attempt is running.
  let busy = false;
  let fingerBusy = false;
  let keyBusy = false;
  // After a key error, the key is only tried again once it was unplugged.
  let waitUnplug = false;
  let sawNoMatch = false;
  let autoRestart = false;
  // Touch ID and Windows Hello start on their own only once.
  let fingerTried = false;
  let useFinger = false;
  let autoKey = false;
  // The reader and the key are only used while this window is focused and visible: fprintd
  // allows one user of the reader, and an open key request gets in the way of the browser.
  let active = false;
  let pollTimer = 0;
  let restartTimer = 0;

  function stopTimers() {
    window.clearInterval(pollTimer);
    window.clearTimeout(restartTimer);
    pollTimer = restartTimer = 0;
  }

  /** Leaves the screen once, whichever unlock got there first, after `delay` ms. */
  function finish(delay = 0) {
    if (finished || disposed) return;
    finished = true;
    stopTimers();
    window.setTimeout(() => {
      if (!disposed) done();
    }, delay);
  }

  function start() {
    if (disposed || finished) return;
    if (useFinger) autoScan();
    if (autoKey && !pollTimer) {
      pollTimer = window.setInterval(pollKey, KEY_POLL_MS);
      pollKey();
    }
  }

  /** A YubiKey call already running cannot be stopped; no new one starts. */
  function stop() {
    stopTimers();
    if (useFinger) unlockCancel().catch(() => {});
  }

  const isActive = () => document.visibilityState === "visible" && document.hasFocus();

  function onFocusChange() {
    const now = isActive();
    if (now === active) return;
    active = now;
    if (active) start();
    else stop();
  }
  window.addEventListener("focus", onFocusChange);
  window.addEventListener("blur", onFocusChange);
  document.addEventListener("visibilitychange", onFocusChange);

  // A failed read (for example a damaged file) leaves the plain password form; unlocking then
  // reports the problem.
  const methods: Promise<UnlockMethods | null> = unlockMethods().catch(() => null);
  methods.then((m) => {
    if (!m || disposed) return;
    if (m.mode === "password_yubikey") {
      hint.textContent = "Type your password, then touch your YubiKey.";
      hint.hidden = false;
      return;
    }
    const any = m.mode === "any";
    useFinger = any && m.can_fingerprint && m.fingerprint;
    const hasKeys = any && m.can_yubikey && m.yubikeys.length > 0;
    autoKey = hasKeys && m.auto_yubikey;
    hint.textContent = listenHint(useFinger, autoKey);
    hint.hidden = hint.textContent === "";
    // Windows shows its own dialog for a key, so it only starts on a click.
    yubikey.hidden = !(hasKeys && !m.auto_yubikey);
    if (useFinger) {
      // Touch ID and Windows Hello own their dialog (which takes the focus); only fprintd is
      // restarted on its own.
      autoRestart = m.platform === "linux";
      finger.hidden = false;
    }
    // Waits for the focus when the window starts in the background. Focus changes before this
    // point only set `active`, since nothing was set up to start.
    active = isActive();
    if (active) start();
  });

  /** Starts a scan by itself only while focused, and on macOS and Windows only once. */
  function autoScan() {
    if (active && (autoRestart || !fingerTried)) scanFinger();
    else if (!fingerBusy) setFingerState(finger, "idle");
  }

  async function scanFinger() {
    if (disposed || finished || fingerBusy) return;
    fingerBusy = true;
    fingerTried = true;
    sawNoMatch = false;
    fingerAgain.hidden = true;
    setFingerState(finger, "scanning");
    setFingerLine(finger, "");
    try {
      await vaultUnlockFingerprint();
      fingerBusy = false;
      setFingerState(finger, "match");
      finish(MATCH_SHOW_MS);
      return;
    } catch (e) {
      fingerBusy = false;
      if (disposed || finished) return;
      fingerFailed(String(e));
    }
  }

  function fingerFailed(msg: string) {
    const expected = sawNoMatch || msg === TIMED_OUT || msg === CANCELLED;
    if (!expected || !autoRestart) {
      setFingerState(finger, "idle");
      if (!expected) setFingerLine(finger, msg, true);
      fingerAgain.hidden = false;
    } else if (sawNoMatch) {
      restartTimer = window.setTimeout(autoScan, FINGER_RESTART_MS);
    } else if (msg === TIMED_OUT) {
      autoScan();
    } else if (active) {
      // Cancelled while focused: a cancel meant for an earlier scan; start a fresh one.
      restartTimer = window.setTimeout(autoScan, FINGER_RESTART_MS);
    } else {
      setFingerState(finger, "idle");
    }
  }

  const unlistenFinger = onFingerStatus((s) => {
    if (!fingerBusy) return;
    if (s.state === "scanning") {
      setFingerState(finger, "scanning");
    } else if (s.state === "retry") {
      setFingerLine(finger, s.message ?? "");
    } else {
      sawNoMatch = true;
      setFingerState(finger, "no_match");
      setFingerLine(finger, "Not recognized. Try again.");
    }
  });

  /** The key line shows what went wrong with the last key attempt; the prompt shows the touch. */
  function showKeyLine(text: string, isError = false) {
    keyLine.textContent = text;
    keyLine.hidden = text === "";
    keyLine.classList.toggle("error", isError);
    keyLine.classList.toggle("dim", !isError);
  }

  /** Asks a plugged-in key for a touch; enumerating devices never needs one. */
  async function pollKey() {
    if (disposed || finished || keyBusy || !active) return;
    let present: boolean;
    try {
      present = await yubikeyPresent();
    } catch {
      return;
    }
    if (disposed || finished || keyBusy || !active) return;
    if (!present) {
      if (waitUnplug) showKeyLine("");
      waitUnplug = false;
      return;
    }
    if (waitUnplug) return;
    keyBusy = true;
    try {
      await vaultUnlockYubikey();
      keyBusy = false;
      finish();
      return;
    } catch (e) {
      keyBusy = false;
      if (!busy) showPrompt(keyPrompt, "");
      if (disposed || finished) return;
      const msg = String(e);
      if (msg === TIMED_OUT || msg === NO_YUBIKEY_FOUND || msg === CANCELLED) {
        showKeyLine("");
      } else {
        showKeyLine(msg, true);
        waitUnplug = true;
      }
    }
  }

  // Only shown while a device call runs, so a late event cannot leave a stale line.
  const unlistenTouch = onTouchNeeded((t) => {
    if (keyBusy || busy) showPrompt(keyPrompt, touchText(t));
  });

  /** Runs one unlock with every button disabled; a second one while it runs is ignored. */
  async function attempt(work: () => Promise<void>, statusText = "") {
    if (busy) return;
    err.textContent = "";
    reset.hidden = true;
    busy = true;
    status.textContent = statusText;
    for (const b of buttons) b.disabled = true;
    try {
      await work();
      finish();
      return;
    } catch (e) {
      if (disposed) return;
      err.textContent = String(e);
      reset.hidden = !err.textContent.startsWith(DAMAGED_PREFIX);
      pw.select();
    }
    busy = false;
    status.textContent = "";
    if (!keyBusy) showPrompt(keyPrompt, "");
    for (const b of buttons) b.disabled = false;
  }

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const password = pw.value;
    attempt(async () => {
      const m = await methods;
      await (m?.mode === "password_yubikey" ? vaultUnlockTwoFactor(password) : vaultUnlock(password));
    });
  });
  yubikey.addEventListener("click", () => attempt(vaultUnlockYubikey));
  fingerAgain.addEventListener("click", () => scanFinger());

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
    disposed = true;
    stopTimers();
    window.removeEventListener("focus", onFocusChange);
    window.removeEventListener("blur", onFocusChange);
    document.removeEventListener("visibilitychange", onFocusChange);
    unlistenTouch.then((off) => off());
    unlistenFinger.then((off) => off());
    unlockCancel().catch(() => {});
  };
}
