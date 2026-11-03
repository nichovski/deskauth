import { vaultReset, vaultUnlock } from "../api";
import { confirmDialog } from "./confirm";

const DAMAGED_PREFIX = "Vault file is damaged";

export function renderUnlock(root: HTMLElement, done: () => void): () => void {
  root.innerHTML = `
    <form class="card">
      <h1>Unlock</h1>
      <input id="pw" type="password" placeholder="Password" autocomplete="current-password" autofocus />
      <p class="error" id="err"></p>
      <button type="submit">Unlock</button>
      <button type="button" id="reset" class="ghost danger" hidden>Delete vault and start over</button>
    </form>`;
  const form = root.querySelector("form")!;
  const pw = root.querySelector<HTMLInputElement>("#pw")!;
  const err = root.querySelector<HTMLElement>("#err")!;
  const button = root.querySelector("button")!;
  const reset = root.querySelector<HTMLButtonElement>("#reset")!;
  pw.focus();

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    err.textContent = "";
    reset.hidden = true;
    button.disabled = true;
    try {
      await vaultUnlock(pw.value);
      done();
    } catch (e) {
      err.textContent = String(e);
      reset.hidden = !err.textContent.startsWith(DAMAGED_PREFIX);
      pw.select();
      button.disabled = false;
    }
  });

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
  return () => {};
}
