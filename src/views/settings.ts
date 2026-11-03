import { vaultChangePassword } from "../api";
import type { Go } from "../main";

const MIN_LENGTH = 8;

export function renderSettings(root: HTMLElement, go: Go): () => void {
  root.innerHTML = `
    <form class="card">
      <h1>Change password</h1>
      <input id="current" type="password" placeholder="Current password" autocomplete="current-password" />
      <input id="pw" type="password" placeholder="New password" autocomplete="new-password" />
      <input id="pw2" type="password" placeholder="Confirm new password" autocomplete="new-password" />
      <p class="error" id="err"></p>
      <p class="ok" id="ok"></p>
      <div class="actions">
        <button type="button" id="back" class="ghost">Back</button>
        <button type="submit">Change password</button>
      </div>
    </form>`;
  const form = root.querySelector("form")!;
  const current = root.querySelector<HTMLInputElement>("#current")!;
  const pw = root.querySelector<HTMLInputElement>("#pw")!;
  const pw2 = root.querySelector<HTMLInputElement>("#pw2")!;
  const err = root.querySelector<HTMLElement>("#err")!;
  const ok = root.querySelector<HTMLElement>("#ok")!;
  const submit = root.querySelector<HTMLButtonElement>("button[type=submit]")!;
  current.focus();

  root.querySelector("#back")!.addEventListener("click", () => go("list"));
  form.addEventListener("keydown", (e) => {
    if (e.key === "Escape") go("list");
  });
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
    submit.disabled = true;
    try {
      await vaultChangePassword(current.value, pw.value);
      current.value = pw.value = pw2.value = "";
      ok.textContent = "Password changed";
    } catch (e) {
      err.textContent = String(e);
      current.select();
    }
    submit.disabled = false;
  });
  return () => {};
}
