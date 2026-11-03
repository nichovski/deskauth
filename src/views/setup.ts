import { vaultCreate } from "../api";

const MIN_LENGTH = 8;

export function renderSetup(root: HTMLElement, done: () => void): () => void {
  root.innerHTML = `
    <form class="card">
      <h1>Create vault</h1>
      <p class="dim">Choose a password to encrypt your accounts.</p>
      <input id="pw" type="password" placeholder="Password" autocomplete="new-password" autofocus />
      <input id="pw2" type="password" placeholder="Confirm password" autocomplete="new-password" />
      <p class="warn">A lost password cannot be recovered. Your accounts would be gone.</p>
      <p class="error" id="err"></p>
      <button type="submit">Create</button>
    </form>`;
  const form = root.querySelector("form")!;
  const pw = root.querySelector<HTMLInputElement>("#pw")!;
  const pw2 = root.querySelector<HTMLInputElement>("#pw2")!;
  const err = root.querySelector<HTMLElement>("#err")!;
  const button = root.querySelector("button")!;
  pw.focus();

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    err.textContent = "";
    if (pw.value.length < MIN_LENGTH) {
      err.textContent = `Use at least ${MIN_LENGTH} characters`;
      return;
    }
    if (pw.value !== pw2.value) {
      err.textContent = "Passwords do not match";
      return;
    }
    button.disabled = true;
    try {
      await vaultCreate(pw.value);
      done();
    } catch (e) {
      err.textContent = String(e);
      button.disabled = false;
    }
  });
  return () => {};
}
