import { vaultUnlock } from "../api";

export function renderUnlock(root: HTMLElement, done: () => void): () => void {
  root.innerHTML = `
    <form class="card">
      <h1>Unlock</h1>
      <input id="pw" type="password" placeholder="Password" autocomplete="current-password" autofocus />
      <p class="error" id="err"></p>
      <button type="submit">Unlock</button>
    </form>`;
  const form = root.querySelector("form")!;
  const pw = root.querySelector<HTMLInputElement>("#pw")!;
  const err = root.querySelector<HTMLElement>("#err")!;
  const button = root.querySelector("button")!;
  pw.focus();

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    err.textContent = "";
    button.disabled = true;
    try {
      await vaultUnlock(pw.value);
      done();
    } catch (e) {
      err.textContent = String(e);
      pw.select();
      button.disabled = false;
    }
  });
  return () => {};
}
