import { accountAddManual, type Algorithm } from "../api";
import type { Go } from "../main";

export function renderAdd(root: HTMLElement, go: Go): () => void {
  root.innerHTML = `
    <form class="card">
      <h1>Add account</h1>
      <input id="issuer" placeholder="Issuer" autocomplete="off" spellcheck="false" />
      <input id="name" placeholder="Name" autocomplete="off" spellcheck="false" />
      <input id="secret" placeholder="Secret key" autocomplete="off" spellcheck="false" />
      <details>
        <summary>Advanced</summary>
        <label>Algorithm
          <select id="algorithm">
            <option>SHA1</option>
            <option>SHA256</option>
            <option>SHA512</option>
          </select>
        </label>
        <label>Digits
          <select id="digits">
            <option>6</option>
            <option>8</option>
          </select>
        </label>
        <label>Period (seconds)
          <input id="period" type="number" min="1" value="30" />
        </label>
      </details>
      <p class="error" id="err"></p>
      <div class="actions">
        <button type="button" id="cancel" class="ghost">Cancel</button>
        <button type="button" id="scan" class="ghost">Scan QR</button>
        <button type="submit">Add</button>
      </div>
    </form>`;
  const $ = <T extends HTMLElement>(id: string) => root.querySelector<T>(`#${id}`)!;
  const form = root.querySelector("form")!;
  const issuer = $<HTMLInputElement>("issuer");
  const name = $<HTMLInputElement>("name");
  const secret = $<HTMLInputElement>("secret");
  const algorithm = $<HTMLSelectElement>("algorithm");
  const digits = $<HTMLSelectElement>("digits");
  const period = $<HTMLInputElement>("period");
  const err = $("err");
  const submit = root.querySelector<HTMLButtonElement>("button[type=submit]")!;
  issuer.focus();

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    err.textContent = "";
    submit.disabled = true;
    try {
      await accountAddManual(
        issuer.value.trim(),
        name.value.trim(),
        secret.value,
        algorithm.value as Algorithm,
        Number(digits.value),
        Number(period.value),
      );
      go("list");
    } catch (e) {
      err.textContent = String(e);
      submit.disabled = false;
    }
  });
  $("cancel").addEventListener("click", () => go("list"));
  $("scan").addEventListener("click", () => go("import"));
  const onKey = (e: KeyboardEvent) => {
    if (e.key === "Escape") go("list");
  };
  window.addEventListener("keydown", onKey);
  return () => window.removeEventListener("keydown", onKey);
}
