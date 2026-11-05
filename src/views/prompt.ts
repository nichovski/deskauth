/** The large "touch your key" line shown right below the button that started a device call. */

import type { TouchNeeded } from "../api";

/** A key: round head with a hole, and a shaft with two teeth. */
const KEY_ICON = `
  <svg class="prompt-icon" viewBox="0 0 24 24" aria-hidden="true">
    <circle cx="8" cy="12" r="4.5" />
    <circle cx="8" cy="12" r="1.5" />
    <path d="M 12.5 12 H 21 M 18 12 V 15.5 M 21 12 V 15" />
  </svg>`;

/** Markup for one prompt, hidden until `showPrompt` gives it text. */
export function promptHtml(id: string): string {
  return `<p class="prompt" id="${id}" aria-live="polite" hidden>${KEY_ICON}<span class="prompt-text"></span></p>`;
}

/** Shows `text` (hides the prompt when empty); `icon` is false for the fingerprint. */
export function showPrompt(el: HTMLElement, text: string, icon = true) {
  el.querySelector<HTMLElement>(".prompt-text")!.textContent = text;
  el.classList.toggle("no-icon", !icon);
  el.hidden = text === "";
}

/** What to tell the user for one touch-needed event. */
export function touchText(t: TouchNeeded): string {
  if (t.of <= 1) return t.name ? `Touch ${t.name}` : "Touch your YubiKey";
  if (t.name) return `Touch ${t.name} (${t.step} of ${t.of})`;
  return t.step === 1 ? `Touch your YubiKey (1 of ${t.of})` : `Touch it again (${t.step} of ${t.of})`;
}
