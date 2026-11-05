/** The fingerprint icon shown while a scan runs, on the lock screen and in Settings. */

export type FingerState = "idle" | "scanning" | "no_match" | "match";

const SHAKE_MS = 600;

/** Nested arcs open at the bottom, like the ridges of a finger. */
function ridges(): string {
  const cx = 24;
  const cy = 26;
  const open = (20 * Math.PI) / 180;
  return [5, 9, 13, 17]
    .map((r) => {
      const dx = r * Math.cos(open);
      const y = (cy + r * Math.sin(open)).toFixed(2);
      return `<path d="M ${(cx - dx).toFixed(2)} ${y} A ${r} ${r} 0 1 1 ${(cx + dx).toFixed(2)} ${y}" />`;
    })
    .join("");
}

/** Markup for one icon with its message line. */
export function fingerprintHtml(id: string): string {
  return `
    <div class="finger" id="${id}" data-state="idle" hidden>
      <svg viewBox="0 0 48 48" aria-hidden="true">
        <g class="ridges">${ridges()}<path d="M 24 26 L 24 33" /></g>
        <line class="scan" x1="4" x2="44" y1="0" y2="0" />
      </svg>
      <p class="dim finger-line" aria-live="polite"></p>
    </div>`;
}

/** Sets the icon's state; `no_match` falls back to `scanning` after the shake. */
export function setFingerState(el: HTMLElement, state: FingerState) {
  el.dataset.state = state;
  if (state === "no_match") {
    window.setTimeout(() => {
      if (el.dataset.state === "no_match") el.dataset.state = "scanning";
    }, SHAKE_MS);
  }
}

export function setFingerLine(el: HTMLElement, text: string, isError = false) {
  const line = el.querySelector<HTMLElement>(".finger-line")!;
  line.textContent = text;
  line.classList.toggle("error", isError);
  line.classList.toggle("dim", !isError);
}
