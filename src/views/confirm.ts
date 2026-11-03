/**
 * Themed in-app confirm. Enter confirms, Escape or a click outside cancels.
 * It lives inside #app, so a re-route (for example auto-lock) removes it.
 */
export function confirmDialog(message: string, confirmLabel: string): Promise<boolean> {
  const host = document.querySelector<HTMLElement>("#app")!;
  const previous = document.activeElement as HTMLElement | null;

  const overlay = document.createElement("div");
  overlay.className = "overlay";
  const dialog = document.createElement("div");
  dialog.className = "dialog";
  dialog.setAttribute("role", "alertdialog");
  dialog.setAttribute("aria-modal", "true");
  const text = document.createElement("p");
  text.textContent = message;
  const actions = document.createElement("div");
  actions.className = "actions";
  const cancel = document.createElement("button");
  cancel.type = "button";
  cancel.className = "ghost";
  cancel.textContent = "Cancel";
  const confirm = document.createElement("button");
  confirm.type = "button";
  confirm.className = "danger";
  confirm.textContent = confirmLabel;
  actions.append(cancel, confirm);
  dialog.append(text, actions);
  overlay.append(dialog);
  host.append(overlay);
  confirm.focus();

  return new Promise((resolve) => {
    const close = (result: boolean) => {
      overlay.remove();
      previous?.focus();
      resolve(result);
    };
    overlay.addEventListener("keydown", (e) => {
      e.stopPropagation();
      if (e.key === "Enter") {
        e.preventDefault();
        close(true);
      } else if (e.key === "Escape") {
        e.preventDefault();
        close(false);
      } else if (e.key === "Tab") {
        e.preventDefault();
        (document.activeElement === confirm ? cancel : confirm).focus();
      }
    });
    overlay.addEventListener("click", (e) => {
      if (e.target === overlay) close(false);
    });
    cancel.addEventListener("click", () => close(false));
    confirm.addEventListener("click", () => close(true));
  });
}
