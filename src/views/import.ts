import {
  cameraList,
  cameraStart,
  cameraStop,
  importCancel,
  importFinish,
  importImage,
  onCameraFrame,
  type CameraInfo,
  type ImportProgress,
  type MergeResult,
} from "../api";
import type { Go } from "../main";

/** "Added 5, skipped 2 already present, 1 unsupported". Zero skips are left out. */
export function resultText(r: MergeResult): string {
  const parts = [`Added ${r.added}`];
  if (r.skipped_duplicates) parts.push(`skipped ${r.skipped_duplicates} already present`);
  if (r.skipped_unsupported) parts.push(`${r.skipped_unsupported} unsupported`);
  return parts.join(", ");
}

export function progressText(p: ImportProgress): string {
  const ready = p.accounts === 1 ? "1 account ready" : `${p.accounts} accounts ready`;
  if (p.batch_size && p.batch_size > 1) {
    return `batch ${p.batches_seen.length} of ${p.batch_size} scanned, ${ready}`;
  }
  return p.accounts ? ready : "";
}

type Mode = "camera" | "image";

export function renderImport(root: HTMLElement, go: Go): () => void {
  root.innerHTML = `
    <header class="bar"><h1>Import</h1></header>
    <div class="tabs" role="tablist">
      <button id="tab-camera" class="tab" role="tab">Camera</button>
      <button id="tab-image" class="tab" role="tab">Image</button>
    </div>
    <section id="pane-camera" class="pane">
      <select id="cams" hidden></select>
      <div class="preview"><img id="preview" alt="Camera preview" hidden /></div>
    </section>
    <section id="pane-image" class="pane" hidden>
      <button id="drop" class="drop" type="button">Drop a QR image here, or press Enter to choose a PNG or JPG</button>
      <input id="file" type="file" accept="image/png,image/jpeg" multiple hidden />
    </section>
    <div class="status">
      <p id="progress" class="dim"></p>
      <p id="result" class="ok"></p>
      <p id="err" class="error"></p>
    </div>
    <footer class="actions">
      <button id="cancel" class="ghost">Cancel</button>
      <button id="finish" disabled>Finish import</button>
    </footer>`;
  const $ = <T extends HTMLElement>(id: string) => root.querySelector<T>(`#${id}`)!;
  const tabs = { camera: $("tab-camera"), image: $("tab-image") };
  const panes = { camera: $("pane-camera"), image: $("pane-image") };
  const cams = $<HTMLSelectElement>("cams");
  const preview = $<HTMLImageElement>("preview");
  const drop = $("drop");
  const file = $<HTMLInputElement>("file");
  const progress = $("progress");
  const result = $("result");
  const err = $("err");
  const cancel = $<HTMLButtonElement>("cancel");
  const finishButton = $<HTMLButtonElement>("finish");

  let mode: Mode = "camera";
  let cameras: CameraInfo[] | null = null;
  let cameraOn = false;
  let finishing = false;
  let disposed = false;
  let accounts = 0;

  const show = (p: ImportProgress) => {
    if (p.accounts > accounts) err.textContent = "";
    accounts = p.accounts;
    progress.textContent = progressText(p);
    finishButton.disabled = finishing || p.accounts === 0;
  };

  const finish = async () => {
    if (finishing) return;
    finishing = true;
    cameraOn = false;
    finishButton.disabled = true;
    try {
      const r = await importFinish();
      result.textContent = resultText(r);
      progress.textContent = "";
      err.textContent = "";
      accounts = 0;
      preview.hidden = true;
      cancel.textContent = "Done";
      cancel.focus();
    } catch (e) {
      err.textContent = String(e);
    } finally {
      finishing = false;
    }
  };

  /** Shows progress and finishes on its own once every batch is in. */
  const apply = async (p: ImportProgress) => {
    show(p);
    if (p.complete && p.accounts > 0) await finish();
  };

  const startCamera = async (): Promise<boolean> => {
    err.textContent = "";
    try {
      if (!cameras) {
        cameras = await cameraList();
        cams.replaceChildren(
          ...cameras.map((c) => {
            const o = document.createElement("option");
            o.value = String(c.index);
            o.textContent = `${c.name} (${c.index})`;
            return o;
          }),
        );
        cams.hidden = cameras.length <= 1;
      }
      if (cameras.length === 0) {
        err.textContent = "Camera not available";
        return false;
      }
      await cameraStart(Number(cams.value));
      if (disposed || mode !== "camera") {
        await cameraStop();
        return true;
      }
      cameraOn = true;
      return true;
    } catch (e) {
      err.textContent = String(e);
      return false;
    }
  };

  const stopCamera = () => {
    cameraOn = false;
    preview.hidden = true;
    return cameraStop();
  };

  const select = async (m: Mode) => {
    mode = m;
    for (const k of ["camera", "image"] as const) {
      tabs[k].setAttribute("aria-selected", String(k === m));
      panes[k].hidden = k !== m;
    }
    if (m === "camera") {
      if (!(await startCamera()) && !cameras?.length) {
        // No camera at all: images are the only way in, but keep the reason visible.
        const reason = err.textContent;
        await select("image");
        err.textContent = reason;
      }
    } else {
      await stopCamera();
      drop.focus();
    }
  };

  const importFiles = async (files: FileList | null) => {
    for (const f of Array.from(files ?? [])) {
      try {
        await apply(await importImage(new Uint8Array(await f.arrayBuffer())));
      } catch (e) {
        err.textContent = String(e);
      }
    }
  };

  const unlisten = onCameraFrame((f) => {
    if (!cameraOn) return;
    if (f.preview) {
      preview.src = f.preview;
      preview.hidden = false;
    } else {
      cameraOn = false;
      preview.hidden = true;
    }
    if (f.error) err.textContent = f.error;
    apply(f.progress);
  });

  tabs.camera.addEventListener("click", () => select("camera"));
  tabs.image.addEventListener("click", () => select("image"));
  cams.addEventListener("change", () => startCamera());
  drop.addEventListener("click", () => file.click());
  drop.addEventListener("dragover", (e) => {
    e.preventDefault();
    drop.classList.add("over");
  });
  drop.addEventListener("dragleave", () => drop.classList.remove("over"));
  drop.addEventListener("drop", (e) => {
    e.preventDefault();
    drop.classList.remove("over");
    importFiles(e.dataTransfer?.files ?? null);
  });
  file.addEventListener("change", async () => {
    await importFiles(file.files);
    file.value = "";
  });
  finishButton.addEventListener("click", finish);
  cancel.addEventListener("click", () => go("list"));
  const onKey = (e: KeyboardEvent) => {
    if (e.key === "Escape") go("list");
  };
  window.addEventListener("keydown", onKey);

  select("camera");

  return () => {
    disposed = true;
    cameraOn = false;
    window.removeEventListener("keydown", onKey);
    unlisten.then((off) => off());
    importCancel();
  };
}
