import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";

export type VaultStatus = "none" | "locked" | "unlocked";
export type Palette = Record<string, string>;

export interface CodeView {
  id: string;
  issuer: string;
  name: string;
  code: string;
  remaining: number;
  period: number;
}

export interface ImportProgress {
  batches_seen: number[];
  batch_size: number | null;
  accounts: number;
  complete: boolean;
}

export interface MergeResult {
  added: number;
  skipped_duplicates: number;
  skipped_unsupported: number;
}

export interface CameraInfo {
  index: number;
  name: string;
}

export interface CameraFrame {
  preview: string;
  progress: ImportProgress;
  error: string | null;
}

export type Algorithm = "SHA1" | "SHA256" | "SHA512";

export const vaultStatus = () => invoke<VaultStatus>("vault_status");
export const vaultCreate = (password: string) => invoke<void>("vault_create", { password });
export const vaultUnlock = (password: string) => invoke<void>("vault_unlock", { password });
export const vaultLock = () => invoke<void>("vault_lock");
export const activity = () => invoke<void>("activity");
export const codes = () => invoke<CodeView[]>("codes");
export const copyCode = (id: string) => invoke<void>("copy_code", { id });
export const getTheme = () => invoke<Palette>("get_theme");
export const importImage = (bytes: Uint8Array) =>
  invoke<ImportProgress>("import_image", { bytes: Array.from(bytes) });
export const cameraList = () => invoke<CameraInfo[]>("camera_list");
export const cameraStart = (index: number) => invoke<void>("camera_start", { index });
export const cameraStop = () => invoke<void>("camera_stop");
export const importFinish = () => invoke<MergeResult>("import_finish");
export const importCancel = () => invoke<void>("import_cancel");
export const accountAddManual = (
  issuer: string,
  name: string,
  secret: string,
  algorithm: Algorithm,
  digits: number,
  period: number,
) => invoke<void>("account_add_manual", { issuer, name, secret, algorithm, digits, period });

export const accountRename = (id: string, issuer: string, name: string) =>
  invoke<void>("account_rename", { id, issuer, name });
export const accountDelete = (id: string) => invoke<void>("account_delete", { id });
export const vaultChangePassword = (current: string, newPassword: string) =>
  invoke<void>("vault_change_password", { current, newPassword });
export const vaultReset = () => invoke<void>("vault_reset");

export const onLocked = (cb: () => void): Promise<UnlistenFn> => listen("locked", () => cb());
export const onTheme = (cb: (p: Palette) => void): Promise<UnlistenFn> =>
  listen<Palette>("theme", (e) => cb(e.payload));
export const onCameraFrame = (cb: (f: CameraFrame) => void): Promise<UnlistenFn> =>
  listen<CameraFrame>("camera-frame", (e) => cb(e.payload));
