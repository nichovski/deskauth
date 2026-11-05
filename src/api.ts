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
  skipped_unsupported: number;
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

export type Mode = "password" | "any" | "password_yubikey";

export interface KeyView {
  id: string;
  name: string;
}

export interface UnlockMethods {
  mode: Mode;
  yubikeys: KeyView[];
  fingerprint: boolean;
  can_yubikey: boolean;
  can_fingerprint: boolean;
  /** The lock screen may poll for a plugged-in key and ask for a touch by itself. */
  auto_yubikey: boolean;
  platform: string;
}

export interface FingerStatus {
  state: "scanning" | "retry" | "no_match";
  message: string | null;
}

/** Error texts the lock screen reacts to (from `DeviceError` in Rust). */
export const CANCELLED = "Cancelled.";
export const TIMED_OUT = "Timed out waiting. Try again.";
export const NO_YUBIKEY_FOUND = "No YubiKey found. Plug it in and try again.";

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
export const unlockMethods = () => invoke<UnlockMethods>("unlock_methods");
export const vaultUnlockYubikey = () => invoke<void>("vault_unlock_yubikey");
export const vaultUnlockFingerprint = () => invoke<void>("vault_unlock_fingerprint");
export const vaultUnlockTwoFactor = (password: string) =>
  invoke<void>("vault_unlock_two_factor", { password });
export const unlockCancel = () => invoke<void>("unlock_cancel");
export const yubikeyPresent = () => invoke<boolean>("yubikey_present");
export const yubikeyAdd = (name: string, password: string, pin: string | null) =>
  invoke<void>("yubikey_add", { name, password, pin });
export const yubikeyRemove = (id: string) => invoke<void>("yubikey_remove", { id });
export const fingerprintEnable = () => invoke<void>("fingerprint_enable");
export const fingerprintDisable = () => invoke<void>("fingerprint_disable");
export const setMode = (mode: Mode, password: string | null, name: string | null, pin: string | null) =>
  invoke<void>("set_mode", { mode, password, name, pin });

export const onLocked = (cb: () => void): Promise<UnlistenFn> => listen("locked", () => cb());
export const onTheme = (cb: (p: Palette) => void): Promise<UnlistenFn> =>
  listen<Palette>("theme", (e) => cb(e.payload));
export const onCameraFrame = (cb: (f: CameraFrame) => void): Promise<UnlistenFn> =>
  listen<CameraFrame>("camera-frame", (e) => cb(e.payload));
/** Fired while a fingerprint scan runs. */
export const onFingerStatus = (cb: (s: FingerStatus) => void): Promise<UnlistenFn> =>
  listen<FingerStatus>("finger-status", (e) => cb(e.payload));
/** Fired before each YubiKey touch; `name` is the key to touch, or null for any registered key. */
export const onTouchNeeded = (cb: (name: string | null) => void): Promise<UnlistenFn> =>
  listen<{ name: string | null }>("touch-needed", (e) => cb(e.payload.name));
