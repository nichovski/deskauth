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

export const vaultStatus = () => invoke<VaultStatus>("vault_status");
export const vaultCreate = (password: string) => invoke<void>("vault_create", { password });
export const vaultUnlock = (password: string) => invoke<void>("vault_unlock", { password });
export const vaultLock = () => invoke<void>("vault_lock");
export const activity = () => invoke<void>("activity");
export const codes = () => invoke<CodeView[]>("codes");
export const copyCode = (id: string) => invoke<void>("copy_code", { id });
export const getTheme = () => invoke<Palette>("get_theme");

export const onLocked = (cb: () => void): Promise<UnlistenFn> => listen("locked", () => cb());
export const onTheme = (cb: (p: Palette) => void): Promise<UnlistenFn> =>
  listen<Palette>("theme", (e) => cb(e.payload));
