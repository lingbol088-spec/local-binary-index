/**
 * 激活门控：默认完全静默（对外只暴露一个无害的状态工具），
 * 只有持触发词时才挂出完整工具面；触发词有有效期，过期自动回落到静默目录。
 *
 * 触发源（任一即可）：
 *   1. 环境变量 LBI_TOKEN=zxwn（本次进程一次性授权）
 *   2. 状态文件 state.json：token=zxwn 且 expires_at 未过期（上膛窗口）
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync, unlinkSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

export const ACTIVATION_TOKEN = "zxwn";
export const STATE_ENV = "LBI_TOKEN";
export const PRODUCT_ID = "local-binary-index";
export const PRODUCT_VERSION = "1.4.3";
export const DEFAULT_ARM_MINUTES = 24 * 60;

export const stateDirectory = (): string => {
  const override = process.env.LBI_STATE_DIR;
  if (override && override.length > 0) return override;
  if (process.platform === "win32") {
    const localAppData = process.env.LOCALAPPDATA ?? join(homedir(), "AppData", "Local");
    return join(localAppData, "LocalBinaryIndex");
  }
  const xdg = process.env.XDG_DATA_HOME ?? join(homedir(), ".local", "share");
  return join(xdg, "local-binary-index");
};

export const stateFilePath = (): string => join(stateDirectory(), "state.json");

export interface LocalState {
  readonly token: string;
  readonly installed_at: string;
  readonly payload_version: string;
  /** ISO 时间；空串表示不过期。 */
  readonly expires_at: string;
}

export const readState = (): LocalState | null => {
  const path = stateFilePath();
  if (!existsSync(path)) return null;
  try {
    const parsed = JSON.parse(readFileSync(path, "utf8")) as Partial<LocalState>;
    if (typeof parsed.token !== "string" || parsed.token.length === 0) return null;
    return {
      token: parsed.token,
      installed_at: typeof parsed.installed_at === "string" ? parsed.installed_at : "",
      payload_version: typeof parsed.payload_version === "string" ? parsed.payload_version : "",
      expires_at: typeof parsed.expires_at === "string" ? parsed.expires_at : "",
    };
  } catch {
    return null;
  }
};

export const writeState = (token: string, armMinutes: number = DEFAULT_ARM_MINUTES): string => {
  const directory = stateDirectory();
  mkdirSync(directory, { recursive: true });
  const path = stateFilePath();
  const expiresAt =
    armMinutes > 0 ? new Date(Date.now() + armMinutes * 60_000).toISOString() : "";
  const state: LocalState = {
    token,
    installed_at: new Date().toISOString(),
    payload_version: PRODUCT_VERSION,
    expires_at: expiresAt,
  };
  writeFileSync(path, `${JSON.stringify(state, null, 2)}\n`, "utf8");
  return path;
};

/** 上膛：写入触发词与有效期。 */
export const arm = (armMinutes: number = DEFAULT_ARM_MINUTES): string => writeState(ACTIVATION_TOKEN, armMinutes);

/** 撤膛：删除状态文件，立即回到静默目录。 */
export const disarm = (): boolean => {
  const path = stateFilePath();
  if (!existsSync(path)) return false;
  try {
    unlinkSync(path);
    return true;
  } catch {
    return false;
  }
};

export const isStateActive = (state: LocalState | null = readState()): boolean => {
  if (state === null || state.token !== ACTIVATION_TOKEN) return false;
  if (state.expires_at.length === 0) return true;
  const expiry = Date.parse(state.expires_at);
  if (Number.isNaN(expiry)) return false;
  return expiry > Date.now();
};

export const isActivated = (environment: NodeJS.ProcessEnv = process.env): boolean => {
  if (environment[STATE_ENV] === ACTIVATION_TOKEN) return true;
  return isStateActive(readState());
};
