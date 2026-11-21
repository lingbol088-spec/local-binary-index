/**
 * 自检探针：用 Node 子进程直连 MCP 服务，做一次真实握手
 * （initialize → tools/list → prompts/list，可选再打一次分析调用）。
 * 不依赖 PowerShell 的 .NET 管道，避免不同宿主下子进程 stdout 丢失。
 */
import { spawn } from "node:child_process";

export interface SelfCheckOptions {
  readonly entry: string;
  /** 触发词；空串表示显式移除 LBI_TOKEN。 */
  readonly token: string;
  /** 覆盖状态目录（用于验证静默目录）。 */
  readonly stateDirectory: string | null;
  /** 可选：额外发起一次 inspect_protection_profile 调用。 */
  readonly sample: string | null;
  readonly timeoutMs?: number;
}

export interface SelfCheckResult {
  readonly ok: boolean;
  readonly toolCount: number;
  readonly toolNames: readonly string[];
  readonly promptNames: readonly string[];
  readonly serverName: string | null;
  readonly serverVersion: string | null;
  readonly protocolVersion: string | null;
  readonly sampleVerdict: string | null;
  readonly sampleFamily: string | null;
  readonly stderr: string;
  readonly error: string | null;
}

const INIT_REQUEST = '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}';
const LIST_REQUEST = '{"jsonrpc":"2.0","id":2,"method":"tools/list"}';
const PROMPT_REQUEST = '{"jsonrpc":"2.0","id":4,"method":"prompts/list"}';

const sampleRequest = (sample: string): string =>
  '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"inspect_protection_profile","arguments":{"path":' +
  JSON.stringify(sample) +
  "}}}";

export const runSelfCheck = async (options: SelfCheckOptions): Promise<SelfCheckResult> => {
  const timeoutMs = options.timeoutMs ?? 20_000;
  const environment: NodeJS.ProcessEnv = { ...process.env };
  if (options.token.length === 0) delete environment.LBI_TOKEN;
  else environment.LBI_TOKEN = options.token;
  if (options.stateDirectory === null) delete environment.LBI_STATE_DIR;
  else environment.LBI_STATE_DIR = options.stateDirectory;

  const requests = [INIT_REQUEST, LIST_REQUEST, PROMPT_REQUEST];
  if (options.sample !== null) requests.push(sampleRequest(options.sample));

  return await new Promise<SelfCheckResult>((resolve) => {
    let stdout = "";
    let stderr = "";
    let settled = false;
    const child = spawn(process.execPath, [options.entry], {
      stdio: ["pipe", "pipe", "pipe"],
      env: environment,
      windowsHide: true,
    });

    const empty = (error: string | null): SelfCheckResult => ({
      ok: false,
      toolCount: 0,
      toolNames: [],
      promptNames: [],
      serverName: null,
      serverVersion: null,
      protocolVersion: null,
      sampleVerdict: null,
      sampleFamily: null,
      stderr,
      error,
    });

    const finish = (result: SelfCheckResult): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try {
        child.kill();
      } catch {
        /* 可能已退出 */
      }
      resolve(result);
    };

    const timer = setTimeout(() => finish(empty(`超时 ${timeoutMs}ms 未收到完整握手`)), timeoutMs);

    child.stdout.on("data", (chunk: Buffer) => {
      stdout += chunk.toString("utf8");
    });
    child.stderr.on("data", (chunk: Buffer) => {
      stderr += chunk.toString("utf8");
    });
    child.on("error", (error) => finish(empty(`无法启动服务: ${error.message}`)));

    child.on("close", () => {
      const messages = stdout
        .split(/\r?\n/)
        .filter((line) => line.trim().length > 0)
        .flatMap((line) => {
          try {
            return [JSON.parse(line) as Record<string, unknown>];
          } catch {
            return [];
          }
        });

      const pick = (id: number): Record<string, unknown> | null => {
        const message = messages.find((entry) => entry["id"] === id);
        const result = message?.["result"];
        return result !== null && typeof result === "object" ? (result as Record<string, unknown>) : null;
      };

      const initResult = pick(1);
      const listResult = pick(2);
      const promptResult = pick(4);
      const callResult = pick(3);

      const tools = Array.isArray(listResult?.["tools"]) ? (listResult["tools"] as { name?: unknown }[]) : [];
      const prompts = Array.isArray(promptResult?.["prompts"])
        ? (promptResult["prompts"] as { name?: unknown }[])
        : [];
      const serverInfo = initResult?.["serverInfo"];
      const serverInfoRecord =
        serverInfo !== null && typeof serverInfo === "object" ? (serverInfo as Record<string, unknown>) : null;

      let sampleVerdict: string | null = null;
      let sampleFamily: string | null = null;
      const content = Array.isArray(callResult?.["content"]) ? (callResult["content"] as { text?: unknown }[]) : [];
      const text = typeof content[0]?.text === "string" ? (content[0]?.text as string) : null;
      if (text !== null) {
        try {
          const parsed = JSON.parse(text) as Record<string, unknown>;
          sampleVerdict = typeof parsed["verdict"] === "string" ? (parsed["verdict"] as string) : null;
          sampleFamily = typeof parsed["primary_family"] === "string" ? (parsed["primary_family"] as string) : null;
        } catch {
          sampleVerdict = null;
        }
      }

      finish({
        ok: messages.length > 0 && listResult !== null,
        toolCount: tools.length,
        toolNames: tools.map((tool) => (typeof tool.name === "string" ? tool.name : "")),
        promptNames: prompts.map((prompt) => (typeof prompt.name === "string" ? prompt.name : "")),
        serverName:
          typeof serverInfoRecord?.["name"] === "string" ? (serverInfoRecord["name"] as string) : null,
        serverVersion:
          typeof serverInfoRecord?.["version"] === "string" ? (serverInfoRecord["version"] as string) : null,
        protocolVersion:
          typeof initResult?.["protocolVersion"] === "string" ? (initResult["protocolVersion"] as string) : null,
        sampleVerdict,
        sampleFamily,
        stderr,
        error: messages.length === 0 ? "子进程未输出任何 JSON-RPC 报文" : null,
      });
    });

    for (const request of requests) child.stdin.write(`${request}\n`);
    child.stdin.end();
  });
};
