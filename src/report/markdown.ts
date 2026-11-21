/**
 * Markdown 报告渲染（给人看），与 JSON 结果同源。
 */
import type { BinaryAnalysis } from "../index.js";
import { toHex } from "../util/bytes.js";

const table = (headers: readonly string[], rows: readonly (readonly (string | number)[])[]): string => {
  const head = `| ${headers.join(" | ")} |`;
  const divider = `| ${headers.map(() => "---").join(" | ")} |`;
  const body = rows.map((row) => `| ${row.map((cell) => String(cell).replace(/\|/g, "\\|")).join(" | ")} |`);
  return [head, divider, ...body].join("\n");
};

export const renderMarkdown = (analysis: BinaryAnalysis): string => {
  const lines: string[] = [];
  let sectionNo = 1;
  const sectionHeader = (title: string): void => {
    sectionNo += 1;
    lines.push("");
    lines.push(`## ${sectionNo}. ${title}`);
    lines.push("");
  };
  lines.push(`# 二进制分析报告`);
  lines.push("");
  lines.push(`- 样本：\`${analysis.source.path ?? "<memory>"}\``);
  lines.push(`- SHA-256：\`${analysis.source.sha256}\``);
  lines.push(`- 大小：${analysis.source.size} 字节`);
  lines.push(`- 分析时间：${analysis.source.analyzed_at}`);
  lines.push(`- 引擎：${analysis.product.id} ${analysis.product.version}`);
  lines.push("");
  lines.push("## 1. 结论");
  lines.push("");
  lines.push(
    table(
      ["项", "结论"],
      [
        ["保护判定", `${analysis.protection.verdict}（置信度 ${analysis.protection.confidence}）`],
        ["主家族", analysis.protection.primaryFamily ?? "无已知家族"],
        ["架构 / 子系统", `${analysis.image.is64 ? "x64" : "x86"} · ${analysis.image.subsystem}`],
        ["入口", `${toHex(analysis.image.entryPoint.va, 16)}（RVA ${toHex(analysis.image.entryPoint.rva)}）`],
        ["导入", `${analysis.imports.current.moduleCount} 模块 / ${analysis.imports.current.functionCount} 函数`],
        ["反分析得分", String(analysis.antiAnalysis.score)],
        ["托管代码", analysis.managed.isManaged ? `是（${analysis.managed.runtimeVersion ?? "?"}）` : "否"],
      ],
    ),
  );
  lines.push("");
  lines.push("### 处置路线");
  for (const strategy of analysis.protection.strategies) lines.push(`- ${strategy.replace(/^\s*-\s*/, "")}`);
  sectionHeader("结构");
  lines.push(
    table(
      ["#", "区段", "RVA", "VirtualSize", "RawSize", "熵", "权限", "异常"],
      analysis.image.sections.map((section) => [
        section.index,
        section.name || `#${section.index}`,
        toHex(section.virtualAddress),
        section.virtualSize,
        section.sizeOfRawData,
        section.entropy,
        section.flags,
        section.truncated ? "截断" : "",
      ]),
    ),
  );
  if (analysis.image.anomalies.length > 0) {
    lines.push("");
    lines.push("结构异常：");
    for (const anomaly of analysis.image.anomalies) {
      lines.push(`- [${anomaly.severity}] ${anomaly.id}: ${anomaly.detail}`);
    }
  }
  if (analysis.image.overlay) {
    lines.push("");
    lines.push(
      `overlay：偏移 ${toHex(analysis.image.overlay.offset)}，${analysis.image.overlay.size} 字节，熵 ${analysis.image.overlay.entropy}，标记 ${analysis.image.overlay.markers.join(",") || "无"}`,
    );
  }
  sectionHeader("保护指纹");
  if (analysis.protection.families.length === 0) {
    lines.push("未命中已知家族签名。");
  } else {
    lines.push(
      table(
        ["家族", "类别", "难度", "置信度", "命中证据"],
        analysis.protection.families.slice(0, 8).map((family) => [
          family.family,
          family.category,
          family.difficulty,
          family.confidence,
          family.signals.map((signal) => `${signal.kind}:${signal.detail}`).join("；"),
        ]),
      ),
    );
  }
  if (analysis.protection.genericSignals.length > 0) {
    lines.push("");
    lines.push("通用结构信号：");
    for (const signal of analysis.protection.genericSignals) lines.push(`- (${signal.weight}) ${signal.detail}`);
  }
  sectionHeader("入口转移（OEP）");
  lines.push(
    `stub：解码 ${analysis.entryTransfer.stub.decodedInstructions} 条指令，停止原因 ${analysis.entryTransfer.stub.stoppedReason}，pushad ${analysis.entryTransfer.stub.pushadOffset === null ? "无" : toHex(analysis.entryTransfer.stub.pushadOffset)}，控制转移 ${analysis.entryTransfer.stub.controlTransfers} 次`,
  );
  lines.push("");
  if (analysis.entryTransfer.candidates.length === 0) {
    lines.push("无静态 OEP 候选：走运行时路线（ESP 定律 / RWX 断点 / 间接转移断点）。");
  } else {
    lines.push(
      table(
        ["得分", "来源", "候选 RVA", "候选 VA", "区段", "证据"],
        analysis.entryTransfer.candidates.slice(0, 6).map((candidate) => [
          candidate.score,
          candidate.origin,
          toHex(candidate.rva),
          toHex(candidate.va, 16),
          candidate.sectionName ?? "?",
          candidate.evidence.slice(0, 2).join("；"),
        ]),
      ),
    );
  }
  if (analysis.entryTransfer.indirectTransfers.length > 0) {
    lines.push("");
    lines.push("间接转移（需运行时解析）：");
    for (const transfer of analysis.entryTransfer.indirectTransfers.slice(0, 6)) {
      lines.push(`- ${toHex(transfer.fileOffset)} → ${transfer.va === null ? "?" : toHex(transfer.va, 16)}：${transfer.note}`);
    }
  }
  sectionHeader("导入表重建");
  lines.push(
    `当前：${analysis.imports.current.moduleCount} 模块，IAT @ ${analysis.imports.current.iatRva === null ? "无目录" : toHex(analysis.imports.current.iatRva)}（${analysis.imports.current.iatSection ?? "?"}），ordinal-only ${analysis.imports.current.ordinalOnlyCount}`,
  );
  if (analysis.imports.descriptorCandidates.length > 0) {
    lines.push("");
    lines.push("残留原始描述符候选：");
    for (const candidate of analysis.imports.descriptorCandidates.slice(0, 6)) {
      lines.push(`- 得分 ${candidate.score} @ ${toHex(candidate.arrayRva)}：${candidate.moduleNames.join(", ")}`);
    }
  }
  lines.push("");
  lines.push("重建步骤：");
  for (const step of analysis.imports.rebuildSteps) lines.push(`- ${step}`);
  sectionHeader("反分析");
  if (analysis.antiAnalysis.findings.length === 0) {
    lines.push("未命中反调试/反虚拟机特征。");
  } else {
    lines.push(
      table(
        ["类别", "级别", "标题", "位置", "原始字节", "落地建议"],
        analysis.antiAnalysis.findings.slice(0, 20).map((finding) => [
          finding.category,
          finding.severity,
          finding.title,
          finding.va === null ? "-" : toHex(finding.va, 16),
          finding.bytes ?? "-",
          finding.patch?.patchBytes ?? finding.patch?.strategy ?? "-",
        ]),
      ),
    );
  }
  if (analysis.patchList.length > 0) {
    lines.push("");
    lines.push("可直接落地的补丁：");
    for (const patch of analysis.patchList) lines.push(`- ${toHex(patch.fileOffset)} → \`${patch.bytes}\`（${patch.reason}）`);
  }
  if (analysis.antiAnalysis.hookTargets.length > 0) {
    lines.push("");
    lines.push("运行期 hook 目标：");
    for (const hook of analysis.antiAnalysis.hookTargets.slice(0, 12)) {
      lines.push(`- ${hook.dll}!${hook.api} @ ${toHex(hook.iatVa, 16)}（${hook.category}，${hook.suggestedBypass}）`);
    }
  }
  if (analysis.managed.isManaged) {
    sectionHeader("托管层");
    lines.push(`运行时 ${analysis.managed.runtimeVersion ?? "?"}，流：${analysis.managed.streams.map((stream) => `${stream.name}(${stream.size})`).join(", ")}`);
    lines.push("");
    lines.push(
      table(
        ["TypeDef", "MethodDef", "Field", "MemberRef", "AssemblyRef"],
        [
          [
            analysis.managed.totals.typeDefs,
            analysis.managed.totals.methods,
            analysis.managed.totals.fields,
            analysis.managed.totals.memberRefs,
            analysis.managed.totals.assemblyRefs,
          ],
        ],
      ),
    );
    if (analysis.managed.indicators.length > 0) {
      lines.push("");
      for (const indicator of analysis.managed.indicators) lines.push(`- ${indicator}`);
    }
    lines.push("");
    for (const step of analysis.managed.steps) lines.push(`- ${step}`);
  }
  sectionHeader("证据链");
  lines.push(table(["ID", "类型", "说明", "摘要"], analysis.evidence.map((item) => [item.id, item.kind, item.detail, item.digest.slice(0, 16)])));
  lines.push("");
  sectionHeader("局限");
  for (const limitation of analysis.limitations) lines.push(`- ${limitation}`);
  sectionHeader("复现");
  lines.push("```");
  lines.push(`node bin/lbi.mjs zxwn analyze "${analysis.source.path ?? "<sample>"}" --out ./out`);
  lines.push("```");
  return lines.join("\n");
};
