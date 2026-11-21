# Disclaimer / 免责声明

**Read this before installing or running `local-binary-index`.**
**安装或运行前请先读这一段。**

---

## English

### 1. Intended use

`local-binary-index` is a **static analysis** tool for the Portable Executable (PE) format. It is published for:

- security research and education;
- incident response and malware triage **in an isolated lab or on samples you are authorized to handle**;
- CTF and training exercises;
- auditing software that **you own** or have **written permission** to analyze.

### 2. Prohibited use

You may **not** use this software to:

- analyze, crack, bypass or remove protection from software without the rights holder's permission;
- develop, test, distribute or operate malware, ransomware, stealers, or command-and-control infrastructure;
- evade detection systems on networks or systems you do not own or administer;
- violate any applicable local, national or international law, including computer-misuse, copyright, export-control and sanctions law.

### 3. No samples, no execution, no network

- This repository **ships no malware and no real-world binaries**. Test fixtures are generated locally by `scripts/make-fixtures.mjs` and contain synthetic bytes only.
- The engine **never executes, loads, or emulates** the analyzed file, and it makes **no network requests**. Any unpacking, debugging or dumping is performed by *you*, with *your own* tools, on *your own* responsibility.

### 4. No warranty, no liability

The software is provided **"AS IS"**, without warranty of any kind, express or implied, including but not limited to merchantability, fitness for a particular purpose, and non-infringement. In no event shall the authors or contributors be liable for any claim, damage, loss of data, loss of profit, or other liability — whether in contract, tort or otherwise — arising from, out of, or in connection with the software or its use.

Static analysis produces **heuristic results**. Verdicts, family identifications, OEP candidates and "patch bytes" may be wrong. You are responsible for verifying any conclusion before acting on it, and for any binary you choose to modify.

### 5. Jurisdiction

You are solely responsible for compliance with the laws of your jurisdiction. The authors do not encourage, support, or take part in unlawful activity of any kind.

---

## 中文

### 1. 允许的用途

`local-binary-index` 是一个针对 PE 格式的**静态分析**工具，仅面向：

- 安全研究与教学；
- **在隔离实验环境内**、或对**你有权处理的样本**做应急响应与恶意样本分析；
- CTF 与培训演练；
- 审计**你本人拥有**或**已获得书面授权**的软件。

### 2. 禁止的用途

不得将本软件用于：

- 未经权利人许可，分析、破解、绕过或移除软件的授权/保护机制；
- 开发、测试、传播或运营恶意软件、勒索软件、窃密程序或 C2 基础设施；
- 在非自有、非你管理的网络或系统上规避检测；
- 违反任何适用的计算机犯罪、著作权、出口管制与制裁等法律法规。

### 3. 不含样本、不执行、不联网

- 本仓库**不包含任何恶意代码或真实二进制样本**。测试样本由 `scripts/make-fixtures.mjs` 在本地生成，内容为合成字节。
- 引擎**从不执行、加载或模拟**被分析文件，也**不发起任何网络请求**。脱壳、调试、内存 dump 均由**你自己**使用**你自己的**工具完成，风险自担。

### 4. 无担保、不承担责任

本软件按**“现状”**提供，不附带任何明示或默示的担保，包括但不限于适销性、特定用途适用性与不侵权担保。作者与贡献者在任何情况下均不对因本软件或其使用而产生的任何索赔、损害、数据丢失、利润损失或其他责任负责（无论基于合同、侵权或其他）。

静态分析给出的是**启发式结果**：壳判定、家族识别、OEP 候选与“可直接落地的补丁字节”都可能是错的。你有责任在据此行动前自行验证，并对你选择修改的任何二进制负责。

### 5. 司法管辖

你有责任遵守所在司法管辖区的法律。作者不鼓励、不支持、也不参与任何违法活动。

---

## Contact / 联系

Security or licensing questions: **lingbol088@gmail.com**
