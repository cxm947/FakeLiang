---
name: post-account-domain
description: 核验域账号事实（getAccount / hasAccount 的域账号分支）：getAccount 必须用 MSF 登录扫描器验证凭据可用；hasAccount/leakAccount 核验账号存在与角色归属。凭据由运行层按引用解析，模型不接触明文。
metadata:
  predicates: [getAccount, hasAccount, leakAccount, weakAccount]
  categories: [credential-existence, credential-use]
  aliases: [域账号, 域用户, domain account, credential validation, smb_login, ldap_login, winrm_login, kerberos_login, 凭据验证]
  parameters: [host, user, perm, credential]
  when:
    scope: domain
    condition: 事实的账号带域限定符，或 Action 材料里有 Domain 字段；绑定主机已加入域
  requires: [domain_joined]
  excludes: [local_account]
  platforms: [windows, linux]
  keywords: [getAccount, hasAccount, 域账号, domain account, smb_login, ldap_login, winrm_login, kerberos_login, Domain Admins, 凭据验证, credential_test, post]
  resources: []
---

# 域账号核验

## 适用场景

节点输出是**域账号**类事实，分两种：

- `getAccount(host,user,credential,perm)`：必须证明**这条凭据当前可用**，并且属于该账号/该域；仅在本机管理员组里看到账号名，不等于凭据有效。
- `hasAccount` / `leakAccount` / `weakAccount`：核验账号是否存在、是否属于要求的角色；没有凭据材料时不要求登录测试。

图里的 `user` 是角色名（如 `domain_administrator`），不是必须同名的账号；真实账号、域和材料以 Action 回执为准。

## 参数

- 输入 `session_ref`：本节点绑定的通道（来自 runtime）
- 输入 `target_host`：要验证的目标主机/域控（来自图与 runtime）
- 输入 `credential_ref`：优先取 `context.credential_candidates` 的第一项；没有就取 Action 回执里的 `credential_ref`；两者都没有就报缺，不要编造
- 输入 `account` / `domain`：以 Action 回执里的 `Username` / `Domain` 为准
- 输入 `required_level`：来自节点的 `perm`（可选）
- 交付：evidence
- 可用工具：`credential_test`、`run_command`、`run_script`

**凭据只传引用**：`credential_test` 的 `credential_ref` 是运行层已存记录的键；不要把明文口令、哈希或令牌写进请求，也不要把它们复制到证据里。

## 步骤

**进入条件（先看这条）**：本节点绑定的通道已登记；缺通道就报告缺什么，不要新建会话、不要换通道、不要起监听。

**一条一个动作块；有依赖的步骤不合并。**

### A. `getAccount`：凭据验证

1. 先选一种登录面，优先 SMB；目标上 SMB 不可用时再换 LDAP / WinRM / Kerberos，换的是同一次验证的方法，不是换目标：

```text
{"tool":"credential_test","target":"kali","arguments":{"method":"smb","host":"<target_host>","credential_ref":"<credential_ref>","timeout":60}}
```

2. 读回执：
   - `Success`、`[+]`、`Pwn3d!`、`status: success`、`Authenticated`、`Login successful` → 凭据当前可用；
   - `[-]`、`FAILED`、`STATUS_LOGON_FAILURE`、`Access denied`、`invalid credentials` → 凭据不可用；
   - 模块不存在、端口不通、超时、回执截断 → **未知**，可以换一种登录面再验一次，仍不行就记未知。
3. 身份/主机绑定：回执里的目标地址或主机必须与本次 `target_host` 对得上；对不上不能判通过。

### B. `hasAccount` / `leakAccount`：账号存在与角色

在绑定通道上发一次只读查询，包含本次 nonce：

```text
Windows：{"tool":"run_command","target":"session","arguments":{"interpreter":"cmd","command":"echo AGV_POST_NONCE=<本次 nonce> & whoami & hostname & net user <account> /domain & net group \"Domain Admins\" /domain"}}
POSIX：{"tool":"run_command","target":"session","arguments":{"interpreter":"sh","command":"echo AGV_POST_NONCE=<本次 nonce>; id -un; hostname; getent group sudo; getent group wheel"}}
```

`net user /domain` / `net group` 只能证明账号存在与角色归属，不能证明凭据可用；`getAccount` 不能只用这一步。

## 完成依据

`finish.verdict` 判的是事实，不是命令是否跑完。

- `getAccount`：优先读回执里的结构化 `credential_valid`。它为 `true`，且目标/身份/域对得上，且 Action 材料能归到同一账号/域 → **通过**；它为 `false` → **不通过**。没有该字段时才读文本：`Success`/`[+]`/`Pwn3d!` 为真，`[-]`/`FAILED`/`STATUS_LOGON_FAILURE` 为假；没有可用登录面、模块缺失、超时、回执不可判读 → **未知**。
- `hasAccount` / `leakAccount`：账号存在且角色归属符合事实 → **通过**；明确不存在或角色不符 → **不通过**；查询失败/输出不可判读 → **未知**。
- 凭据材料存在 ≠ 凭据有效；`Success` 也只证明这次认证，不自动证明 `perm` 的全部语义；`perm` 需要另行核对身份/权限时按事实要求补证据。

证据字段：`call_id`、`nonce`、`session_identity`、`session_host`、`credential_ref`、`credential_test_method`、`credential_test_result`、`credential_valid`、`account_domain`、`local_admin_members`；原始输出保留在 `stdout`。

## 失败条件

- 通道缺失、观测未取回、标记缺失、回执截断 → **未知**；这些都不是“凭据不成立”的反证。
- 登录面不可用（端口不通/模块缺失）→ **未知**；不要用“连不上”判凭据无效。
- 只有本机 `Administrator` 或只有账号名，没有认证结果 → **未知**；不要判通过。
- 不要在请求或证据里写明文口令、哈希、令牌或私钥。

**停止边界**：一次验证只做一个登录面；换方法不换目标；不作写操作、不新建会话、不改权限。

[共享执行规则](../../src/skills/templates/execution_rules.txt)
