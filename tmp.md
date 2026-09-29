现在 SYSTEM 和 `SeTcbPrivilege` 都正确。`LastTaskResult: 1` 只是因为当前 VM 缺少登记文件：

```text
%ProgramData%\UnlockWindowsWithIPhone\enrollment.dat
```

不能从其他电脑复制该文件，因为它受本机 DPAPI 保护。请在这台 VM 重新登记。

1. 用目标 Windows 用户登录，在普通用户 PowerShell 中启动前台服务：

```powershell
C:\build\unlock_service_host.exe
```

2. 在另一个普通用户 PowerShell 中，从 iPhone 复制 130 位原始公钥，然后运行：

```powershell
C:\build\unlock_pairing_tool.exe --key-clipboard
```

核对 Windows 与 iPhone 显示的指纹，然后点击 Confirm。不要以 SYSTEM 运行 PairingTool，否则会登记错误的 SID。

3. 确认登记文件存在：

```powershell
Test-Path "$env:ProgramData\UnlockWindowsWithIPhone\enrollment.dat"
```

应返回 `True`。

4. 重新运行现有探针任务：

```powershell
Start-ScheduledTask -TaskName 'Unlock-LSA-Token-Probe'
Start-Sleep -Seconds 2

while ((Get-ScheduledTask -TaskName 'Unlock-LSA-Token-Probe').State -eq 'Running') {
    Start-Sleep -Milliseconds 500
}

Get-ScheduledTaskInfo -TaskName 'Unlock-LSA-Token-Probe'
Get-Content C:\Temp\lsa-token-probe.txt
```

请把新的 `lsa-token-probe.txt` 内容发给我。暂时保留计划任务，分析完成后再删除。





# Windows 解锁闭环与 GATT Agent 分阶段实施计划

## Summary

实施严格受两个顺序不可颠倒的阶段门约束：

1. 先使用现有手动 Credential Provider tile 和自定义 LSA package，实现真实 Windows 锁屏解锁。
2. 真实解锁成功后，运行未打包 Win32 `GattServiceProvider` 可行性实验。
3. 只有前两个阶段门均通过，才开始生产 GattAgent 生命周期重构和安装集成。

保持现有 BLE UUID、challenge/assertion 协议、Secure Enclave、公钥登记模型和 `UnlockLogonBuffer` 不变。

## Gate 1：真实 Windows 解锁

- 暂不重构 GATT，不创建生产 GattAgent，不改 package identity 或 MSIX。
- 将 `UnlockService` 转为 LocalSystem Windows Service，并将现有 IPC 改为支持跨 Session、按客户端身份和 operation 授权的本地 named pipe：
  - GATT 用户进程只能申请 challenge、提交 assertion。
  - PairingTool 只能刷新登记记录。
  - SYSTEM/LogonUI Credential Provider 只能消费当前 SID 的一次性 approval。
  - 使用受限 DACL、`PIPE_REJECT_REMOTE_CLIENTS`、客户端 token/SID/session/image 校验，删除 Everyone ACL 和同服务 SID 假设。
- 首先保留手动选择并点击现有 Credential Provider tile，贯通：
  `iPhone assertion → UnlockService approval → CP GetSerialization → LSA package → Windows unlock`。
- 保持 LSA 独立验证签名、SID、audience、新鲜度和重放保护；根据 VM 实际回调正确支持锁屏场景产生的 `Interactive` 和 `Unlock` logon type。
- 使用受支持的 Windows API，从登记 SID可靠取得构造 `LSA_TOKEN_INFORMATION_V2` 所需的账户、主组、组、Owner、默认 DACL和权限信息。
- 禁止使用硬编码组、合成权限、假造账户安全信息、保存密码/PIN，或私自改成其他认证架构。
- 如果无法通过受支持 API可靠构造正确 token，立即停止并报告：
  - 缺少的具体 token 字段；
  - 已验证的 Windows API及其失败结果；
  - 现有 LSA contract 为什么不足；
  - 可选架构及其安全影响。
- Gate 1 仅在 Windows 接受 LSA 返回的 token、锁屏真正解除，并且 Windows Hello/PIN/密码恢复入口仍正常时通过。仅完成 package lookup、tile 显示、serialization 或 LSA 回调均不算通过。

## Gate 2：未打包 Win32 GATT 可行性实验

- 仅在 Gate 1 通过后，使用现有未打包 `GattHost`、Windows VM/测试机和实体 iPhone进行实验；此时仍不实施生产 Agent 重构。
- 验证普通用户会话 `GattServiceProvider` 在以下场景的实际行为：
  - 解锁态创建 provider；
  - Win+L 后继续广播、连接、订阅、读写和通知；
  - 多次 lock/unlock；
  - sleep/wake；
  - hibernate/resume；
  - BLE 断开重连及 radio off/on。
- 记录 `CreateAsync` 结果、HRESULT、advertisement status、订阅状态和每次恢复结果。
- 若需要 `bluetooth` capability/package identity，或锁屏与恢复行为不可重复可靠，立即停止并提交证据；不得自动加入 MSIX、Background Task、Broker、AppService 或 `GattServiceProviderTrigger`。
- Gate 2 仅在未打包 Win32 进程能可靠完成目标生命周期时通过。

## Gate 3：生产运行时

- Gate 1 和 Gate 2 均通过后，将现有 transport 抽为共享 `GattCore`：
  - `GattHost` 保留开发日志和现有交互式登记流程。
  - `GattAgent` 为无窗口、无 console、无 tray 的登记用户进程。
- UUID、四个 characteristic、`0x01` 认证请求和现有 JSON payload保持不变；生产 Agent 不启动 PairingTool。
- UnlockService 成为唯一认证和生命周期权威：
  - 只服务于登记 SID 对应的活动物理控制台 session；
  - RDP、其他用户、未登录和快速切换后的非目标会话全部 fail closed；
  - 每次 `unlocked → locked` 创建新的 `lockCycleId`；
  - 解锁、新 cycle、服务停止或超时清除 challenge 和未消费 approval。
- 服务处理 `WTS_SESSION_LOCK/UNLOCK` 和 power events；resume 后重新查询活动 session、SID 和锁定状态，不沿用睡眠前缓存。
- 单一 named pipe 支持多个并发实例及长连接。Agent 协议包含 `READY/GET_STATE/SUBSCRIBED/ASSERTION/RESULT_SUBMITTED/ADVERTISING_* /ERROR` 和 `STATE/ARM/DISARM/SEND_CHALLENGE/SEND_RESULT`，所有认证消息绑定当前 epoch。
- Agent 长期运行但只在 ARM 状态广播。pipe 断开、身份验证失败或服务停止时立即停止广播。
- 有效 assertion 原子关闭当前 cycle、生成一次性 approval并提交 BLE success result；结果提交完成或短超时后停止广播。同一 cycle 不允许再次认证。
- 在手动 tile 链路持续稳定后，才增加 Credential Provider approval watcher 和自动提交；approval 仍只在 `GetSerialization` 中消费一次。

## 安装与恢复

- 仅在运行时和可靠性测试通过后扩展 Components Wizard。
- 安装事务加入：
  - 自动启动的 UnlockService；
  - 有限次数 SCM restart recovery；
  - 针对登记 SID、使用 interactive token 的 GattAgent 登录触发任务；
  - pipe ACL、服务、任务、CP 和 LSA 注册验证。
- 卸载顺序固定为：禁止新认证并停止广播 → 删除 Agent 启动任务 → 停止并删除服务 → 撤销 CP/LSA 注册 → 沿用现有重启后 DLL 清理流程。
- 不改变现有未知残留处理和事务回滚原则。
- 每阶段同步更新 README/TODO；保留用户当前未提交的 `AGENTS.md` 修改，并遵守作者注释规则。

## Test Plan

- Gate 1：有效、过期、错误和重放 assertion；approval 单次消费；`Interactive`/`Unlock`；完整 Token V2；实际锁屏解除；失败后系统凭据仍可用。
- IPC：登记用户、SYSTEM/LogonUI、管理员 PairingTool 的允许操作，以及其他用户、RDP、错误 session、错误角色和远程客户端的拒绝路径。
- Gate 2：至少多轮 Win+L、sleep/wake、hibernate/resume 和 BLE 重连，保留可复现日志。
- Gate 3：20 次连续 lock/unlock、Agent/Service 分别在锁定时重启、长时间锁定、蓝牙关闭恢复、iPhone 断线重连。
- 冷启动预期：首次正常登录前不可使用 iPhone 解锁；首次登录启动 Agent 后，本次登录生命周期内支持锁定和睡眠恢复。
- 系统组件安装、真实 LSA 登录和解锁测试仅在一次性 Windows VM、测试账户或备用 Windows 设备执行。

## Assumptions

- 首版只支持唯一登记用户的活动物理控制台 session，不支持 RDP、多用户并发、注销后登录或冷启动首次登录。
- Gate 1 是绝对前置条件；在 Windows 真实解锁前不开展生产 GattAgent 生命周期工作。
- Gate 2 必须先验证未打包 Win32 方案；在获得失败证据前不讨论 package identity 或 MSIX。
- 任一阶段触发停止条件时，仅报告证据和需要用户决定的选项，不自行改变认证或部署架构。


现在 SYSTEM 和 `SeTcbPrivilege` 都正确。`LastTaskResult: 1` 只是因为当前 VM 缺少登记文件：

```text
%ProgramData%\UnlockWindowsWithIPhone\enrollment.dat
```

不能从其他电脑复制该文件，因为它受本机 DPAPI 保护。请在这台 VM 重新登记。

1. 用目标 Windows 用户登录，在普通用户 PowerShell 中启动前台服务：

```powershell
C:\build\unlock_service_host.exe
```

2. 在另一个普通用户 PowerShell 中，从 iPhone 复制 130 位原始公钥，然后运行：

```powershell
C:\build\unlock_pairing_tool.exe --key-clipboard
```

核对 Windows 与 iPhone 显示的指纹，然后点击 Confirm。不要以 SYSTEM 运行 PairingTool，否则会登记错误的 SID。

3. 确认登记文件存在：

```powershell
Test-Path "$env:ProgramData\UnlockWindowsWithIPhone\enrollment.dat"
```

应返回 `True`。

4. 重新运行现有探针任务：

```powershell
Start-ScheduledTask -TaskName 'Unlock-LSA-Token-Probe'
Start-Sleep -Seconds 2

while ((Get-ScheduledTask -TaskName 'Unlock-LSA-Token-Probe').State -eq 'Running') {
    Start-Sleep -Milliseconds 500
}

Get-ScheduledTaskInfo -TaskName 'Unlock-LSA-Token-Probe'
Get-Content C:\Temp\lsa-token-probe.txt
```

请把新的 `lsa-token-probe.txt` 内容发给我。暂时保留计划任务，分析完成后再删除。