<!-- Created by Rui MA on 26 Sep 2026 -->

# Windows

Windows 主线只有一条：iPhone 签名经用户态 GATT host 转交 LocalSystem 服务验证，服务创建 120 秒单次授权，Credential Provider 领取本机加密保存的密码并提交给原生 Negotiate。2026-10-02 同一 host 已改为普通用户托盘进程、按实际控制台锁定状态启停广播。用户反馈测试动作均符合预期，唯一报告的问题是实际解锁、广播停止后托盘仍显示“错误”。最新提示修正仅完成静态检查，尚未重新构建或运行验证；第一阶段最终验收、登录任务和安装器接入仍未完成。

## 目录

- `Protocol`：固定签名载荷和 CNG P-256 验签。
- `PhoneApproval`：`PhoneApprovalCore` 与 `EnrollmentStore`，由保存凭据服务直接使用。
- `SavedCredential`：LocalSystem 服务、两条受限 named pipe、DPAPI vault 和临时密码管理 GUI。
- `GattHost`：无终端的普通用户托盘 BLE transport，只接受认证请求 `0x01`；当前仍手动启动，用户已反馈测试动作符合预期，最新提示修正及最终验收待验证。
- `CredentialProvider`：LogonUI 磁贴，只领取有效手机授权对应的保存凭据。
- `PairingTool`：管理员确认并登记 iPhone 公钥。
- `ComponentsWizard`：唯一安装、更新、卸载和事务恢复入口。
- `Diagnostics`：只读状态检查。

仓库不再包含自定义 LSA 包、LSA 探针、独立 phone-approval host、PowerShell 安装包装器或旧序列化格式。

## 构建

最低支持 Windows 10。使用目标机器原生架构的 Visual Studio C++ 工具链：

```powershell
cd windows
make build
make test
make build-release
```

`make test` 会触发编译。没有当前任务的明确授权时不要运行构建或测试。

## 安装、更新与卸载

将 Release 产物放在 Components Wizard 同一目录，提升权限运行 `unlock_windows_components_wizard.exe`。Wizard 安装以下两个系统组件：

- `%SystemRoot%\System32\unlock_saved_credential_service.exe`
- `%SystemRoot%\System32\unlock_credential_provider.dll`

### 已安装机器的更新（2026-10-02，正常流程实测通过）

用户已确认正常 Update 流程通过；同轮自动解锁及无新批准保持锁定、重新批准再次解锁、原生 PIN/密码回归也通过。此记录不包含更新中断、失败恢复、文件前后哈希或其他管理员续办等专项验收。

在仓库根目录启动新构建的 Wizard；新服务 EXE 与 CP DLL 必须与它同目录。安装器本身不编译代码：

```powershell
Start-Process -FilePath '.\windows\build\unlock_windows_components_wizard.exe' -Verb RunAs
```

1. 完整安装会默认显示 **Update**。不要勾选 **Uninstall instead (clears saved credential)**；该选项才是原有卸载路径。
2. Update 把新服务、CP 和续办 Wizard 暂存到 `%SystemRoot%\System32\UnlockWindowsUpdate-<transactionID>`，继承 System32 的访问控制。随后停用 CP 注册、停止并禁用服务；不删除服务登记、不调用密码清除、不修改公钥登记。
3. 点击 **Restart**。未完成真正重启前，即使注销、再次运行 Wizard 或任务被触发，也不会替换可能仍在使用的 DLL。该边界使用 HKLM volatile registry key，休眠或 Fast Startup 关机不能替代 Restart。
4. 重启后使用原生 PIN／密码登录。启动更新的管理员登录后，现有续办任务运行受保护暂存目录中的 Wizard，替换并逐字节核对两个系统文件，再恢复服务自动启动、启动服务并注册 CP。
5. 显示 **Update complete** 后，原有密码副本和公钥应仍可用；旧内存批准不保留。启动本次新构建的 GATT host，重新锁屏、重新手机批准，验证解锁。无需重新保存密码或配对。

若 over-the-shoulder UAC 使用了另一管理员，该管理员未登录时不会自动显示续办窗口。可在仓库根目录提升权限再次运行上述命令，安装器会识别待完成更新。失败时显示具体错误并保留更新事务及暂存文件，重新运行只继续更新，不进入会清除密码的卸载恢复。没有自动回滚到旧二进制；保持原生登录入口。

暂存目录仅含程序文件、不含密码或公钥；当前保留它作为续办/后续卸载的 Wizard 来源。Manager 和 GATT host 仍从新构建目录运行，不属于两个 System32 安装组件。托盘 host 须先完成实体机生命周期验收，随后才接入安装、Update 和卸载。此前正常 Update 和端到端自动解锁均已获用户实测确认；安装器文件/服务检查本身仍不能代替每次更新后的解锁回归。

更新专项验收（不因正常更新通过而自动标绿）：记录更新前后 DPAPI 密文文件及 enrollment 文件的 SHA-256（需 SYSTEM 权限读取密码密文，不要为测试放宽 ACL）；两个记录应未改变。确认服务 Running、System32 二进制与新构建一致、重新手机批准后恢复原 SID/session。另验证重启前续办只提示 Restart、中断后能续办且不会清除保存凭据。

卸载先要求服务确认删除保存凭据，再注销组件并安排重启后删除剩余文件。失败状态由同一份 HKLM 事务记录恢复；没有忽略凭据清理失败的强制删除入口。

`Diagnostics/Get-ComponentsStatus.ps1` 只读取文件、服务、注册表和清理任务状态，不修改系统。

## 当前使用顺序

1. Components Wizard 安装服务和 Credential Provider。
2. `unlock_saved_credential_manager` 在已解锁控制台设置或更新密码。
3. `unlock_pairing_tool` 确认并登记 iPhone 公钥。
4. 启动 `unlock_gatt_host`，锁定 Windows，在 iPhone 发起认证。
5. 显示锁屏登录选项，收到 `unlock_approved` 后 Windows 自动解锁，无需点击 Credential Provider 的 **Unlock**；手动按钮仍保留。

Manager GUI 在正式设置 UI 出现前必须保留；它的 Refresh、Set、Update 和 Clear 是当前唯一凭据维护入口。

2026-10-02 用户实体机确认上述自动解锁和三项回归通过，现冻结这一旧前台 host 原型里程碑。用户还确认重启后首次登录不显示自定义磁贴，使用原生密码登录，符合仅解锁已有会话的目标；首次登录明确不支持手机登录，不是待实现功能。随后用户反馈托盘 host 测试动作均符合预期，但实际解锁、广播停止后仍显示“错误”；最新提示修正尚未重新构建或运行验证，原始历史错误的具体来源也尚未提供。当前托盘 GATT 仍须手动启动，iPhone App 保持前台；五轮验收步骤与当前记录见 [GATT host](GattHost/README.md#实体机验收记录与待验证项)。完整负面路径继续待验收，CP 回归步骤见 [Credential Provider](CredentialProvider/README.md)。第一阶段最终验收通过后才接入安装器，不新增 LocalSystem 蓝牙服务。

## 更新实现参考

- [Microsoft: RegCreateKeyExW / REG_OPTION_VOLATILE](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regcreatekeyexw)
- [Microsoft: ChangeServiceConfigW](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-changeserviceconfigw)
