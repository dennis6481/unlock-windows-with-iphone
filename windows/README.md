<!-- Created by Rui MA on 26 Sep 2026 -->

# Windows

Windows 主线只有一条：iPhone 签名经前台 GATT host 转交 LocalSystem 服务验证，服务创建 120 秒单次授权，Credential Provider 领取本机加密保存的密码并提交给原生 Negotiate。

## 目录

- `Protocol`：固定签名载荷和 CNG P-256 验签。
- `PhoneApproval`：`PhoneApprovalCore` 与 `EnrollmentStore`，由保存凭据服务直接使用。
- `SavedCredential`：LocalSystem 服务、两条受限 named pipe、DPAPI vault 和临时密码管理 GUI。
- `GattHost`：当前前台 BLE transport，只接受认证请求 `0x01`。
- `CredentialProvider`：LogonUI 磁贴，只领取有效手机授权对应的保存凭据。
- `PairingTool`：管理员确认并登记 iPhone 公钥。
- `ComponentsWizard`：唯一安装、卸载和事务恢复入口。
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

## 安装与卸载

将 Release 产物放在 Components Wizard 同一目录，提升权限运行 `unlock_windows_components_wizard.exe`。Wizard 安装以下两个系统组件：

- `%SystemRoot%\System32\unlock_saved_credential_service.exe`
- `%SystemRoot%\System32\unlock_credential_provider.dll`

卸载先要求服务确认删除保存凭据，再注销组件并安排重启后删除剩余文件。失败状态由同一份 HKLM 事务记录恢复；没有忽略凭据清理失败的强制删除入口。

`Diagnostics/Get-ComponentsStatus.ps1` 只读取文件、服务、注册表和清理任务状态，不修改系统。

## 当前使用顺序

1. Components Wizard 安装服务和 Credential Provider。
2. `unlock_saved_credential_manager` 在已解锁控制台设置或更新密码。
3. `unlock_pairing_tool` 确认并登记 iPhone 公钥。
4. 启动 `unlock_gatt_host`，锁定 Windows，在 iPhone 发起认证。
5. 收到 `unlock_approved` 后，120 秒内点击 Credential Provider 的 **Unlock**。

Manager GUI 在正式设置 UI 出现前必须保留；它的 Refresh、Set、Update 和 Clear 是当前唯一凭据维护入口。
