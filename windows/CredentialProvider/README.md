<!-- Created by Rui MA on 27 Sep 2026 -->

# Credential Provider

`unlock_credential_provider.dll` 为 Windows 10+ 的 `CPUS_LOGON` 和 `CPUS_UNLOCK_WORKSTATION` 提供一个 **Unlock with iPhone** 磁贴。

当前磁贴只有图标、标题和 **Unlock** 按钮。它不接受手输密码，也没有“使用保存凭据”复选框或绕过手机批准的测试模式。

提交时 Provider：

1. 从 `ICredentialProviderSetUserArray` 获取 Windows 提供的 SID、Primary SID、QualifiedUserName 和 provider ID，并在当前 console 身份匹配时同步身份快照，供 Manager 的 Refresh 使用。
2. 提交时再次核对当前 active console session 与 SID。
3. 通过只允许 LogonUI 客户端的 named pipe 捕获本次身份 nonce。
4. 领取服务中尚未消费且未过期的手机授权；领取动作会立即消费授权。
5. 使用返回的保存密码构造 `CRED_PACK_PROTECTED_CREDENTIALS | CRED_PACK_ID_PROVIDER_CREDENTIALS` 缓冲区，并交给 Windows 原生 Negotiate 包。

如果授权不存在、已消费、已过期，账户或 session 不匹配，或服务拒绝调用，Provider 不返回凭据，并显示错误。Windows 随后的密码校验失败不会恢复已经领取的授权。

安装和卸载只由 `unlock_windows_components_wizard.exe` 负责。不要手工注册 DLL，也不要恢复已经删除的 PowerShell 安装脚本。

该实现已在物理 Windows 机器的已有 Microsoft Account 会话上完成一次“手机批准 + 手动点击磁贴 + 无需输入密码”的解锁验证。自动选择/提交和完整负面路径仍未验收。
