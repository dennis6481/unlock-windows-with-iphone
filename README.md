<!-- Created by Rui MA on 26 Sep 2026 -->

# Unlock Windows with iPhone

这个项目用 iPhone 的 Secure Enclave 私钥证明手机身份，并在 Windows 已有会话的锁屏界面消费一次性授权。

当前已验证的 Windows 路径是：iPhone 签名通过后，LocalSystem 服务创建一个 120 秒、单次消费的授权；用户手动点击 Credential Provider 的 **Unlock** 按钮后，Provider 从服务领取本机加密保存的 Microsoft Account 密码，并交给 Windows 原生 Negotiate 包解锁已有控制台会话。第二次领取会被拒绝，原生 PIN/密码入口保持可用。

这仍是测试实现，不是后台自动解锁产品。前台 GATT host 必须运行，Credential Provider 仍需手动提交，身份变化与部分拒绝路径尚未完成验收。

## 当前边界

- BLE 只运输 challenge、assertion 和结果，不把“附近存在设备”当作认证。
- iPhone 私钥不可导出；Windows 只保存登记后的 P-256 公钥和账户 SID。
- Windows 密码由专用 LocalSystem 服务使用 DPAPI machine scope 保存；Credential Provider 只能在有效手机授权窗口内领取一次。
- Credential Provider 不提供手输密码输入框，也没有绕过手机批准的测试开关。
- 当前分支不包含自定义 LSA Authentication Package。此前的无密码 token 构造研究没有形成可用产品路径，相关探针和兼容层已经移除。
- 公钥登记由提升权限运行的 `unlock_pairing_tool` 完成。GATT 不接受远程登记命令。
- 安装、卸载和失败恢复只由原生 Components Wizard 管理；没有 PowerShell 安装兼容层，也没有跳过凭据清除确认的 emergency removal。

## Windows 组件

```text
iPhone
  └─ BLE challenge/assertion
      └─ unlock_gatt_host (当前为前台进程)
          └─ phone-only named pipe
              └─ unlock_saved_credential_service (LocalSystem)
                  ├─ PhoneApprovalCore：challenge、防重放、验签
                  ├─ EnrollmentStore：已确认的公钥与账户 SID
                  ├─ SavedCredentialVault：本机加密凭据
                  └─ 120 秒单次授权
                      └─ LogonUI-only named pipe
                          └─ unlock_credential_provider
                              └─ Windows Negotiate
```

- `windows/GattHost`：暴露四个 GATT characteristic，只处理认证请求 `0x01`、challenge、assertion 和结果。
- `windows/SavedCredential`：LocalSystem 服务、IPC、凭据保管和暂时保留的密码管理 GUI。
- `windows/CredentialProvider`：绑定当前控制台用户，只消费手机批准后的保存凭据。
- `windows/PhoneApproval`：当前服务使用的签名验证核心与登记存储；不是独立 host。
- `windows/PairingTool`：管理员确认公钥登记、刷新服务中的登记状态。
- `windows/ComponentsWizard`：安装、卸载、重启后清理和事务恢复。
- `windows/Protocol`：跨平台签名载荷与 Windows CNG 验签。

## 当前手动验证流程

1. 使用 Components Wizard 安装 `unlock_saved_credential_service` 和 Credential Provider。
2. 在已解锁的物理控制台，以管理员身份运行 `unlock_saved_credential_manager`：点击 **Refresh**，然后设置或更新当前账户的实际 Microsoft Account 密码。
3. 以管理员身份运行 `unlock_pairing_tool`，核对指纹并登记 iPhone 公钥。
4. 启动前台 `unlock_gatt_host`，然后锁定 Windows。
5. 在 iPhone 上发起认证。手机收到 `unlock_approved` 后，120 秒内选择 **Unlock with iPhone** 磁贴并点击 **Unlock**。
6. 该授权在 Credential Provider 领取时立即消费；Windows 随后的密码校验失败也不会恢复授权。

详细边界见 [Windows 总览](windows/README.md)、[GATT host](windows/GattHost/README.md)、[保存凭据服务](windows/SavedCredential/README.md) 和 [Credential Provider](windows/CredentialProvider/README.md)。

## 构建

Windows 最低版本为 Windows 10。需要与目标 Windows 原生架构一致的 Visual Studio C++ 工具链和 Windows SDK。

```powershell
cd windows
make build
make test
make build-release
```

`make test` 会先构建。仓库自动化代理不得在未获得当前任务明确授权时运行这些命令。

iOS 项目位于 `ios/ios.xcodeproj`。Secure Enclave 路径必须在实体 iPhone 上验证；模拟器不会退回软件密钥。协议格式见 [protocol/README.md](protocol/README.md)。

## 尚未完成

- 将 Windows GATT transport 封装成经过锁屏和重启生命周期验证的后台组件。
- 在保持单次授权语义的前提下自动选择或提交 Credential Provider。
- 为重复认证请求返回比通用 `not_ready` 更明确的“已有有效授权”状态。
- 完成身份切换、错误签名、过期、重放、非 LogonUI 调用者和服务重启等负面路径验收。
- 生产级安装、签名、更新和恢复策略。

## 参考资料

- [Apple: Protecting keys with the Secure Enclave](https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave)
- [Apple: Core Bluetooth background processing](https://developer.apple.com/library/archive/documentation/NetworkingInternetWeb/Conceptual/CoreBluetooth_concepts/CoreBluetoothBackgroundProcessingForIOSApps/PerformingTasksWhileYourAppIsInTheBackground.html)
- [Microsoft: Credential Providers in Windows](https://learn.microsoft.com/en-us/windows/win32/secauthn/credential-providers-in-windows)
- [Microsoft V2 Credential Provider sample](https://github.com/microsoft/Windows-classic-samples/blob/main/Samples/CredentialProvider/cpp/CSampleCredential.cpp)
- [Microsoft: CredPackAuthenticationBuffer](https://learn.microsoft.com/en-us/windows/win32/api/wincred/nf-wincred-credpackauthenticationbuffera)
- [Microsoft: CryptProtectData](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata)
- [Microsoft: Named Pipe Security and Access Rights](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights)

## License

This project is licensed under the MIT License. See [LICENSE.md](LICENSE.md).
