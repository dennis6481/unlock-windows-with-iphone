<!-- Created by Rui MA on 26 Sep 2026 -->

# Unlock Windows with iPhone

这个项目用 iPhone 的 Secure Enclave 私钥证明手机身份，并在 Windows 已有会话的锁屏界面消费一次性授权。

当前已验证的 Windows 路径是：iPhone 签名通过后，LocalSystem 服务创建一个 120 秒、单次消费的授权；Credential Provider 自动提交，从服务领取本机加密保存的 Microsoft Account 密码，并交给 Windows 原生 Negotiate 包解锁已有控制台会话，无需点击 Windows 磁贴。手动 **Unlock** 按钮仍保留，原生 PIN/密码入口保持可用。

这仍是原型，不是已验收的后台自动解锁产品。2026-10-02 已将同一 Windows GATT host 改为带托盘、无终端的普通用户进程，仅在确认当前物理控制台锁定时广播。用户反馈测试动作均符合预期，唯一报告的问题是实际解锁、广播停止后托盘仍显示“错误”；该提示逻辑已修正，2026-10-02 用户确认最新提示修正回归成功。第一阶段五轮专项验收记录仍待补齐。登录任务和安装器接入尚未实施。运行时仍须手动启动 host，iPhone App 保持前台；身份变化与部分拒绝路径尚未完成验收。重启后首次登录明确不支持手机登录：不显示自定义磁贴，使用原生登录方式；手机解锁只用于已有会话再次锁屏。

2026-10-02 冻结记录（用户实体机实测反馈）：手机批准后的自动解锁通过；再次锁屏且不发起手机批准时保持锁定，重新手机批准后再次自动解锁，原生 PIN/密码仍可用。Components Wizard 的 Update 更新流程也已确认通过。冻结范围为“前台 iPhone 批准 → 自动解锁已有会话 + 安装器正常更新”，不代表完整负面测试或生产级更新恢复已通过。

## 当前边界

2026-10-02 用户补充实测：重启后首次登录不显示自定义磁贴，使用原生密码进入 Windows。这符合预期，是保留的行为边界，不是缺失功能或待实现的首次登录路径。

- BLE 只运输 challenge、assertion 和结果，不把“附近存在设备”当作认证。
- iPhone 私钥不可导出；Windows 只保存登记后的 P-256 公钥和账户 SID。
- Windows 密码由专用 LocalSystem 服务使用自身 user scope 的 DPAPI 保存，不使用 `CRYPTPROTECT_LOCAL_MACHINE`；Credential Provider 只能在有效手机授权窗口内领取一次。
- Credential Provider 不提供手输密码输入框，也没有绕过手机批准的测试开关。
- 当前分支不包含自定义 LSA Authentication Package。此前的无密码 token 构造研究没有形成可用产品路径，相关探针和兼容层已经移除。
- 公钥登记由提升权限运行的 `unlock_pairing_tool` 完成。GATT 不接受远程登记命令。
- 安装、更新、卸载和失败恢复只由原生 Components Wizard 管理；Update 保留密码与公钥，重启后续办替换，正常更新流程已由用户确认通过，[步骤见 Windows 文档](windows/README.md#安装更新与卸载)。没有 PowerShell 安装兼容层，也没有跳过凭据清除确认的 emergency removal。

## Windows 组件

```text
iPhone
  └─ BLE challenge/assertion
      └─ unlock_gatt_host (用户态托盘进程；锁屏广播生命周期待验收)
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

- `windows/GattHost`：暴露四个 GATT characteristic，只处理认证请求 `0x01`、challenge、assertion 和结果；广播按实际锁屏状态启停，停止时不主动断开连接。用户已反馈测试动作符合预期，最新托盘提示修正已获用户回归成功反馈，五轮专项验收记录仍待补齐。
- `windows/SavedCredential`：LocalSystem 服务、IPC、凭据保管和暂时保留的密码管理 GUI。
- `windows/CredentialProvider`：绑定当前控制台用户，只消费手机批准后的保存凭据。
- `windows/PhoneApproval`：当前服务使用的签名验证核心与登记存储；不是独立 host。
- `windows/PairingTool`：管理员确认公钥登记、刷新服务中的登记状态。
- `windows/ComponentsWizard`：安装、更新、卸载、重启后续办和事务恢复。
- `windows/Protocol`：跨平台签名载荷与 Windows CNG 验签。

## 当前已验证流程

1. 使用 Components Wizard 安装 `unlock_saved_credential_service` 和 Credential Provider。
2. 在已解锁的物理控制台，以管理员身份运行 `unlock_saved_credential_manager`：点击 **Refresh**，然后设置或更新当前账户的实际 Microsoft Account 密码。
3. 以管理员身份运行 `unlock_pairing_tool`，核对指纹并登记 iPhone 公钥。
4. 以普通用户手动启动 `unlock_gatt_host`，然后锁定 Windows。自动解锁链路此前已由用户确认；托盘 host 测试动作也已获用户预期反馈，最新提示修正已获用户回归成功反馈。五轮生命周期验收步骤与当前记录见 [GATT host](windows/GattHost/README.md#实体机验收记录与待验证项)。
5. 显示锁屏登录选项，在前台 iPhone App 上发起认证。手机收到 `unlock_approved` 后 Windows 自动解锁，不点击 **Unlock**；该按钮仍可用于手动回归与定位通知问题。
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

- 补齐用户态 GATT host 的五轮实体机广播生命周期验收记录；最终验收通过后再接入 Components Wizard 和登录任务，分别验收自动启动、Update 恢复和卸载。
- 验证自动提交在 CP 重建、重复枚举、打包失败和服务中断等场景下的单次行为。
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
- [Microsoft: CredentialsChanged](https://learn.microsoft.com/en-us/windows/win32/api/credentialprovider/nf-credentialprovider-icredentialproviderevents-credentialschanged)
- [Microsoft: GetCredentialCount and automatic submission](https://learn.microsoft.com/en-us/windows/win32/api/credentialprovider/nf-credentialprovider-icredentialprovider-getcredentialcount)
- [Microsoft: Message-only windows](https://learn.microsoft.com/en-us/windows/win32/winmsg/window-features#message-only-windows)
- [Microsoft: RegCreateKeyExW / volatile reboot boundary](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regcreatekeyexw)
- [Microsoft: ChangeServiceConfigW](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-changeserviceconfigw)

## License

This project is licensed under the MIT License. See [LICENSE.md](LICENSE.md).

## GATT 生命周期实现参考

- [Microsoft GATT foreground sample](https://github.com/microsoft/Windows-universal-samples/blob/main/Samples/BluetoothLE/cppwinrt/Scenario3_ServerForeground.cpp)
- [Microsoft: WTSRegisterSessionNotification](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsregistersessionnotification)
- [Microsoft: WTSINFOEX_LEVEL1_W](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/ns-wtsapi32-wtsinfoex_level1_w)
- [Microsoft: GattServiceProviderAdvertisementStatus](https://learn.microsoft.com/en-us/uwp/api/windows.devices.bluetooth.genericattributeprofile.gattserviceprovideradvertisementstatus)
