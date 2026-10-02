<!-- Created by Rui MA on 26 Sep 2026 -->

# Unlock Windows with iPhone

这个项目用 iPhone 的 Secure Enclave 私钥证明手机身份，并在 Windows 已有会话的锁屏界面消费一次性授权。

当前已验证的 Windows 路径是：iPhone 签名通过后，LocalSystem 服务创建一个 120 秒、单次消费的授权；Credential Provider 自动提交，从服务领取本机加密保存的 Microsoft Account 密码，并交给 Windows 原生 Negotiate 包解锁已有控制台会话，无需点击 Windows 磁贴。手动 **Unlock** 按钮仍保留，原生 PIN/密码入口保持可用。

这仍是原型，不是已验收的后台自动解锁产品。2026-10-02 已将同一 Windows GATT host 改为带托盘、无终端的普通用户进程，仅在确认当前物理控制台锁定时广播。用户反馈测试动作均符合预期，唯一报告的问题是实际解锁、广播停止后托盘仍显示“错误”；该提示逻辑已修正，2026-10-02 用户确认最新提示修正回归成功。第一阶段五轮专项验收记录仍待补齐。登录任务和安装器重构已接入代码，按用户要求跳过验证；本轮未构建、安装或实测。此前 host 实测记录为手动启动，iPhone App 保持前台；身份变化与部分拒绝路径尚未完成验收。重启后首次登录明确不支持手机登录：不显示自定义磁贴，使用原生登录方式；手机解锁只用于已有会话再次锁屏。

2026-10-02 冻结记录（用户实体机实测反馈）：手机批准后的自动解锁通过；再次锁屏且不发起手机批准时保持锁定，重新手机批准后再次自动解锁，原生 PIN/密码仍可用。Components Wizard 的 Update 更新流程也已确认通过。冻结范围为“前台 iPhone 批准 → 自动解锁已有会话 + 安装器正常更新”，不代表完整负面测试或生产级更新恢复已通过。

## 当前边界

2026-10-02 用户补充实测：重启后首次登录不显示自定义磁贴，使用原生密码进入 Windows。这符合预期，是保留的行为边界，不是缺失功能或待实现的首次登录路径。

- BLE 只运输 challenge、assertion 和结果，不把“附近存在设备”当作认证。
- iPhone 私钥不可导出；Windows 只保存登记后的 P-256 公钥和账户 SID。
- Windows 密码由专用 LocalSystem 服务使用自身 user scope 的 DPAPI 保存，不使用 `CRYPTPROTECT_LOCAL_MACHINE`；Credential Provider 只能在有效手机授权窗口内领取一次。
- Credential Provider 不提供手输密码输入框，也没有绕过手机批准的测试开关。
- 当前分支不包含自定义 LSA Authentication Package。此前的无密码 token 构造研究没有形成可用产品路径，相关探针和兼容层已经移除。
- 公钥登记必须在已解锁控制台由用户主动开启配对，立即处理一次 UAC，等待窗口就绪后再经 BLE 发送公钥，在同一 `unlock_pairing_tool` 窗口核对完整指纹并确认。正常模式拒绝蓝牙登记；Windows 交互已获用户符合预期的反馈；iPhone 与完整蓝牙登记专项测试暂缓，手工登记工具仍可使用。
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

- `windows/GattHost`：暴露四个 GATT characteristic；正常模式处理认证请求 `0x01`，本地主动开启的配对窗口另接收 `0x02 + 公钥`。停止广播时不主动断开连接。原锁屏广播和提示修正已获用户预期反馈，新增 Windows 交互已获用户确认；完整蓝牙登记验收暂缓。
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
4. 新安装器部署后由目标用户登录任务启动托盘（待验收）；此前实测为普通用户手动启动 `unlock_gatt_host`，然后锁定 Windows。自动解锁链路此前已由用户确认；托盘 host 测试动作也已获用户预期反馈，最新提示修正已获用户回归成功反馈。五轮生命周期验收步骤与当前记录见 [GATT host](windows/GattHost/README.md#实体机验收记录与待验证项)。
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

- 构建并验收新增蓝牙公钥登记代码：两种 UAC 身份实验已获用户截图确认通过，实验探针源码已移除；Windows 交互已获用户确认；iOS、原子保存及取消／失败专项测试暂缓。[操作与验收要求](windows/GattHost/README.md#蓝牙公钥登记代码已接入产品待验收)。
- 补齐用户态 GATT host 的五轮实体机广播生命周期验收记录；新代码已接入 Components Wizard 和登录任务，自动启动、SYSTEM 续办、Update 恢复与卸载分别待验收。
- 验证自动提交在 CP 重建、重复枚举、打包失败和服务中断等场景下的单次行为。
- 为重复认证请求返回比通用 `not_ready` 更明确的“已有有效授权”状态。
- 完成身份切换、错误签名、过期、重放、非 LogonUI 调用者和服务重启等负面路径验收。
- 生产级安装、签名、更新和恢复策略。

## 未来方向
- 提供 MSI 安装包，规划服务、桌面组件及登录任务的安装、升级和卸载。尚未实现；当前安装入口仍为 Components Wizard。

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

## 配对 UI 调整（2026-10-02，Windows 交互已获用户确认）

应用图标以根目录 `icon.png` 为来源，转换为多尺寸 ICO 后嵌入所有 Windows EXE，托盘使用同一资源，部署无需额外 PNG；菜单的退出始终位于最底部。新增移除手机登记按钮：一次 UAC 后显示目标账户和删除确认窗口，取消不修改登记，确认仅删除手机公钥并重新加载服务，不修改密码副本。移除期间不开放桌面配对广播。用户已确认 Windows 交互符合预期；完整登记、移除后的实际效力和失败专项尚未验收，测试暂缓。

点击配对立即请求一次 UAC；窗口显示等待手机，工具就绪后才开启配对广播。公钥经受限本地命名管道交给工具，同一窗口随后显示完整指纹并允许确认，无第二次 UAC。通道拒绝远程连接、限定 ACL 并核对双方实际进程身份和原控制台用户 SID。用户明确要求跳过独立通信实验，已直接接入产品并删除新探针；Windows 交互已获用户确认；跨管理员产品通信及完整生命周期尚未逐项验证，测试暂缓。

## 当前验证状态（2026-10-02）

用户已确认 Windows 方面的交互符合预期。本记录覆盖用户对当前 Windows 交互的总体反馈，不将首次登记后解锁、更换后旧手机失效、移除后的实际效力、密码副本不变、另一管理员凭据通信及取消／超时／失败专项分别记为通过。iOS 改动及完整两端蓝牙登记仍待验证，用户明确暂缓后续测试；原子保存回归用例也未由代理编译或执行。

安装器当前部署 System32 工具并注册目标用户 Run；用户确认新版本 Update 和自启项注册成功。实际重新登录自启与完整卸载等专项未单独确认；完整蓝牙登记仍未最终验收。

## 安装器与登录自启（2026-10-02，代码接入，待验收）

独立 Win32 页面取代 Wizard97 导航和更新复选框，六个预编译组件统一部署到 System32。蓝牙只通过目标用户 Run 登录自启，以普通权限运行；密码服务保持开机自动启动。重启续办由 SYSTEM 无窗口完成，结果由目标用户普通权限提示，详见 [安装流程](windows/ComponentsWizard/README.md)。用户已确认 Update 和自启项注册成功；结构清理后的代码仍需回归。本轮未更改认证协议、密码格式或 iOS，原有 iOS 工作区改动保留。

参考：[Task Scheduler schema](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-scheduler-schema)、[ITaskFolder::DeleteTask](https://learn.microsoft.com/en-us/windows/win32/api/taskschd/nf-taskschd-itaskfolder-deletetask)。

[Microsoft Shell link flags](https://learn.microsoft.com/en-us/windows/win32/api/shlobj_core/ne-shlobj_core-shell_link_data_flags)：凭据管理快捷方式的提权配置。

## Windows 程序图标

所有 CMake EXE 目标（包括服务、管理器、GATT host、PairingTool、Components Wizard 和测试程序）统一嵌入由根目录 `icon.png` 转换的 `windows/Resources/AppIcon.ico`。ICO 包含 16、24、32、48、64、128、256 像素尺寸；GUI 窗口及 GATT 托盘也使用同一图标资源。更新源 PNG 后运行 `powershell -File windows/Resources/Update-AppIcon.ps1` 重新生成 ICO，再在获得构建授权后构建。运行和部署不需要外置 PNG 或 ICO。

2026-10-02：图标资源已接入，ICO 内容与 EXE 目标覆盖已做静态检查；本次未构建或运行，新 EXE 图标及窗口显示仍待验证。

## 安装器任务身份校验修复（2026-10-02）

实体机更新后观察到：Task Scheduler 返回 `denni` / `SPITSBERGEN\denni`，解析后的 SID 与安装事务 `TargetSid` 一致，且登录类型为 Interactive、权限为 Limited；原安装器直接比较账户名和 SID，误报身份不匹配。任务主体及登录触发器现统一解析为 SID 后核对，仍要求交互用户 token 与最低权限；空账户或解析失败明确报错，不跳过验证。修复仅做静态检查，尚未构建或验证失败更新的续办，不清理原事务或保存凭据。

## 蓝牙登录自启入口（2026-10-02，代码改动待验收）

用户确认前述安装器修复后安装成功；随后观察到登录任务运行返回 1，而同一安装程序手动启动和稍后运行任务正常。现按用户要求将 GATT 自启改为目标用户的 `Run` 项，值名 `Unlock Windows with iPhone`，可由任务管理器启动应用管理。更新移除原 GATT 登录任务，卸载清除自启项；保留目标 SID，不写另一 UAC 管理员的 HKCU。系统开机续办能写未登录目标用户的现有 hive，普通权限完成结果页负责首次启动，后续由用户登录启动；不强制改写 Windows 的用户禁用选择。

托盘注册失败时保留进程、记录错误并等待任务栏/定时器重试。开机任务栏时序是推断而非已捕获异常。用户随后确认改用 Run 后 Update 与自启项注册成功；再次重启/登录自动启动、禁用/启用及离线 hive 专项仍待确认。认证协议和保存密码未改，此 Windows 清理任务未修改 iOS。

参考：[Run and RunOnce registry keys](https://learn.microsoft.com/en-us/windows/win32/setupapi/run-and-runonce-registry-keys)、[RegLoadKeyW](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regloadkeyw)。

## Windows 部署清理与冻结边界（2026-10-02）

ComponentFiles.h 唯一定义六个部署文件及工具属性，暂存、替换、路径核对和工具移除复用同一清单；DesktopDeployment.cpp 统一管理任务、Run、快捷方式和托盘交接，移除重复 COM/任务封装及转调接口。Run 是唯一持续 GATT 自启入口，旧任务名仅用于迁移移除和诊断。事务 TargetSid 是目标身份来源，观察快照与完成结果不另行选择用户。

可冻结已观察的 Update 与自启项注册成果，不扩大为全部部署测试通过。此次结构清理仅静态检查，新增清单用例未编译或执行；清理后的二进制仍需一次 Update/登录自启及手机解锁回归。具体当前流程与待验收项集中在 [安装器文档](windows/ComponentsWizard/README.md)。
