<!-- Modified by Rui MA on 26 Sep 2026 -->
<!-- Modified by Codex on 26 Sep 2026 -->

# Unlock Windows with iPhone

这个项目探索并实现一条明确的认证链路：

> iPhone 持有 Secure Enclave 私钥 → Windows 发起一次性 challenge → iPhone 签名 → Windows 用已登记的公钥验证 → 后续接入 Windows 解锁流程

项目不把“附近发现 iPhone”或 BLE RSSI 当作认证依据。BLE 只负责传输；真正的身份依据是 iPhone 上的非导出私钥和 Windows 端登记的公钥。

## 当前状态

当前已经完成协议、安全密钥存储、iOS BLE Central 骨架，以及 Windows 侧的协议/CNG 验证、前台 GATT 传输和首次登记原型：

- iOS App 的 Secure Enclave P-256 密钥生成与 Keychain 持久化。
- Keychain 使用 `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`；这允许设备重启后完成第一次解锁之后，在 iPhone 再次锁屏时读取密钥并签名。
- 明确的 challenge/签名数据结构和跨平台固定二进制签名载荷，JSON 只作传输外壳，见 [`protocol/README.md`](protocol/README.md)。
- App 内的本地签名和本地公钥验证测试，以及可见的错误信息。
- iOS CoreBluetooth Central 状态机：扫描、连接、状态恢复、challenge notify、签名和 assertion 回写；Windows 已有可运行的前台 GATT host。
- iOS 后台蓝牙中心角色所需的 Info.plist 声明。
- Windows CNG/BCrypt P-256 公钥导入、SHA-256 和原始 `r || s` 签名验证代码。
- Windows 与 iOS 一致的签名载荷构造代码，以及供未来 LSA 使用的无密码提交缓冲区定义。

当前还没有完成：

- Windows GATT host 的后台/锁屏生命周期、package identity 和完整安装流程。
- Windows `PairingTool` 的公钥确认通知和受保护登记存储已经有原型，iOS UI 已支持通过 GATT 发送登记公钥；剪贴板复制仅作为备用调试路径。
- Windows Credential Provider 的生产实现。
- 无密码的 LSA Authentication Package。
- “检测到 iPhone 后自动解锁”的端到端流程。

Windows 侧当前没有可安装的服务、Credential Provider 或 LSA 包；前台 GATT、IPC、受保护公钥登记和配对确认工具可以在 Windows SDK 环境中编译验证。

不会用软件私钥、密码硬编码、静默重试或吞掉异常来伪造这些功能。某个阶段未实现或系统拒绝访问时，App/服务应报告明确错误。

### 已知问题（iOS BLE，暂缓处理）

以下问题已经确认，但暂时不作为当前 Windows 主线的阻塞项，后续实现 GATT host 和跨平台传输测试时统一处理：

- iOS 在调用 `setNotifyValue(true, for:)` 后会立即写入 request；应等待 challenge characteristic 的订阅成功回调，避免 Windows 已发送通知但 iOS 尚未完成订阅。
- challenge 和 assertion 当前直接以完整 JSON 写入 characteristic，尚未实现应用层 MTU 分片、重组、消息长度限制、乱序/重复片段拒绝和传输超时。
- result characteristic 已订阅，但 iOS 尚未消费明确的成功/失败回执，也没有把回执状态暴露到界面。
- CoreBluetooth 的后台恢复、锁屏 iPhone、Windows 锁屏以及 BLE 断线重连的组合生命周期尚未在实体设备上验证。
- BLE 配对/链路保护与 Windows GATT characteristic 的权限策略尚未完成联调；BLE 仍然只负责传输，不能替代签名认证。
- App 中仍有部分说明文字把 BLE 描述为“尚未接入”，需要在 BLE 传输稳定后统一更新 UI 文案。

## 解决的问题与边界

### iOS 端

iOS App 负责：

1. 在 Secure Enclave 可用的实体 iPhone 上创建 P-256 签名密钥。
2. 将 Secure Enclave 私钥的持久化表示放入 Keychain，访问级别为 `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`。
3. 用 Windows 发来的 challenge 生成签名 assertion。
4. 通过 CoreBluetooth 作为 Central 连接 Windows 端 GATT Server。

这个访问级别有一个必须接受的安全语义：它保证“本机自上次重启后已经成功解锁过”，不保证“当前屏幕处于解锁状态”或“当前一定是本人在操作”。因此本项目的第一版目标是允许锁屏 iPhone 响应 challenge；如果以后要求当前用户在场，需要改用带用户参与条件的 Keychain/Secure Enclave access control，并重新评估后台可用性。

模拟器没有可用的 Secure Enclave，本项目不会悄悄退回软件密钥。请在实体 iPhone 上测试密钥阶段。

### Windows 端

Windows 端最终需要拆成四个组件：

- `GattHost`：带 package identity 的 Windows GATT host，优先使用 `GattServiceProvider`/后台 GATT provider 接收 iPhone 连接。它不是普通桌面进程；是否能在目标 Windows 版本的锁屏阶段持续工作，必须在实体机器上验证。
- `UnlockService`：Windows Service，运行在 Session 0，维护 challenge 超时/防重放、已登记公钥、协议验证和与 Credential Provider/LSA 的 IPC。当前不把“普通 Session 0 服务直接调用 GATT Server”当成已验证事实。
- `CredentialProvider`：实现 `CPUS_UNLOCK_WORKSTATION`，向 LogonUI 提供解锁凭据入口。它不能靠普通桌面 App 的 UI 自动解锁。
- `PairingTool`：只负责首次配对、显示并确认公钥指纹、安装/注册所需组件。

此外还有 `LSAAuthenticationPackage`：它由 LSA 在系统启动时加载，接收自定义的无密码认证数据，重新验证 iPhone 签名并为已映射的 Windows 用户返回登录 Token。它不能依赖普通用户桌面进程的内存结果。

真正不保存 Windows 密码的方案需要自定义 LSA Authentication Package，将验证后的公钥身份转换为 Windows 的认证令牌。这是高权限、系统级、安全敏感的代码，尚未实现；不能用“把 PIN/密码放在配置文件里”冒充无密码方案。

Windows Hello / WebAuthn 可以作为交互式登录或凭据能力的研究方向，但不是本项目锁屏自动解锁的直接替代品。Credential Provider 和 LSA 的边界、安装权限以及 Windows 版本兼容性需要单独验证。

## 目录结构

```text
.
├── README.md
├── protocol/
│   └── README.md
├── ios/
│   ├── ios.xcodeproj/
│   ├── App/Info.plist
│   ├── Core/
│   │   ├── UnlockError.swift
│   │   ├── SecureEnclaveKeyStore.swift
│   │   ├── UnlockProtocol.swift
│   │   ├── BluetoothAuthenticator.swift
│   │   └── UnlockSetupModel.swift
│   ├── ContentView.swift
│   └── MyApp.swift
└── windows/
    ├── CMakeLists.txt
    ├── GattHost/
    ├── UnlockService/
    ├── CredentialProvider/
    ├── LSAAuthenticationPackage/
    ├── PairingTool/
    └── Protocol/
        ├── UnlockCrypto.*
        ├── SigningPayload.*
        ├── UnlockLogonBuffer.h
        └── README.md
```

这是一个根目录下同时包含 iOS target 和 Windows 工程的跨平台项目；两边共享的是协议和测试向量，不共享 UI 或平台安全 API。

## iOS：安装方式

要求：

- macOS 和 Xcode 26.3 或更高版本（项目当前由该版本创建）。
- 一台能运行当前 Deployment Target 的实体 iPhone。
- Apple Developer 签名团队；免费个人签名也可以用于开发验证，但有效期和后台能力受 Apple 规则限制。

安装步骤：

1. 用 Xcode 打开 `ios/ios.xcodeproj`。
2. 在 target `ios` 的 Signing & Capabilities 中选择你的 Team，并确认 Bundle Identifier 可用。
3. 选择实体 iPhone，而不是 Simulator，运行 App。
4. 首次启动时允许蓝牙权限。
5. 点击“准备密钥”生成或读取 Secure Enclave 私钥。
6. 点击“执行本地签名测试”确认本机可以完成签名和公钥验证。
7. 点击“开始连接”会扫描项目定义的 Windows GATT service；在 Windows `GattHost` 尚未实现前，页面会显示明确的连接失败或无设备状态，不会报告认证成功。

## iOS：使用方法

1. 启动 App。
2. 点击“准备密钥”。App 会创建或读取 Secure Enclave 私钥，并显示公钥 SHA-256 指纹。
3. 点击“执行本地签名测试”。App 会生成随机 challenge、签名，并使用公钥在本地验证；成功或失败都会显示在界面上。
4. 如果设备刚重启且尚未第一次解锁，Keychain 可能返回系统拒绝访问错误。先手动解锁一次，再重试；这不是被隐藏的 fallback。

当前 App 不会因为附近存在某个蓝牙设备就报告认证成功；必须完成指定 service、characteristic 和 challenge 签名链路。

## Windows：安装方式

完整 Windows 组件尚未实现，因此现在没有可安装的 Windows MSI、服务或 Credential Provider，也不应把原型注册为系统组件。当前仓库已经有协议/CNG 库、前台 GATT host、IPC host 和 PairingTool，但仍只能在 Windows SDK 环境中构建验证。

下一阶段的开发环境预期为：

- Windows 11 x64。
- Visual Studio 2022，安装 “Desktop development with C++” 和 Windows App SDK/C++/WinRT 所需组件。
- Windows SDK，包含 Bluetooth GATT、Windows Service、Credential Provider 和 LSA 相关头文件/库。
- 支持 BLE 的硬件；开发阶段建议用独立的测试账户和虚拟机/备用机器。
- GATT host 需要带 package identity 的安装方式（MSIX 或 packaged with external location），因为 Windows 的后台/能力声明依赖 package identity。

构建当前协议/CNG 库的命令为：

```powershell
cmake -S windows -B windows/build -A x64
cmake --build windows/build --config Debug
```

也可以使用 `windows/Makefile` 简化命令：

```powershell
cd windows
make                 # 构建并运行测试
make build           # 只构建
make test            # 构建并运行测试
```

如果没有 GNU Make，在 Visual Studio Developer PowerShell/Command Prompt 中使用原生命令：

```powershell
nmake /f Makefile build
nmake /f Makefile test
```

Windows SDK 目标已在当前 Windows 环境完成构建和本机 CTest 验证；这仍不等于后台锁屏生命周期、Credential Provider 或 LSA 已经实现。

在 Windows 端可以运行的当前里程碑是协议验证工具、前台 GATT host、UnlockService IPC host 和 PairingTool，而不是直接注册 LSA 包。PairingTool 通过 Windows 通知要求用户确认后写入 DPAPI 保护的公钥；GATT host 不会自动登记公钥。完整里程碑仍必须证明：公钥到 Windows SID 的映射、challenge 新鲜度、签名验证、超时、重放拒绝以及锁屏时 GATT host 的生命周期都正确。

## Windows：使用方法（当前阶段）

当前还不能完成端到端自动解锁，因为 Windows 认证组件尚未实现。当前原型可以先按下面的流程登记公钥并验证 BLE/IPC 链路：

1. 启动 `unlock_service_host` 和前台 `unlock_gatt_host`。
2. 在 iPhone 点击“准备密钥”，再点击“登记到 Windows”；Windows 通知显示候选公钥指纹，确认与 iPhone 指纹一致后点击 Confirm enrollment。
3. iPhone 再点击“开始连接”；它通过 GATT 发送 assertion，UnlockService 从受保护登记存储加载公钥并返回验证结果。
4. 后续再安装带 package identity 的 `GattHost`，并将 `UnlockService` 转换为受保护的 Windows Service。
5. 锁屏时由认证链路生成 challenge，iPhone 返回签名 assertion。
6. `UnlockService` 和 `LSAAuthenticationPackage` 独立验证 assertion，并将公钥映射到指定 Windows 用户。
7. 认证包返回 Windows 登录 Token；Windows Hello/PIN/密码仍可作为用户主动选择的 fallback。
8. 任一验证、超时、权限或系统 API 错误都停止本次自动解锁并保留明确日志。

## 当前验证状态

- `ios/App/Info.plist` 已通过 `plutil -lint`。
- iOS 核心安全、协议和 BLE 源码已通过 Swift 类型检查。
- `windows/Protocol/SigningPayload.cpp` 已通过 macOS 上的 C++20 语法检查。
- 当前 Windows SDK 构建已通过全部目标，3 个 CTest 均通过；PairingTool 的帮助命令 smoke test 通过。
- Xcode 工程可以被 `xcodebuild -list` 正确解析。
- 完整 Xcode 构建曾被当前环境的 `swift-plugin-server`/sandbox 限制阻断；这属于构建环境限制，不能当作完整构建成功，也不能当作源码已经在真实设备上验证。

## 已确认的安全路线

已确认采用路线 A：不保存 Windows 密码，使用 iPhone 私钥签名和 Windows 公钥验证，再由自定义 LSA Authentication Package 完成认证。路线 B 只作为调试通信的临时验证方式，不会被实现成产品 fallback，也不会把密码写入配置文件。

LSA 包属于系统级登录组件。未完成隔离测试、签名、账户映射和恢复方案前，不会注册到日常使用的 Windows 主机。

## 参考资料

- [Apple：Protecting keys with the Secure Enclave](https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave)
- [Apple：`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`](https://developer.apple.com/documentation/Security/kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly)
- [Apple：Core Bluetooth background processing](https://developer.apple.com/library/archive/documentation/NetworkingInternetWeb/Conceptual/CoreBluetooth_concepts/CoreBluetoothBackgroundProcessingForIOSApps/PerformingTasksWhileYourAppIsInTheBackground.html)
- [Microsoft：Credential Providers](https://learn.microsoft.com/en-us/windows/win32/secauthn/credential-providers-in-windows)
- [Microsoft：LSA Authentication Model](https://learn.microsoft.com/en-us/windows/win32/secauthn/lsa-authentication-model)

## Windows 当前推进状态

- `windows/GattHost` 已有可编译、可运行的前台 GATT Server 原型：创建项目定义的 service 和四个 characteristic，接收 `0x01` request，发送 challenge，并接收 assertion 传输帧。
- `windows/UnlockService/UnlockServiceCore` 已独立实现 challenge 新鲜度、单次使用、assertion JSON 解析、P-256 公钥指纹匹配和 CNG 验签；`unlock_service_host` 通过同用户 named pipe 使用它，并从 DPAPI/ACL 保护的登记文件加载公钥。
- `unlock_pairing_tool` 已实现 Windows 通知确认按钮；iOS 可通过 GATT 发送登记候选公钥，但没有点击 Confirm 就不会写入公钥。
- Windows 本机的 `unlock_protocol_tests`、`unlock_service_tests` 和 `unlock_service_ipc_tests` 均已通过；全部 Windows 目标已完成 SDK 构建。
- 下一步是把当前前台登记流程提升为 package identity/MSIX、后台/锁屏生命周期、SID 映射和真正的 Windows Service；在这些完成前不会接入 Credential Provider 或 LSA 注册。
