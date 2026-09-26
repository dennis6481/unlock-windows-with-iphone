# Unlock Windows with iPhone

这个项目探索并实现一条明确的认证链路：

> iPhone 持有 Secure Enclave 私钥 → Windows 发起一次性 challenge → iPhone 签名 → Windows 用已登记的公钥验证 → 后续接入 Windows 解锁流程

项目不把“附近发现 iPhone”或 BLE RSSI 当作认证依据。BLE 只负责传输；真正的身份依据是 iPhone 上的非导出私钥和 Windows 端登记的公钥。

## 当前状态

当前是第一阶段骨架，已经有：

- iOS App 的 Secure Enclave P-256 密钥生成与 Keychain 持久化。
- Keychain 使用 `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`；这允许设备重启后完成第一次解锁之后，在 iPhone 再次锁屏时读取密钥并签名。
- 明确的 challenge/签名数据结构和 canonical JSON 编码约定，见 [`protocol/README.md`](protocol/README.md)。
- App 内的本地签名和本地公钥验证测试，以及可见的错误信息。
- iOS 后台蓝牙中心角色所需的 Info.plist 声明；BLE 连接和 Windows 端服务尚未声称完成。

当前还没有完成：

- Windows GATT Server、配对工具和跨平台 BLE 传输。
- Windows Credential Provider 的生产实现。
- 无密码的 LSA Authentication Package。
- “检测到 iPhone 后自动解锁”的端到端流程。

不会用软件私钥、密码硬编码、静默重试或吞掉异常来伪造这些功能。某个阶段未实现或系统拒绝访问时，App/服务应报告明确错误。

## 解决的问题与边界

### iOS 端

iOS App 负责：

1. 在 Secure Enclave 可用的实体 iPhone 上创建 P-256 签名密钥。
2. 将 Secure Enclave 私钥的持久化表示放入 Keychain，访问级别为 `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`。
3. 用 Windows 发来的 challenge 生成签名 assertion。
4. 通过 CoreBluetooth 作为 Central 连接 Windows 端 GATT Server（下一阶段实现）。

这个访问级别有一个必须接受的安全语义：它保证“本机自上次重启后已经成功解锁过”，不保证“当前屏幕处于解锁状态”或“当前一定是本人在操作”。因此本项目的第一版目标是允许锁屏 iPhone 响应 challenge；如果以后要求当前用户在场，需要改用带用户参与条件的 Keychain/Secure Enclave access control，并重新评估后台可用性。

模拟器没有可用的 Secure Enclave，本项目不会悄悄退回软件密钥。请在实体 iPhone 上测试密钥阶段。

### Windows 端

Windows 端最终需要拆成三个组件：

- `UnlockService`：Windows Service，运行在 Session 0，维护 GATT Server、challenge 超时/防重放、已登记公钥和 Credential Provider 的 IPC。
- `CredentialProvider`：实现 `CPUS_UNLOCK_WORKSTATION`，向 LogonUI 提供解锁凭据入口。它不能靠普通桌面 App 的 UI 自动解锁。
- `PairingTool`：只负责首次配对、显示并确认公钥指纹、安装/注册所需组件。

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
│   │   └── UnlockSetupModel.swift
│   ├── ContentView.swift
│   └── MyApp.swift
└── windows/
    ├── UnlockService/
    ├── CredentialProvider/
    └── PairingTool/
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
4. 首次启动时允许蓝牙权限。当前版本只完成密钥准备和本地签名测试，尚未开始 BLE 配对。

## iOS：使用方法

1. 启动 App。
2. 点击“准备密钥”。App 会创建或读取 Secure Enclave 私钥，并显示公钥 SHA-256 指纹。
3. 点击“执行本地签名测试”。App 会生成随机 challenge、签名，并使用公钥在本地验证；成功或失败都会显示在界面上。
4. 如果设备刚重启且尚未第一次解锁，Keychain 可能返回系统拒绝访问错误。先手动解锁一次，再重试；这不是被隐藏的 fallback。

当前 App 不会声称已经连接 Windows，也不会因为附近存在某个蓝牙设备就报告认证成功。

## Windows：安装方式

当前 Windows 组件尚未实现，因此现在没有可安装的 Windows MSI、服务或 Credential Provider，也不应把空目录注册为系统组件。

下一阶段的开发环境预期为：

- Windows 11 x64。
- Visual Studio 2022，安装 “Desktop development with C++”。
- Windows SDK，包含 Bluetooth GATT、Windows Service、Credential Provider 和 LSA 相关头文件/库。
- 支持 BLE 的硬件；开发阶段建议用独立的测试账户和虚拟机/备用机器。

在 Windows 端可以运行的第一个里程碑应是协议验证工具和 GATT 认证服务，而不是直接安装解锁 Provider。它必须先证明：公钥登记、challenge 新鲜度、签名验证、超时和重放拒绝都正确。

## Windows：使用方法（当前阶段）

当前没有可执行步骤，因为 Windows 认证组件尚未实现。实现后会把下面的流程补成可复制的命令和安装脚本：

1. 用 `PairingTool` 完成一次性配对并人工确认公钥指纹。
2. 以受保护的 Windows Service 身份运行 `UnlockService`。
3. 锁屏时由 Service 发起 challenge，iPhone 返回签名 assertion。
4. Service 验证 assertion 后，通过受支持的 Credential Provider/LSA 路径完成解锁。
5. 任一验证、超时、权限或系统 API 错误都停止本次自动解锁并保留明确日志，Windows Hello/PIN/密码仍可作为用户主动选择的 fallback。

## 安全决策（实现前必须确认）

下一阶段存在一个不能默认替用户选择的分叉：

- **路线 A：先做无密码的自定义 LSA Authentication Package。** 安全边界更符合目标，但开发、签名、安装和调试成本最高，错误可能影响系统登录。
- **路线 B：先做 Credential Provider + 测试账户桥接。** 只用于验证 BLE、challenge 和 LogonUI 生命周期；它需要一个明确的测试认证后端，不能作为最终产品，也不能把真实密码以明文或普通配置保存。

在开始写 Windows 解锁代码前，需要确认先走哪条路线。无论选择哪条路线，都不会把认证失败改成“继续尝试”或静默降级。

## 参考资料

- [Apple：Protecting keys with the Secure Enclave](https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave)
- [Apple：`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`](https://developer.apple.com/documentation/Security/kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly)
- [Apple：Core Bluetooth background processing](https://developer.apple.com/library/archive/documentation/NetworkingInternetWeb/Conceptual/CoreBluetooth_concepts/CoreBluetoothBackgroundProcessingForIOSApps/PerformingTasksWhileYourAppIsInTheBackground.html)
- [Microsoft：Credential Providers](https://learn.microsoft.com/en-us/windows/win32/secauthn/credential-providers-in-windows)
- [Microsoft：LSA Authentication Model](https://learn.microsoft.com/en-us/windows/win32/secauthn/lsa-authentication-model)
