<!-- Created by Rui MA on 27 Sep 2026 -->

# 自动解锁认证模式 TODO

本项目只采用“自动解锁认证模式”：完成首次登记后，iPhone 在后台自动发现已登记的 Windows 电脑，自动建立 BLE 连接、完成 challenge 签名并触发解锁流程。

运行期间不使用 NFC、Face ID、手动确认或 Windows 通知确认。首次登记仍必须保留 Windows 指纹确认，避免把未知公钥写入本机。

## 下一步开发顺序（固定主线）

Components Wizard 当前已可用，UI 细节暂时冻结。除非安装、卸载或恢复流程出现功能性问题，不应在下列端到端主线完成前继续打磨 Wizard UI。

1. **完成并提交当前 Components Wizard 事务化改造**
   - 先修正提交前已发现的作者注释、README 重复、只读诊断和 PowerShell 兼容入口问题。
   - 保持 Wizard 仅管理当前 Credential Provider 和 LSA package，不在这一步顺带加入新服务。
2. **立即进行实体 iPhone 前台协议联调**
   - 使用前台 iOS App、前台 `GattHost` 和前台 `UnlockService` 验证完整链路：`iPhone -> GATT -> challenge -> assertion -> unlock_approved`。
   - 验证首次登记、公钥指纹确认、签名验证、过期、重放和重复请求。
   - 该阶段属于“真机 BLE/协议联调”，不代表 Windows 锁屏已解锁。
3. **将 `UnlockService` 改为真正的 Windows Service，并重设计 IPC 授权**
   - 服务运行在 Session 0，支持开机启动、停止、崩溃恢复和安全卸载。
   - 不得简单删除当前 named-pipe 同用户检查或对所有本地进程放行。
   - 按操作和调用方身份区分权限：GATT 仅能请求 challenge/提交 assertion，PairingTool 仅能执行管理员确认后的登记刷新，LogonUI/SYSTEM 仅能消费一次性 approval。
   - 优先考虑拆分 IPC 端点或对每个 operation 做独立的客户端身份验证，并增加跨 Session 测试。
4. **打通手动点击 tile 的 VM 锁屏纵向链路**
   - 暂时保留前台 GATT 和 iPhone App，也暂时允许手动选择 Credential Provider tile。
   - 验证：`iPhone assertion -> UnlockService approval -> GetSerialization -> LSA package -> Windows 登录结果`。
   - 这是第一个“系统锁屏解锁”里程碑，必须只在一次性 VM、测试账户或备用电脑上执行。
5. **修正并验证 LSA 登录语义**
   - 根据 VM 实际回调结果处理 `CPUS_LOGON` 对应的 `Interactive` 与 `Unlock` 登录类型，不再假定只会收到 `Unlock`。
   - 完整验证 `LSA_TOKEN_INFORMATION_V2` 中用户 SID、主组、组、权限、Owner 和默认 DACL 等字段。
   - 验证失败路径不影响 Windows Hello、PIN 和密码恢复入口。
6. **实现 Credential Provider 的 approval 通知和自动提交**
   - 利用 Credential Provider events 在 approval 到达时通知 LogonUI 刷新凭据。
   - 在安全条件满足时自动触发 `GetSerialization`，取消选择 tile 和点击 Unlock 的要求。
   - 保证 approval 只能消费一次，超时或 UI 重建不会导致重复登录。
7. **完成 Windows 后台 GATT 和 iOS 后台自动化**
   - 为 Windows GATT 提供 package identity、`bluetooth` capability 和可靠的锁屏生命周期。
   - 完成 iOS 自动扫描、连接、状态恢复、断线重连、超时和指数退避。
   - 实体 iPhone 锁屏且 App 不在前台时，验证 Windows 锁屏从发现到解锁的完整自动链路。
8. **将 Windows Service 和后台 GATT 纳入 Components Wizard**
   - 只在服务和后台 GATT 的安装/卸载边界稳定后扩展 Wizard 事务。
   - 继续遵守“先撤销注册与启动项，重启后再删除仍可能被占用的二进制文件”的回滚原则。
9. **最后处理发布级安全、签名与 Wizard UI 精修**
   - 完成 LSA Protection/签名路线、审计日志、威胁模型和失败恢复验证。
   - 在功能边界稳定后再统一优化 Wizard 交互、文案和视觉细节。

阶段定义：

- **真机 BLE/协议联调**：实体 iPhone 与 Windows 前台组件产生 `unlock_approved`，不含系统解锁。
- **VM 锁屏纵向链路**：可以使用前台 GATT 和手动 tile，但 approval、Credential Provider、LSA 和登录结果必须真实贯通。
- **后台自动解锁**：iPhone 与 Windows 都在后台/锁屏生命周期中自动恢复，不要求手动选择 tile 或点击 Unlock。

## 当前已完成

- [x] iPhone Secure Enclave P-256 私钥和 Keychain 持久化
- [x] iOS CoreBluetooth Central、BLE service/characteristic 和状态恢复骨架
- [x] iOS `bluetooth-central` 后台能力声明
- [x] Windows 前台 GATT Host 广播和 characteristic 传输
- [x] challenge、签名 assertion、重放和过期校验
- [x] Windows CNG P-256 验签
- [x] Windows 公钥指纹登记和通知确认
- [x] DPAPI/ACL 保护的公钥登记存储
- [x] 登记记录保存 Windows 用户 SID
- [x] `UnlockServiceCore` 在签名验证后绑定登记 SID，并输出 `unlock_approved` 决策信号（不执行系统解锁）
- [x] 定义 Credential Provider/LSA 共用的无密码提交缓冲区，并增加结构校验测试（不注册系统组件）
- [x] 实现只用于 SDK/COM smoke test 的 `CPUS_LOGON`/`CPUS_UNLOCK_WORKSTATION` Credential Provider shell（不注册、不返回登录凭据）
- [x] Credential Provider 增加 V2 用户关联：通过 `ICredentialProviderSetUserArray` 和 `ICredentialProviderCredential2::GetUserSid` 绑定当前 Windows 用户
- [x] 增加只构建不注册的 LSA Authentication Package 原型：独立校验 `UnlockLogonBuffer`、登记公钥、SID、audience、时间窗口和签名，并准备 SID 映射的 token 信息
- [x] 增加仅供一次性 Windows VM 使用的 LSA 注册备份/回滚脚本和只读 package lookup smoke test（默认不执行、不注册）
- [x] 在关闭 LSA Protection 的一次性 VM 中完成 LSA package 注册、重启和 package ID 查询
- [x] 增加仅供一次性 Windows VM 使用的 Credential Provider 注册/回滚脚本，并完成注册表/DLL 路径检查
- [x] 增加原生 Windows EXE 向导：安装/验证 Credential Provider 与 LSA package，并支持通过 `--resume-uninstall` 手动完成重启后的 DLL 和状态清理
- [ ] 验证并修复 Windows 11 登录后自动触发 EXE 卸载续跑任务
- [x] 对自动解锁批准加入短冷却和一次性 challenge 消费，抑制 BLE 重复发现造成的连续批准
- [x] UnlockService named-pipe IPC
- [x] Windows CMake/Makefile 构建和六个 CTest

## 借鉴成熟方案的边界

已实现的协议、BLE 传输、Secure Enclave 签名、Windows CNG 验签、DPAPI 登记和首次指纹确认暂时冻结，不直接替换为参考项目的实现。

- [x] 参考 UnTouchID 的分层思路：后台常驻组件、一次性 challenge、短期有效的配对凭据、重放保护、连接重试和审计日志
- [x] 参考 EIDAuthentication 的 Windows 边界：Credential Provider 负责锁屏交互，LSA/受保护服务负责认证结果和 SID 映射，安装/卸载/回滚必须独立设计
- [ ] 不直接复制参考项目代码；EIDAuthentication 使用 GPL-3.0，后续若需要复用代码必须先单独处理许可证问题
- [x] 在接入实际登录 Token 前先完成认证决策信号 `unlock_approved`

参考项目：

- [UnTouchID](https://github.com/HMAKT99/UnTouchID)（macOS/PAM 架构参考，不作为 Windows 实现）
- [EIDAuthentication](https://github.com/SP00KY-CB/EIDAuthentication)（Windows Credential Provider/LSA 架构参考，不复制智能卡和密码逻辑）

## 1. iOS 后台自动认证

- [ ] 增加“启用自动解锁”设置，并在首次登记成功后持久化状态
- [ ] App 启动、蓝牙恢复和系统唤醒时自动扫描项目 GATT service
- [ ] 发现已登记 Windows 广播后自动连接，不要求点击“开始连接”
- [ ] 后台自动订阅 challenge/result characteristic
- [ ] 自动发送 request、接收 challenge、签名并写回 assertion
- [ ] 处理断线重连、重复发现、重复 request、超时和指数退避
- [ ] 收到 `unlock_approved` 后停止本轮扫描，避免重复认证
- [ ] 蓝牙关闭、权限撤销、App 被系统终止时显示明确状态
- [ ] 实体 iPhone 验证前台、后台、锁屏、重新启动 App 和断线重连
- [ ] 记录并验证 iOS 后台扫描不是实时保证，不能把超时当成认证失败

## 2. Windows 后台 GATT 生命周期

- [ ] 将前台 `GattHost` 改为带 package identity 的后台 GATT 组件
- [ ] 验证 `GattServiceProvider` 在 Windows 锁屏时仍能广播和接收写入
- [ ] 将 `UnlockService` 改为真正的 Windows Service
- [ ] 配置开机启动、服务停止、崩溃恢复和安全卸载
- [ ] 按 operation 和客户端身份重设计 named-pipe 授权，允许经验证的 LogonUI/SYSTEM 消费 approval，且不向其他本地进程放开敏感操作
- [ ] 验证 GATT、PairingTool 和 Credential Provider 在 Session 0/跨 Session 场景下只能调用各自被授权的 IPC operation
- [ ] 后台服务启动后自动加载 DPAPI 登记记录和 Windows SID
- [ ] 后台服务不能依赖交互式桌面、控制台窗口或 Windows 通知

## 3. 自动解锁决策层

- [x] `UnlockServiceCore` 保存已登记公钥对应的 Windows SID
- [x] 签名验证成功且 SID 有效时返回 `unlock_approved`
- [ ] 未登记、错误公钥、错误 SID、过期 challenge 和重放始终拒绝
- [x] 自动认证结果加入冷却时间和重复请求抑制
- [ ] 增加可配置 RSSI 近距离阈值，信号过弱时不触发自动认证/解锁
- [ ] 对 RSSI 连续采样取平均并加入进入/离开滞回，避免瞬时波动反复触发
- [ ] RSSI 只能作为距离门控，不能替代签名和公钥身份认证
- [ ] 增加自动批准、拒绝、超时和重放的单元测试与 IPC 测试

## 4. Windows 真正解锁

- [x] 设计 Credential Provider 与 UnlockService/LSA 的 IPC 边界
- [x] 定义 Credential Provider 与 LSA 共享的 `UnlockLogonBuffer` 输入边界（仅 codec，不注册 DLL）
- [x] 增加仅供测试的 Credential Provider serialization adapter，验证已批准字段能生成 `CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION`
- [x] 定义开发期 `consumeUnlockApproval` named-pipe 边界：一次性、短期、返回二进制 `UnlockLogonBuffer`
- [x] 让未注册的 Credential Provider 在 LSA 包存在时消费受保护的短期批准并提交 `UnlockLogonBuffer`
- [x] 增加只构建不注册的 LSA Authentication Package callback 和独立验签测试；包内增加进程生命周期内的 request ID 防重放
- [x] 将真实 LSA Authentication Package 注册到测试 VM 并完成 package lookup smoke test（LSA Protection 关闭）
- [x] 验证 Windows 11 ARM VM 中 Credential Provider tile 出现在锁屏，并在点击后完成 LSA package lookup
- [x] 查明一次性 VM 中 LogonUI 仅显示 PIN 的原因：旧 x64 DLL 不能由 ARM64 LogonUI 加载，且旧版本拒绝 Windows 10+ 常用的 `CPUS_LOGON`
- [ ] 在 Credential Provider 真正出现在锁屏后，验证 tile 激活、`GetSerialization`、LSA package lookup 和一次性批准消费的完整链路
- [ ] 让认证结果只映射到登记记录中的 Windows SID
- [ ] 研究并实现不保存 Windows 密码的 LSA Authentication Package
- [ ] 在 VM 中记录 `CPUS_LOGON`/`CPUS_UNLOCK_WORKSTATION` 实际对应的 LSA logon type，并正确处理 `Interactive` 与 `Unlock`
- [ ] 完整构造并验证 `LSA_TOKEN_INFORMATION_V2` 的 SID、组、权限、Owner 和默认 DACL
- [ ] 验证认证包返回的登录 Token 和锁屏解锁流程
- [ ] 在 approval 到达时通过 Credential Provider events 通知 LogonUI，并在安全条件满足时自动提交凭据
- [ ] 保留 Windows Hello/PIN/密码作为系统恢复入口
- [ ] 仅在测试账户、虚拟机或备用电脑上验证，完成回滚和卸载流程

## 5. 端到端验证

- [ ] 首次登记后关闭两个前台程序，确认后台组件自动恢复
- [ ] iPhone 锁屏且 App 不在前台时，验证自动连接和签名
- [ ] Windows 锁屏时验证 GATT 广播、challenge 和 assertion
- [ ] iPhone 离开范围后确认不会产生新的解锁批准
- [ ] 手机留在电脑旁、用户离开时记录当前自动模式的安全语义
- [ ] Windows 服务重启后验证公钥和 SID 持久化
- [ ] 蓝牙断开、电脑睡眠/唤醒、iPhone 重启后验证恢复
- [ ] 运行 `make test`，确认全部 Windows 测试通过

## 当前 Windows VM 阻塞记录

- Windows Release 构建和 6 个 CTest 已通过。
- 一次性 Windows 11 ARM VM 中 LSA package lookup 已返回 package ID；Credential Provider tile 已出现在锁屏，点击后会通过 LSA lookup 并返回 “No pending iPhone unlock approval is available”。
- 当前阻塞点是将有效 iPhone assertion 生成的一次性 approval 安全交给 LogonUI；当前前台 `UnlockService` 的同用户 IPC 校验不接受锁屏的 SYSTEM 客户端。
- 尚未完成 iPhone/BLE assertion、一次性 approval 消费、LSA token 返回和实际锁屏解锁的完整链路。

## 6. LSA Protection 与生产发布

- [x] 确认 LSA Protection 会阻止当前未经过 Microsoft LSA 签名的 package
- [x] 将“关闭 LSA Protection 仅限一次性 VM”记录为 Windows 已知问题
- [ ] 生产路线：组织身份、EV 代码签名证书、Partner Center Hardware Developer Program 和 Microsoft LSA File Signing
- [ ] 个人开发路线：评估 Credential Provider + 受保护服务方案，避免把 Microsoft LSA 签名当作 MVP 前置条件
- [ ] 不在宿主机或日常使用系统关闭 LSA Protection

## 明确不采用

- [ ] NFC 贴近确认
- [ ] UWB 距离测量（当前电脑和测试环境没有 UWB 硬件）
- [ ] 运行期间 Face ID 或人工确认
- [ ] 仅依靠 RSSI、蓝牙连接状态或传统蓝牙配对作为认证
- [ ] 在配置文件中保存 Windows 密码或 PIN
