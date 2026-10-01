<!-- Created by Rui MA on 27 Sep 2026 -->

# 自动解锁认证模式 TODO

本项目只采用“自动解锁认证模式”：完成首次登记后，iPhone 在后台自动发现已登记的 Windows 电脑，自动建立 BLE 连接、完成 challenge 签名并触发解锁流程。

运行期间不使用 NFC、Face ID、手动确认或 Windows 通知确认。首次登记仍必须保留 Windows 指纹确认，避免把未知公钥写入本机。

## 下一步开发顺序（固定主线）

Components Wizard 当前已可用，UI 细节暂时冻结。除非安装、卸载或恢复流程出现功能性问题，不应在下列端到端主线完成前继续打磨 Wizard UI。

当前里程碑（2026-10-02）：实体机已有会话锁屏时，前台 iPhone 签名获得 `unlock_approved`，用户手动点击保存凭据磁贴且未输入密码，Windows 成功解锁；原生密码入口仍可用。下面较早的自定义 LSA/VM 路线是历史研究计划，不是此刻的产品解锁路径。后台蓝牙与自动提交尚未完成。

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

## 当前 Windows 测试阻塞记录

- Windows Release 构建和 6 个 CTest 已通过。
- 一次性 Windows 11 ARM VM 中 LSA package lookup 已返回 package ID；Credential Provider tile 已出现在锁屏，点击后会通过 LSA lookup 并返回 “No pending iPhone unlock approval is available”。
- 当前阻塞点是将有效 iPhone assertion 生成的一次性 approval 安全交给 LogonUI；当前前台 `UnlockService` 的同用户 IPC 校验不接受锁屏的 SYSTEM 客户端。
- 尚未完成 iPhone/BLE assertion、一次性 approval 消费、LSA token 返回和实际锁屏解锁的完整链路。
- Gate 1 增加 `unlock_lsa_token_probe`：默认只读模式记录活动控制台 token 的 elevation、restriction、integrity、primary group、owner 和 default DACL；存在 UAC linked token 时，对比 desktop token、linked token 与 Authz 从 SID 推导的组和权限。显式 `--s4u` 模式仍要求内置 MSV1_0 为同一账户创建临时 interactive S4U token。两种模式都不构造生产 `LSA_TOKEN_INFORMATION_V2`。
- 2026-09-29：实体机三方 probe 确认正常 UAC token 对：desktop 为受限的 medium-integrity `Limited` token，linked 为不受限的 high-integrity `Full` token。Authz 与 linked full 都有相同的 24 个 privilege 名称，因此此前仅凭 Authz 比 filtered token 权限多就认定提权的结论已撤回；但 Authz 仍不等价于 full interactive token：`SeCreateGlobalPrivilege` 和 `SeImpersonatePrivilege` 未启用，Administrators 缺少 owner 属性，并缺少 interactive、console、logon SID、integrity、Microsoft Account 和 cloud-authentication SID，也不能提供真实 Primary Group、Owner 和 Default DACL。尚无合同证明 custom AP 的 V2 会经过原生 UAC filtering、linked-token 及 MSA/session 增补，因此 SID + Authz 仍不能用于生产。MSV1_0 S4U `Interactive` 继续因 `STATUS_BAD_VALIDATION_CLASS (0xC00000A7)` 被否决；生产 V2、未打包 GATT 探针和 GattAgent 重构继续暂停。
- 下一项 Gate 1 研究是 `GetAuthDataForUser` → `ConvertAuthDataToToken(Interactive)`。这两个 callback 只通过 SSP/AP 的 `SpInitialize` 获得；当前旧式 `Authentication Packages` 原型在 `LsaApInitializePackage` 中只收到 `LSA_DISPATCH_TABLE`，普通 EXE 无法直接调用。若继续实现，必须新建仅用于可丢弃测试系统的独立诊断 SSP/AP，通过 `Security Packages` 注册，拒绝所有登录请求，只返回所生成 token 的诊断报告；不得为了探针迁移现有生产 package 或 installer 的注册合同。
- 2026-09-29：已新增并成功构建独立的 `unlock_lsa_convert_probe_package` 与受信任 SYSTEM 客户端 `unlock_lsa_convert_probe`，用于直接执行 `GetAuthDataForUser` → `ConvertAuthDataToToken(Interactive)`；它不接入生产 AP，并拒绝所有登录及非受信任调用。实体机预检发现 `RunAsPPL=2`、`RunAsPPLBoot=2`，诊断 DLL 为 unsigned；Code Integrity 还已有 `APPLE-W.dll` 被事件 3033 拒载的本机证据。根据 Microsoft 的 PPL 签名要求，本轮尚未注册、复制 DLL、重启或加载 LSASS。继续实体机实验必须先明确选择 Microsoft LSA plug-in signing，或明确批准临时关闭 LSA protection 及其恢复方案。
- 2026-09-29：VM 已确认注册表、x64 DLL、VC runtime、关闭 PPL 与 Credential Guard 均符合探针条件；Code Integrity 事件 3066 证明 LSASS 已映射诊断 DLL，且审计策略允许加载，但 `LsaLookupAuthenticationPackage` 返回 `STATUS_NO_SUCH_PACKAGE`。根因范围已缩到 LSA 初始化：旧实现只要六个 helper 中任一个为空就在 `SpInitialize` 返回错误，而 Windows 会因此卸载且不登记 package。现已改为初始化成功后在诊断报告中逐项记录 helper availability；该修订尚未构建或重跑。
- 2026-09-29：应用上述 `SpInitialize` 修订并重新部署后，虚拟机再次确认事件 3066 仅以 audit 模式记录未签名诊断 DLL，且 DLL 实际驻留于 LSASS；但 `LsaLookupAuthenticationPackage` 仍返回 `STATUS_NO_SUCH_PACKAGE`。复核接口合同后撤回“必须补齐旧版 `LsaApLogonUser` 与 `LsaApLogonUserEx`”的判断：Microsoft 只要求三个 logon 回调至少实现一个，当前 `LsaApLogonUserEx2` 已满足。当前最小修正是在 `SpGetInfo` 声明 `SECPKG_FLAG_LOGON`，并改用字段名填充函数表；需要重新构建、部署和重启虚拟机验证，尚未据此得出 helper 可用性或 token 语义结论。
- 2026-09-29：`SECPKG_FLAG_LOGON` 修订后 VM 仍返回 `STATUS_NO_SUCH_PACKAGE`，因此不再用 package lookup 作为本轮 helper 实验的前置条件。诊断 DLL 现改为包内自报告：`SpInitialize` 将 helper availability 写入 `%SystemRoot%\Temp\unlock-lsa-convert-probe.txt`，第一次 `SpAcceptCredentials` 通知仅排队 worker、不读取 credential，并由 worker 运行既有转换探针后覆盖完整报告。该路径仍需重新构建、部署、重启和登录验证；生产 AP 合同保持不变。
- 2026-09-29：VM 包内自报告已实际运行，确认 `SpInitialize` 被调用，且 `GetAuthDataForUser`、`ConvertAuthDataToToken`、`FreeReturnBuffer` 及客户端缓冲区 helper 均可用。首次完整 probe 以 `STATUS_NO_SUCH_USER (0xC0000064)` 停止，明确原因为该 VM 尚无受保护 enrollment 记录；这不是 helper 或 token 转换结果。下一步是在同一 VM、同一目标交互用户下重新登记 iPhone 公钥后重启并重跑，不能复制另一台机器的 DPAPI enrollment 文件。
- 2026-09-29：VM 完成本机 enrollment 后，包内 worker 在 LSASS 中读取 machine-scope DPAPI 记录时以 `CryptUnprotectData: RPC_S_SERVER_UNAVAILABLE (1722)` 停止；两个转换 helper 仍已确认可用，尚未调用 `GetAuthDataForUser`。由于本实验只需要账户身份而不需要 iPhone 公钥，自动路径已改为仅复制 `SpAcceptCredentials.AccountName`、解析其 SID/SAM 名并执行转换，完全绕过 enrollment/DPAPI；primary 和 supplemental credentials 继续不读取。该修订尚待重新构建、部署、重启和登录验证。
- 2026-09-29：绕过 DPAPI 后，LSASS 内的 `LookupAccountNameW` 同样以 RPC 1722 失败，说明不能在该回调路径通过普通账户/SID 名称解析 API 回入 LSA。自动 probe 已进一步改为只复制 `SECPKG_PRIMARY_CRED` 的非敏感 `UserSid`、`DownlevelName` 和 `DomainName`，明确不读取 `Password`、`OldPassword` 或 supplemental credentials，并把 SAM 名直接交给 `GetAuthDataForUser`。为避免成功转换后的报告阶段再次触发同类递归，包内报告只输出原始 SID 和 privilege LUID，不在 LSASS 内解析显示名称。该修订尚待重新构建、部署、重启和登录验证。
- 2026-09-29：直接身份字段版本首次运行捕获到 `<COMPUTER>$` / `S-1-5-18`，并以 `GetAuthDataForUser: STATUS_INVALID_SERVER_STATE (0xC00000DC)` 停止；这证明 helper 已被调用，但样本是启动阶段机器/System 身份，不能回答用户 token 问题。自动回调现会在占用 one-shot 之前忽略 LocalSystem、LocalService、NetworkService SID 以及名称以 `$` 结尾的机器账户，使后续真实 `Interactive`/`Unlock` 用户通知成为测试对象。该筛选修订尚待重新构建和 VM 重跑。
- 2026-09-30：上述筛选后的 VM 报告捕获到实际 Microsoft Account 登录的云身份 `S-1-11-96-...`，`GetAuthDataForUser` 对该 email/flat-name 输入返回 `STATUS_NO_SUCH_USER (0xC0000064)`。同一登录会话的 `whoami /user` 和 `Get-LocalUser` 已确认桌面 token 实际使用 `<COMPUTER>\\<USER>` / `S-1-5-21-...`，且该本机 SAM 账户的 `PrincipalSource=MicrosoftAccount`。因此 MSA 通知本身不能直接作为 SAM 输入，但 backing SAM 账户确实存在；尚待验证 `SpAcceptCredentials` 是否还会通知该 SAM identity。自动回调现只在 `S-1-5-21-...` 通知到达时占用 one-shot；若重跑只停留在等待状态，则下一实验改为显式验证 `SecNameAlternateId` 或使用安装时固定的 SAM identity，不把猜测的 prefix 用于生产。
- 2026-09-30：仅接受 `S-1-5-21` 通知的版本在完整重装、重启和 MSA 登录后始终停留于 `stage=SpInitialize / waitingFor=SpAcceptCredentials`，因此已否决“同次登录还会通知 backing SAM identity”的假设。下一版不再从 credential notification 推导目标：VM 安装器把执行安装的已验证 `S-1-5-21` 用户名/SID 写入仅 SYSTEM 和 Administrators 可访问的 `target-account.ini`；任一合格的 `Interactive`/`Unlock` 通知只充当登录完成触发器，worker 固定调用 `GetAuthDataForUser(<COMPUTER>\\<USER>, SecNameSamCompatible)`，并强制核对转换 token 的用户 SID。该版本已通过完整 `make build-release`，尚待 VM 安装运行；`SecNameAlternateId` 保留为固定 SAM 输入也失败后的独立实验。
- 2026-09-29：为减少 VM 快照恢复后的重复人工部署，新增 `windows/LsaConvertProbe/Install-VmProbe.cmd` 与 `Install-VmProbe.ps1`。安装器不调用 CMake、Visual Studio、编译器或 `make`，只接受开发机预编译的诊断 DLL；显式输入 `INSTALL` 后保存原始 `Security Packages`，通过 SYSTEM 启动任务跨两次重启完成安全替换、哈希验证、注册和 LSASS 映射检查，再由目标用户登录任务等待并打开报告。它拒绝自行关闭 LSA protection，后台错误会持久化而非静默跳过。该自动化尚未在 VM 实际执行。

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

## MSA native credential branch (Gate A/B)

- [x] Replace the Credential Provider's custom LSA serialization with a manual
  MSA password tile that uses the enumerated qualified user name and Windows
  Negotiate online-identity packing in the LogonUI process.
- [x] Record the user SID, primary SID, qualified user name, user name,
  provider ID, and active console session/account SID without recording the password.
- [x] Remove `WTSQueryUserToken` from the Credential Provider after the VM
  returned 1314 (`SeTcbPrivilege` not held). Resolve the active session account
  SID from WTS session metadata and fail closed if it cannot be resolved.
- [x] In the VM, confirm `userSid`, `primarySid`, and `consoleSid` agree and
  `whoami /user` returns the same SID after manual MSA password unlock.
- [ ] If iPhone enrollment is present in the same VM, cross-check its account
  SID separately; Gate B does not require enrollment.
- [x] Make the VM Components Wizard avoid custom LSA registration; a
  pre-existing custom LSA installation blocks this installer.
- [x] Build on the development machine, deploy to a disposable VM, and verify
  manual MSA password unlock of the existing console session. Native PIN
  remains available; a wrong password is rejected.
- [x] Confirm the existing desktop SID and session ID are unchanged after
  manual unlock; a `whoami /all` comparison with the PIN-unlocked desktop
  produced no differences.
- [ ] Run the read-only desktop/linked-token probe once for a strict native
  token baseline; the same-session `whoami /all` check does not replace it.
- [x] Build and VM-validate the saved-credential normal path: the LocalSystem
  service and Credential Provider were installed, identity capture and manager
  Refresh worked repeatedly, and a fresh one-test authorization released the
  saved MSA password for manual submission without typing it at the tile.
  Windows unlocked the existing console SID and SessionId. The pipe client
  handles immediate overlapped completion and busy-instance retries; the
  service waits for a bounded full-reply acknowledgment before disconnecting
  and preserves an authorized nonce across snapshot refresh.
- [x] VM behavior: a successful saved-credential claim cannot be reused without
  reauthorization; a new grant works. A grant issued before a service restart
  cannot unlock afterward, whereas a new grant after that restart can use the
  persisted credential. Native PIN/password recovers after refusal. Normal
  wizard uninstall reported confirmed credential deletion; the former vault
  path was not found afterward. An administrator was denied vault-file access,
  and the directory ACL showed SYSTEM only. These are operator-reported VM
  observations; the generic claim-refused message does not identify the exact
  failed service check.
- [ ] Complete saved-credential negative and cleanup acceptance: inspect the
  on-disk DPAPI record from SYSTEM without exposing its contents; prove that a
  changed QualifiedUserName/ProviderID under the same SID, wrong session, and
  non-LogonUI caller cannot claim; test service-unavailable recovery and
  emergency wizard removal in disposable VM snapshots. Full Windows reboot
  first logon is outside this existing-session milestone and its refused claim
  does not substitute for these tests.
- [x] In source, add a separate local-only phone transport endpoint and move
  challenge issuance, signature verification and one-time grant authority into
  the LocalSystem saved-credential service. Bind the grant to enrolled/saved/
  console SID, existing locked session and lock generation; continue to release
  plaintext only to the manually submitted LogonUI tile. The old foreground
  UnlockService host is no longer in this credential path.
- [x] Build and physically validate iPhone approval -> manual saved-credential
  claim -> existing-session unlock without typing a password at the tile.
  The 2 Oct 2026 operator report also confirmed native password entry remained
  usable. This does not establish automatic unlock or every negative path.
- [ ] Complete phone-bridge negative tests: wrong signature, expiration/replay,
  enrolled/saved/console SID or session changes, and service restart before
  claim. Verify each rejects release while native PIN/password remains usable.
  The successful physical-machine run alone does not prove these conditions.
- [ ] Only after the manual phone path is validated, implement
  `CredentialsChanged()` and one-shot automatic submission.
- [ ] Validate wrong password, replay, wrong SID/session, non-LogonUI client,
  offline behavior, and service failure while retaining native PIN/password
  recovery.
