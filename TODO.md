<!-- Created by Rui MA on 27 Sep 2026 -->

# 自动解锁认证模式 TODO

本项目只采用“自动解锁认证模式”：完成首次登记后，iPhone 在后台自动发现已登记的 Windows 电脑，自动建立 BLE 连接、完成 challenge 签名并触发解锁流程。

运行期间不使用 NFC、Face ID、手动确认或 Windows 通知确认。首次登记仍必须保留 Windows 指纹确认，避免把未知公钥写入本机。

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
- [x] 实现只用于 SDK/COM smoke test 的 `CPUS_UNLOCK_WORKSTATION` Credential Provider shell（不注册、不返回登录凭据）
- [x] 对自动解锁批准加入短冷却和一次性 challenge 消费，抑制 BLE 重复发现造成的连续批准
- [x] UnlockService named-pipe IPC
- [x] Windows CMake/Makefile 构建和四个 CTest

## 借鉴成熟方案的边界

已实现的协议、BLE 传输、Secure Enclave 签名、Windows CNG 验签、DPAPI 登记和首次指纹确认暂时冻结，不直接替换为参考项目的实现。

- [x] 参考 UnTouchID 的分层思路：后台常驻组件、一次性 challenge、短期有效的配对凭据、重放保护、连接重试和审计日志
- [x] 参考 EIDAuthentication 的 Windows 边界：Credential Provider 负责锁屏交互，LSA/受保护服务负责认证结果和 SID 映射，安装/卸载/回滚必须独立设计
- [ ] 不直接复制参考项目代码；EIDAuthentication 使用 GPL-3.0，后续若需要复用代码必须先单独处理许可证问题
- [ ] 当前 Windows 优先实现认证决策信号 `unlock_approved`，不提前接入实际登录 Token 或解锁 API

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
- [ ] 保留当前 named-pipe 用户/权限校验，并重新验证 Session 0 通信
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

- [ ] 设计 Credential Provider 与 UnlockService/LSA 的 IPC 边界
- [x] 定义 Credential Provider 与 LSA 共享的 `UnlockLogonBuffer` 输入边界（仅 codec，不注册 DLL）
- [x] 增加仅供测试的 Credential Provider serialization adapter，验证已批准字段能生成 `CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION`
- [ ] 让 Credential Provider 在收到受保护的短期批准后提交 `UnlockLogonBuffer`
- [ ] 让认证结果只映射到登记记录中的 Windows SID
- [ ] 研究并实现不保存 Windows 密码的 LSA Authentication Package
- [ ] 验证认证包返回的登录 Token 和锁屏解锁流程
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

## 明确不采用

- [ ] NFC 贴近确认
- [ ] UWB 距离测量（当前电脑和测试环境没有 UWB 硬件）
- [ ] 运行期间 Face ID 或人工确认
- [ ] 仅依靠 RSSI、蓝牙连接状态或传统蓝牙配对作为认证
- [ ] 在配置文件中保存 Windows 密码或 PIN
