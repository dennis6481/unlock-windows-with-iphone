<!-- Created by Rui MA on 01 Oct 2026 -->

# Saved credential service

`unlock_saved_credential_service.exe` 是当前 Windows 解锁链的唯一长期状态所有者。它以 LocalSystem 运行并管理：

- 当前控制台账户身份快照；
- LocalSystem user-scope DPAPI 加密的 Microsoft Account 密码（不使用 machine scope）；
- 已登记 iPhone 公钥和账户 SID；
- challenge、防重放、签名验证；
- 120 秒、单次领取的手机批准。

## IPC 边界

服务使用两条 named pipe：

- phone pipe 只接受 `takePhoneChallenge`、`reportPhoneFailure` 和 `submitPhoneAssertion`，供 GATT transport 投递和完成已有请求使用；不能签发新请求；
- saved-credential pipe 接受身份、密码维护和领取操作，并对管理员、物理 console、锁屏状态与 LogonUI 调用方分别校验。

有效 assertion 必须同时满足登记公钥、登记 SID、保存凭据身份、active console session 和当前 challenge。成功后服务创建 120 秒 grant。`claimCredential` 在返回密码前先清除 grant，因此后续 Windows 密码校验失败也不会让同一批准再次使用。

自动提交增加 `takeAutoSubmitOffer`，仅允许当前锁屏 console 的合格 LogonUI 以完整身份申请。没有尚未发出的匹配批准时返回空成功回复；有匹配批准时在服务内先不可逆标记 offer 已发出，再返回 nonce 和 grant 到期时间，不返回密码。不论 CP 重建或通知丢失，同一批准都不会再次获得自动提交通知。密码的消费仍发生于 `claimCredential`，箭头已改为发起新认证，不能直接领取已有 grant。每次手机批准使用独立随机 nonce，延迟的自动提交不能领取另一份批准。2026-10-02 用户确认实体机自动解锁、无新批准不解锁、重新批准再次解锁及原生 PIN/密码回归通过；CP 重建、通知丢失和失败路径仍须专项验收。正常安装器 Update 也已确认通过，密码保管与公钥登记不走卸载清除路径。

## 箭头发起认证（2026-10-03，待验收）

`beginPhoneAuthentication`（操作 9）仅接受锁屏控制台的合格 LogonUI，以完整 Identity 发起；与保存身份/登记一致才签发，回复结构化 AuthenticationStatus（requestID、阶段、失败原因、服务单调时钟 deadline）。同一时刻只保留一个请求，整次认证期限 30 秒。phone-only 的 `takePhoneChallenge`（13）请求为空，回复结构化 PhoneChallengePayload（AuthenticationStatus 与可为空的 challenge JSON）；仅有可投递请求时 JSON 非空，服务在回复前标记已领取，不重复投递。`reportPhoneFailure`（14）载荷为 `36 字节 requestID + 1 字节原因`：1 信号不足、2 自动批准关闭、3 新 RSSI 不可用、4 没有有效连接、5 通知失败、6 手机拒绝/签名失败。有效拒绝结束本次请求，迟到请求 ID 不影响下一次认证。

`phoneAuthenticationStatus`（15）仅允许 LogonUI 提交完整 Identity，回复 IPC v2 的结构化 AuthenticationStatus；CP 将状态关联到当前请求，再映射为用户提示。成功批准沿用 `takeAutoSubmitOffer` 和 `claimCredential`。超时、解锁、重新锁屏、会话变化和服务重启均不能继续旧请求；未领取的旧授权不能用于新锁屏周期。

## Manager GUI

`unlock_saved_credential_manager.exe` 是当前凭据副本管理界面。通过托盘 **Manage saved password…** 或现有开始菜单入口启动，请求 UAC；仅在提升权限、已解锁的物理控制台使用。主区域显示目标账户及真实保存状态，按钮为：

- **Refresh**：读取最新 LogonUI 身份快照和保存状态；
- **Save password…**：首次保存当前身份的实际 Microsoft Account 密码；
- **Update saved password…**：替换已有保存密码；
- **Remove saved password…**：确认后删除保存记录，确认默认取消；
- **Close**：关闭窗口。

此工具不修改 Windows／Microsoft Account 密码。SID、QualifiedUserName、ProviderID 及 IPC 错误在 **Technical details** 展开查看，目标身份核验没有放宽；另一管理员完成 UAC 时，目标仍是实际控制台用户。快照失效会提示先锁屏、用原生 PIN／密码返回桌面，然后 Refresh，不把历史快照当作有效身份。

Manager 不再创建解锁授权。唯一授权来源是通过 iPhone 验证的 assertion。

典型设置顺序：先锁定并用原生 PIN/密码解锁一次，让服务获得当前 LogonUI 身份快照；从托盘打开管理窗口，Refresh 后核对账户，Save 或 Update。此 GUI 是现有维护入口，不应删除。

2026-10-03：改为原生主题对话框及 PerMonitorV2，技术详情默认折叠，正文约 10 pt、标题约 14 pt，支持对话框键盘导航。只静态检查，未构建或执行；DPI、跨管理员、移除及解锁回归见 [Windows UI 验收](../README.md#windows-ui-验收2026-10-03)。DPAPI 范围、保存格式、领取授权及清零策略不变。

## 删除语义

Components Wizard 卸载前调用 `clearForRemoval`。只有服务确认 vault、grant、snapshot 和 challenge 已清除后，Wizard 才继续注销服务与 Credential Provider。没有忽略此失败的 emergency removal。

## 结构化状态与已有会话资格（2026-10-03，待验收）

内部管道包版本为 2（管道名称未改）；旧版本包明确拒绝，不保留旧字符串状态兼容路径。全部 Windows 组件须来自同一构建。

- unlockEligibility（16）：仅 credential 端点合格 LogonUI 可调用；服务用 WTSQueryUserToken 核对已有控制台 token SID／session、锁定状态和已登记目标 SID；不返回密码或授权。
- AuthenticationStatus：版本、阶段、原因、requestID、GetTickCount64 deadline。阶段包括 idle、waitingPhone、awaitingAssertion、approved、failed、consumed。
- beginPhoneAuthentication：成功回复 AuthenticationStatus，服务限定请求总期限 30 秒。
- phoneAuthenticationStatus：回复 AuthenticationStatus，不再拼接 requestID 和自由文本。
- takePhoneChallenge：回复 PhoneChallengePayload（结构化状态与可为空的 JSON）。托盘只在唯一有效客户端且双通知订阅就绪后调用；非空 JSON 在服务内不可逆地标记已投递。
- 原有 reportPhoneFailure 原因 1–6 保留；认证超时与真实会话／锁定变化单列。无关 session 的通知不递增本次 console generation；每次操作仍核对实际 console。锁定通知本身不作失效事件，避免已在锁定状态发出的请求被延迟到达的锁定通知取消；目标会话解锁、注销或断开仍递增 generation，使旧请求和批准失效。

一次性 grant、领取前消费及 DPAPI 格式不变；阶段日志只记录代码、剩余时间和 session，不记录密码、nonce、密钥或断言。新增静态用例没有执行；首次登录、后台待机及会话变化仍需验收。
