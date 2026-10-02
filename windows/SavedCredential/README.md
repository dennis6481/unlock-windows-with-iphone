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

`beginPhoneAuthentication`（操作 9）仅接受锁屏控制台的合格 LogonUI，以完整 Identity 发起；与保存身份/登记一致才签发，回复 36 字节 ASCII requestID。同一时刻只保留一个请求，期限五秒。phone-only 的 `takePhoneChallenge`（13）请求为空，回复为空表示没有待投递请求，否则回复 `36 字节 requestID + challenge JSON`，服务在回复前标记已领取，不重复投递。`reportPhoneFailure`（14）载荷为 `36 字节 requestID + 1 字节原因`：1 信号不足、2 自动批准关闭、3 新 RSSI 不可用、4 没有有效连接、5 通知失败、6 手机拒绝/签名失败。有效拒绝结束本次请求，迟到请求 ID 不影响下一次认证。

`phoneAuthenticationStatus`（15）仅允许 LogonUI 提交完整 Identity，回复为空或 `36 字节 requestID + ASCII 失败说明`。CP 将说明关联到当前请求；成功批准沿用 `takeAutoSubmitOffer` 和 `claimCredential`。超时、解锁、重新锁屏、会话变化和服务重启均不能继续旧请求；未领取的旧授权不能用于新锁屏周期。无构建或运行验证。

## Manager GUI

`unlock_saved_credential_manager.exe` 是正式设置界面完成前必须保留的临时管理工具。它只在提升权限、已解锁的物理控制台使用，并保留四个功能：

- **Refresh**：读取最新 LogonUI 身份快照和保存状态；
- **Set credential**：首次保存当前身份的实际 Microsoft Account 密码；
- **Update stored**：替换已有保存密码；
- **Clear stored**：删除保存记录。

Manager 不再创建解锁授权。唯一授权来源是通过 iPhone 验证的 assertion。

典型设置顺序：先锁定并用原生 PIN/密码解锁一次，让服务获得当前 LogonUI 身份快照；然后运行 Manager，Refresh 后设置或更新密码。正式设置 UI 完成前不要删除该 GUI。

## 删除语义

Components Wizard 卸载前调用 `clearForRemoval`。只有服务确认 vault、grant、snapshot 和 challenge 已清除后，Wizard 才继续注销服务与 Credential Provider。没有忽略此失败的 emergency removal。
