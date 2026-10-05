<!-- Created by Rui MA on 01 Oct 2026 -->

# Saved credential service

LocalSystem 服务是 Windows 手机认证和密码领取的权威。保存记录绑定 SID、系统 QualifiedUserName 和 ProviderID；CP 每次枚举重新核对 PrimarySid＝SID，领取身份必须精确匹配，不因 SID 相同而释放旧在线身份的密码。

密码以 LocalSystem user-scope DPAPI 保存，使用 CRYPTPROTECT_UI_FORBIDDEN，不使用 machine scope。文件及目录仅 SYSTEM；管理员最终取得 SYSTEM 不在抵御范围。可控明文尽早清零，打包只在 LogonUI 内 CP 执行，不在 Session 0 预打包。

## 请求与领取

1. LogonUI 的 unlockEligibility 核对已有物理控制台 token、SID、session 和明确 locked 状态；首次登录不合格。
2. beginPhoneAuthentication 仅由合格 LogonUI 发起；保存身份、登记 SID 及控制台一致才签发。服务和验签核心共用 30 秒 challenge 期限。
3. phone pipe 仅接受 peekPhoneAuthentication、takePhoneChallenge、reportPhoneFailure 和 submitPhoneAssertion，不开放密码操作或新请求签发。host 双订阅有效并收到绑定本次连接／请求的手机就绪回执后，单次领取 challenge。
4. 服务验签、防重放和登记核对通过，形成独立 120 秒内存 grant；服务重启、解锁／会话变化使旧请求及批准失效。
5. takeAutoSubmitOffer 只向合格 LogonUI 发出一次 nonce／期限，不解密。claimCredential 首次合格领取先不可逆消费，再解密；打包失败、错误密码或 CP 重建不恢复批准。

唯一批准来源是手机 assertion；Manager 不提供测试授权，Grant 不再区分非手机类别。登记一致性检查始终执行。

## IPC 与状态

saved-credential pipe 按操作核对管理员、当前控制台和 LogonUI；phone pipe 限当前控制台用户。连接建立持有进程句柄，核对映像、SYSTEM、session；实际管道 token 校验和 impersonation 后恢复 LocalSystem 再执行 DPAPI 的边界不变。

内部 IPC v2 拒绝旧包，所有组件使用同一构建。同步／带超时传输共用报头构造与校验；服务映像名来自共享组件清单。

AuthenticationStatus 提供 requestID、阶段、原因和单调时钟 deadline。阶段为 idle／waitingPhone／awaitingAssertion／approved／failed／consumed；等待、距离失败、断连、超时和真实 session 变化分开。无关 session 事件不使目标请求失效；每次操作仍重新核对实际控制台。

`peekPhoneAuthentication = 17` 是 phone-only 空请求，返回上述状态，不返回 challenge、不修改投递标记或进入 awaitingAssertion；其他端点拒绝。准备消息与回执不会延长服务原有 30 秒期限。新增投递状态回归用例用于检查 peek 不消费、take 只消费一次；本轮未构建或运行用例，两端匹配版本的实测待验收。

reportPhoneFailure 保留 `36 字节 requestID + 1 字节原因`，原因 1–6 为 RSSI 不足、自动批准关闭、新读数失败、订阅／连接丢失、投递失败、签名失败。迟到结果不覆盖新请求。日志不记录密码、nonce、密钥或断言正文。

## 密码管理

从托盘 **Manage saved password…** 打开，同一 `UnlockWithIPhone.exe --saved-password` 角色请求一次 UAC，仅在已解锁控制台操作。不部署独立密码管理 EXE，不创建开始菜单项。目标是控制台用户，不是提权管理员。

首次设置／更新：先锁屏，再以原生 PIN／密码返回桌面；Refresh 核对账户，Save password… 或 Update saved password…。服务身份快照保留五分钟；失效时需重复原生锁屏／解锁，不读取诊断文件或拼接 online identity。

Remove saved password… 确认后清除本机副本；Close 只关闭该操作实例，不退出普通用户托盘。SID、QualifiedUserName、ProviderID 和错误码在 Technical details。工具不修改 Windows／Microsoft Account 密码。

## 删除与验收

卸载前 clearForRemoval 必须由服务确认密码、grant、snapshot 和 challenge 已清除，安装器才继续。没有绕过清除失败的应急成功路径。

已确认成果与未验证的身份变化、错误调用方、自动提交失败及本轮清理回归统一见 [Windows 验收记录](../Validation.md)。
