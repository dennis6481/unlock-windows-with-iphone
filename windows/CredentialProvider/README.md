<!-- Created by Rui MA on 27 Sep 2026 -->

# Credential Provider

`unlock_credential_provider.dll` 为 Windows 10+ 的 `CPUS_LOGON` 和 `CPUS_UNLOCK_WORKSTATION` 提供一个 **Unlock with iPhone** 磁贴。

当前磁贴只有图标、标题和 **Unlock** 按钮。它不接受手输密码，也没有“使用保存凭据”复选框或绕过手机批准的测试模式。

获得手机批准后的自动提交时 Provider：

1. 从 `ICredentialProviderSetUserArray` 获取 Windows 提供的 SID、Primary SID、QualifiedUserName 和 provider ID，并在当前 console 身份匹配时同步身份快照，供 Manager 的 Refresh 使用。
2. 提交时再次核对当前 active console session 与 SID。
3. 通过只允许 LogonUI 客户端的 named pipe 捕获本次身份 nonce。
4. 领取服务中尚未消费且未过期的手机授权；领取动作会立即消费授权。
5. 使用返回的保存密码构造 `CRED_PACK_PROTECTED_CREDENTIALS | CRED_PACK_ID_PROVIDER_CREDENTIALS` 缓冲区，并交给 Windows 原生 Negotiate 包。

如果授权不存在、已消费、已过期，账户或 session 不匹配，或服务拒绝调用，Provider 不返回凭据，并显示错误。Windows 随后的密码校验失败不会恢复已经领取的授权。

安装、更新和卸载只由 `unlock_windows_components_wizard.exe` 负责。不要手工注册 DLL，也不要恢复已经删除的 PowerShell 安装脚本。

该实现先完成了物理 Windows 机器已有 Microsoft Account 会话的手动解锁。2026-10-02 用户确认“手机批准 + 不点击 Windows 磁贴 + 自动解锁”通过，并确认无新批准时保持锁定、重新批准后再次自动解锁、原生 PIN/密码可用。2026-10-03 手动箭头已改为发起认证，新入口及完整负面路径尚未验收。

## 当前箭头行为（2026-10-03，待验收）

手动点击 **Unlock** 提交箭头调用 `beginPhoneAuthentication`，返回不含凭据的等待状态，不同步等待蓝牙或领取密码。工作线程同时查询当前请求失败信息，经原有消息窗口在 COM 所在线程更新磁贴提示。请求 ID 防止旧失败说明覆盖新请求，通信失败或服务确认的 30 秒期限到期显示明确错误。有效手机批准仍触发现有一次自动提交；该分支不会再发起 challenge。仅枚举/选择磁贴不发起认证。

2026-10-03 用户观察到等待提示一直停留，取消后才显示 `iPhone is not connected with both notifications subscribed.`。该说明由服务端记录，表示 GATT host 未找到唯一且同时订阅 challenge/result 通知的客户端，尚未进行手机 RSSI 判断。此前成功发起请求同时通过磁贴字段和 `GetSerialization` 的 optional status text 显示等待，但异步失败只更新磁贴字段。现成功发起时 optional status text 保持空，只用磁贴字段更新等待、失败及服务确认的超时，避免静态提交提示遮盖异步结果。此 UI 原因与现象吻合，修改仅静态检查，尚未实机验证；不改变有效批准后的自动提交分支。

## 自动提交（2026-10-02，实体机正常路径通过）

Provider 在 `Advise` 和有效用户身份均就绪后启动工作线程，每 500 ms 通过现有受限管道申请 `takeAutoSubmitOffer`。该操作只返回批准 nonce 和有效期，不解密或领取密码，也不使用桌面 Manager 的 `status` 操作。

服务对同一批准只发出一次 offer，包括 CP 重建或管道回复丢失的情况。CP 的工作线程不调用 COM 事件接口；它向 `Advise` 所在线程的 message-only window 投递消息，由该线程调用 `CredentialsChanged()`。`UnAdvise` 或身份变化会停止并回收工作线程；同一身份的重新枚举保留尚待提交的 offer。

`GetCredentialCount()` 对尚未过期的 offer 只返回一次默认磁贴 0 和 `pbAutoLogonWithDefault=TRUE`。LogonUI 随后调用 `GetSerialization()`，Provider 将当次 capture 返回的 nonce 与 offer 比较，再走已验证的领取和 Negotiate 打包路径。服务每次手机批准生成新的 nonce。领取后打包或密码认证失败不会恢复 grant，也不会重新发出 offer；重试需要新的手机批准。自动提交通知无法交付时保留错误，不用手动箭头绕过本次自动提交；有效授权未消费期间重复发起被拒绝。

自动提交正常路径已获用户实测确认，不代表 iPhone 或 GATT 已支持后台运行。目标仅为已有会话的锁屏解锁，重启后首次登录明确不支持手机登录。已有会话、原生 PIN/密码入口及服务端身份、session、锁屏校验继续适用；CP 重建、重复枚举和失败后的自动行为仍待专项验收。

### 首次登录边界与回归

2026-10-02 用户实测确认：重启后的首次登录界面不显示 **Unlock with iPhone** 自定义磁贴，使用原生密码登录 Windows。这符合用户要求，记录为首次登录边界通过，不将手机首次登录列为后续功能。此记录仅描述当前观察，不声称所有账户、策略和登录场景均已覆盖。

后续后台组件或安装器变更时按以下步骤回归：

1. 重启 Windows，在尚未建立用户会话时确认不显示自定义磁贴；手机批准不得用来完成首次登录。
2. 使用 Windows 原生登录方式进入桌面。本次已观察到原生密码可用，不据此推断首次登录时所有 PIN 等选项均可用。
3. 启动当前前台 GATT host，Win+L，再用前台 iPhone App 批准；已有会话应自动解锁。

首次登录时磁贴缺席是预期结果；已有会话再次锁屏后仍无法手机解锁才属于本链路的回归问题。

## 构建后的实体机验收

2026-10-02 首轮自动提交未触发，DebugView 显示服务 `saved credential request read failed` 和 CP `approval query failed: 0x800700e9`。静态检查确认新操作 `takeAutoSubmitOffer=12` 被两端仍限定到 11 的包解析校验拒绝，服务直接断开连接；并非该请求进入身份授权处理后遭拒绝。两处解析校验已统一为显式合法操作列表，并补充真实管道包读取回归用例。随后用户确认自动解锁及上述三项回归通过；自动化测试执行结果未另行确认。

部署同一新构建的服务和 CP DLL。已安装机器可使用 Components Wizard 的 **Update**，重启续办后保留保存密码和公钥；正常更新已由用户确认通过，详见 [更新步骤](../README.md#安装更新与卸载)。不要直接覆盖已经被 LogonUI 加载的 DLL。只有选择正常卸载才会清除保存密码，之后重装需通过 Manager 重新保存。

以下命令均在仓库根目录执行。Windows 已正常登录、密码已保存、公钥已登记后，以当前控制台普通用户启动前台 transport：

```powershell
& '.\windows\build\unlock_gatt_host.exe'
```

1. Win+L，确认默认选中 **Unlock with iPhone**，按一次 Enter（或点击箭头）发起。iPhone 自动批准开关开启；本轮分别记录前台和后台结果。仅选择磁贴不会发起请求。
2. 手机显示 `unlock_approved` 后，观察 Windows 是否自动解锁；记录是否需要触碰屏幕或先选择磁贴。若必须先选择，不能记为无操作自动解锁通过。
3. 核对恢复的是原有账户与 session。用根目录终端运行 `whoami /user` 和 `(Get-Process -Id $PID).SessionId`，与锁屏前比较。
4. 再锁屏，不按 Enter；应保持锁定且不自动提交。按 Enter 发出新请求后才可获得新批准并自动提交。
5. 自动认证失败后不得连续重试同一批准；不要为了本轮验收反复输入错误密码。使用原生 PIN/密码恢复。
6. 验证服务重启使旧批准失效，需要重新手机批准；完整身份变化和错误调用方测试继续单列。

如自动提交未发生，先记录手机和 GATT 的结果，确认本轮已按 Enter 发起请求；记录服务阶段及失败原因，失败后仅发起一份新请求，不能手动绕过 offer 消费。CP 使用 `OutputDebugString` 输出非秘密阶段：`phone approval triggered CredentialsChanged`、`automatic submission offered once`，以及带 HRESULT 的通知或 IPC 错误；不会记录密码或 nonce。

## 参考资料

- [CredentialsChanged](https://learn.microsoft.com/en-us/windows/win32/api/credentialprovider/nf-credentialprovider-icredentialproviderevents-credentialschanged)
- [GetCredentialCount](https://learn.microsoft.com/en-us/windows/win32/api/credentialprovider/nf-credentialprovider-icredentialprovider-getcredentialcount)
- [Message-only windows](https://learn.microsoft.com/en-us/windows/win32/winmsg/window-features#message-only-windows)

## 当前枚举与请求合同（2026-10-03，待验收）

首次登录／注销后无已有控制台用户 token 时返回零磁贴；唯一候选账户不再构成回退依据。仅当系统枚举身份匹配当前物理控制台、服务确认已有用户且明确锁定时返回磁贴。正常候选默认索引为 0、autoLogon=FALSE；有效一次性 offer 才设置 autoLogon=TRUE。选中手机磁贴后一次 Enter 发起，等待期间重复 Enter 不创建第二份请求。箭头不可编辑，不设置 CPFIS_FOCUSED、不添加伪输入框或键盘钩子。此默认选择／Enter 行为须实测，不能保证跨 provider 抢占用户系统选择。

工作线程消费结构化 AuthenticationStatus，只对当前 requestID 更新提示；服务为唯一期限来源。相同 SID、QualifiedUserName、ProviderID 和 session 重新枚举时保留尚待提交 offer；身份变化清除。嵌入 72×72 AppTile.bmp 使用 iOS 标准 App Icon 派生图像，仍为 provider logo，不替换账户照片。无磁贴和嵌入图像用例已修改，未执行。
