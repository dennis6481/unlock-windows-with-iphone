<!-- Created by Rui MA on 27 Sep 2026 -->

# Credential Provider

**Unlock with iPhone®** 仅在已有、明确锁定的物理控制台用户会话中显示。Windows 10+ 的 CPUS_LOGON 也可能用于解锁，不按场景枚举值单独排除。首次登录、注销后登录、其他账户和远程会话无手机磁贴；原生 PIN／密码保留。

## 枚举与发起

CP 从系统 ICredentialProviderUser 取得 SID、PrimarySid、原样 QualifiedUserName 和 ProviderID，核对控制台身份，并通过服务 unlockEligibility 确认已有锁定会话；没有单候选回退，不自行拼在线账户名。

磁贴只有 App 图标、标题及 Unlock 按钮，不接受手输密码或测试授权。正常候选默认索引 0、autoLogon=FALSE；Enter／箭头发起 beginPhoneAuthentication，选中磁贴或刚锁屏不创建请求。默认选择受 LogonUI 控制，不设置不可编辑按钮的 CPFIS_FOCUSED 或添加假输入框。

手动发起返回无凭据的等待状态，不同步阻塞 BLE；工作线程查询服务结构化状态，按 requestID 关联并在 COM 所在线程更新提示。30 秒期限由服务决定，不使用独立认证计时器。

## 自动提交

批准就绪时工作线程取得一次 takeAutoSubmitOffer，消息窗口在 Advise 线程调用 CredentialsChanged。重新枚举后 GetCredentialCount 仅一次设置 autoLogon=TRUE；GetSerialization 核对当次 capture nonce 和 offer，再领取密码。

服务 claimCredential 先消费批准，再返回明文；CP 在 LogonUI 会话中调用 CRED_PACK_PROTECTED_CREDENTIALS | CRED_PACK_ID_PROVIDER_CREDENTIALS，并交原生 Negotiate。CP 不自行创建 token 或调用 LsaLogonUser。

相同 SID、QualifiedUserName、ProviderID 和 session 的重新枚举保留未提交 offer；身份变化／UnAdvise 回收工作线程。通知丢失、打包失败或 Windows 拒绝密码不能恢复授权或重新发 offer，重试需新手机批准。

## 展示与部署

等待手机、等待批准、手机过远、新距离读数失败、断连、自动批准关闭、超时、验签失败、真实会话变化和服务不可用使用英文用户文案。批准显示正在解锁，不提前宣称成功。

AppTile.bmp 是 iOS 标准 AppIcon 派生的 provider logo，不替换用户头像；字号和 ® 位置由 LogonUI 控制。桌面 DPI 配置不注入 CP。

通过 [setup.exe](../README.md#安装更新与卸载) 正常 Update 并重启，服务、CP 与工具须同一构建，不直接覆盖 LogonUI 已加载的 DLL。

## 构建后的实体机验收

按 [集中验收记录](../Validation.md#回归顺序) 回归首次登录边界、已有会话解锁、SID／session、一份批准只用一次、原生恢复和服务重启。正常路径基线不证明重建／通知丢失／失败路径通过。

调试阶段只输出阶段和 HRESULT，不记录密码或 nonce。若没有自动提交，先核对已发请求、双订阅、challenge 投递及服务阶段，不用手动领取绕过批准。

## 参考资料

- [CredentialsChanged](https://learn.microsoft.com/en-us/windows/win32/api/credentialprovider/nf-credentialprovider-icredentialproviderevents-credentialschanged)
- [GetCredentialCount](https://learn.microsoft.com/en-us/windows/win32/api/credentialprovider/nf-credentialprovider-icredentialprovider-getcredentialcount)
- [Message-only windows](https://learn.microsoft.com/en-us/windows/win32/winmsg/window-features#message-only-windows)
