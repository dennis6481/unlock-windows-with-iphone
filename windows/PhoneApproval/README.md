<!-- Created by Rui MA on 26 Sep 2026 -->

# Phone approval core and enrollment store

该目录只有保存凭据服务使用的批准核心与登记存储，没有独立 host。

PhoneApprovalCore 负责随机 challenge、当前 30 秒有效期、request ID／nonce／audience／重放、严格 assertion JSON、登记公钥和指纹核对、CNG P-256 验签以及已验证 SID 的一次性批准结果。服务核对控制台／保存身份后才形成可领取密码的 grant；内部验签结果不是第二套密码领取权限。

批准之间没有固定冷却期；快速再次锁屏时仍须签发新的 challenge 并获得新的有效签名。旧请求不能批准新请求，每个 challenge 及其批准仍只能使用一次。移除冷却后的专项用例已更新，仅静态检查，尚未构建、执行或实机验收。

EnrollmentStore 保存一个合法 P-256 公钥与目标 Windows SID。PairingTool 是唯一写入者，服务读取并在明确 reload 后刷新内存。记录路径为 `%ProgramData%\UnlockWindowsWithIPhone\enrollment.dat`，保留原 DPAPI machine scope、格式和 ACL。

保存使用受保护同目录临时文件，完整写入、刷新、提交前再核对并原子替换；失败保留原文件，不用原地覆盖回退。读取允许删除共享；旧读者完成旧文件读取。调用方合法曲线点验证保留，SHA-256 和小写十六进制指纹统一复用 [Protocol](../Protocol/README.md)。

所有历史验收、静态用例与待验收记录集中到 [Windows 验收记录](../Validation.md)，不以新增测试源码代表运行通过。
