<!-- Created by Rui MA on 26 Sep 2026 -->

# Phone approval core and enrollment store

该目录只包含保存凭据服务使用的手机批准核心与登记存储，没有独立 host。

`PhoneApprovalCore` 由 `unlock_saved_credential_service` 直接持有，负责：

- 随机 challenge 与有效期；
- request ID、nonce、audience 和重放检查；
- assertion JSON 的严格字段解析；
- 已登记 P-256 公钥指纹匹配；
- CNG P-256 签名验证；
- 已验证账户 SID 的一次性批准结果。

`EnrollmentStore` 在 `%ProgramData%\UnlockWindowsWithIPhone\enrollment.dat` 保存一个 65 字节未压缩 P-256 公钥和已验证 Windows SID。记录使用 DPAPI machine scope 保护，并限制文件 ACL。`unlock_pairing_tool` 是当前唯一写入者；保存凭据服务只读取并在明确 reload 后更新内存状态。

2026-10-02 登记保存已改为同目录随机命名、受保护 ACL 的临时文件，完整写入并刷新后再原子替换目标；写入、提交前检查或替换失败时保留原登记，清理本次临时文件失败会连同原错误明确报告。读取允许删除共享，已打开的读取者继续读取旧文件；不存在遇到共享冲突后退回原地写入的路径。保存、读取及指纹计算均通过 CNG 导入验证 P-256 公钥，不只检查长度和 `0x04` 前缀。保存接口的提交前回调供 PairingTool 在替换前核对取消、会话及旧记录。

已补充合法公钥读写、非法曲线点拒绝、提交前取消、目标文件拒绝替换时原密文不变，以及成功替换的回归用例。代码与用例尚未构建或执行，不将静态检查记为实测通过。

GATT 仅负责运输，最终授权和保存凭据 grant 都由 LocalSystem 服务管理。
