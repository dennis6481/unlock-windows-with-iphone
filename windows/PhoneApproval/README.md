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

GATT 仅负责运输，最终授权和保存凭据 grant 都由 LocalSystem 服务管理。
