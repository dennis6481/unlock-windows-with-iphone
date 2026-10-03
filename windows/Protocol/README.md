<!-- Created by Rui MA on 26 Sep 2026 -->

# Windows protocol code

该目录只包含当前签名协议需要的 Windows 实现：

- `SigningPayload`：按照根目录 [Protocol.md](../../Protocol.md) 构造固定二进制签名载荷。
- `UnlockCrypto`：共享 CNG SHA-256、公钥小写十六进制指纹和 P-256 签名验证；登记与验签使用同一实现。

challenge 期限统一为 30 秒，批准领取期独立为 120 秒。共享加密及边界用例已补充但未执行，状态见 [验收记录](../Validation.md)。

JSON 只是传输外壳，不参与签名字节构造。代码不会退回软件密钥或替代校验路径。
