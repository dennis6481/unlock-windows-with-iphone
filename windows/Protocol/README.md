<!-- Created by Rui MA on 26 Sep 2026 -->

# Windows protocol code

该目录只包含当前签名协议需要的 Windows 实现：

- `SigningPayload`：按照根目录 `protocol/README.md` 构造固定二进制签名载荷。
- `UnlockCrypto`：将 CryptoKit 的 SEC1 P-256 公钥导入 CNG，以 SHA-256 验证固定宽度 `r || s` 签名。

JSON 只是传输外壳，不参与签名字节构造。代码不会退回软件密钥或替代校验路径。
