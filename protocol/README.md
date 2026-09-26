<!-- Modified by Rui MA on 26 Sep 2026 -->

# Unlock protocol v1

这是 iPhone 与 Windows 之间的认证层约定。它独立于 BLE；BLE 只负责传输完整的逻辑消息。实现 BLE 分片时，必须先重组出完整 JSON，再交给本协议层解析，不能对半个 JSON 做认证。

## 认证模型

首次配对时，Windows 保存 iPhone 的 P-256 公钥和指纹。正常认证时：

1. Windows 生成 32 字节密码学随机 `nonce`、随机 `requestID` 和短有效期 `issuedAtMilliseconds`。
2. Windows 把 `UnlockChallenge` 发给 iPhone。
3. iPhone 从 Secure Enclave 取出同一把私钥，对固定二进制 challenge 载荷签名。
4. Windows 检查 `version`、`audience`、`requestID`、nonce 是否是当前未完成请求，并检查时间窗口和单次使用规则。
5. Windows 使用已登记公钥验证 64 字节 raw `r || s` ECDSA P-256 签名，并拒绝 assertion 中的公钥指纹与已登记值不一致的情况。

认证成功只表示“持有这台已登记的 iPhone，并且该 iPhone 的 Keychain 在当前系统状态允许使用”。使用 `AfterFirstUnlockThisDeviceOnly` 时，这个状态可能在 iPhone 锁屏后仍然成立。

## Challenge JSON

`UnlockChallenge` 使用 JSON 作为 BLE 传输外壳，`Data` 使用 JSON 默认的 Base64 编码。字段顺序不参与认证；Windows 解码后必须按下面的固定二进制规则重建签名载荷：

```json
{
  "audience": "windows-unlock",
  "issuedAtMilliseconds": 0,
  "nonce": "<base64: 32 bytes>",
  "requestID": "<UUID>",
  "version": 1
}
```

实际签名输入不是 JSON，而是下面的固定二进制结构：

```text
ASCII("unlock-windows-with-iphone/v1") || 0x00 ||
UInt32BE(version) ||
requestID[16 bytes, RFC 4122 order] ||
nonce[32 bytes] ||
Int64BE(issuedAtMilliseconds) ||
UInt16BE(audienceUTF8ByteLength) ||
audienceUTF8
```

签名算法是 ECDSA P-256。iOS CryptoKit 对上述消息计算 SHA-256 后签名；Windows CNG 验证前必须对同一消息计算 SHA-256。这样可以避免把本项目的签名误用于另一个协议上下文，也避免不同 JSON 库的转义/字段顺序差异。`ios/Core/UnlockProtocol.swift` 是当前编码的规范实现。

## Assertion JSON

```json
{
  "keyID": "<lowercase hex SHA-256 of publicKeyRawRepresentation>",
  "publicKeyRawRepresentation": "<base64: 65-byte uncompressed P-256 X9.63 key, 0x04 || X || Y>",
  "requestID": "<same UUID as challenge>",
  "signatureRawRepresentation": "<base64: 64-byte r||s ECDSA signature>",
  "version": 1
}
```

Windows 不应仅信任 assertion 里附带的公钥。附带公钥用于配对/诊断；正常解锁必须将 `keyID` 和公钥与 Windows 本地登记的值逐字匹配。

## BLE 传输规划

推荐 Windows 作为 GATT Server、iPhone 作为 CoreBluetooth Central。建议先定义一个自有 128-bit service 和四个 characteristic：

- `request`：iPhone → Windows，Write With Response；写入固定操作码 `0x01` 请求一次 challenge。
- `challenge`：Windows → iPhone，Notify/Read；Windows 生成 challenge 后通知已订阅的 iPhone。
- `assertion`：iPhone → Windows，Write With Response；iPhone 写入 assertion JSON。
- `result`：Windows → iPhone，Notify/Read；可选的明确成功/失败回执，不参与 Windows 解锁决定。

UUID、MTU 分片、状态恢复、配对授权和超时属于传输层，不改变上面的签名字节。尚未实现这些 characteristic 时，不应在 UI 中报告“Windows 已认证”。

## 必须测试的拒绝条件

- nonce 重复或已消费。
- `requestID` 不匹配当前请求。
- audience/version 不匹配。
- 签名长度/格式无效、签名验证失败或公钥指纹不匹配。
- challenge 超时。
- iPhone 重启后尚未第一次解锁，Keychain 返回不可访问。
- BLE 断开、消息截断或 JSON 解析失败。

所有拒绝都必须是显式错误；不能因为认证失败而自动尝试另一个身份或静默切换到软件密钥。
