# Unlock protocol v1

这是 iPhone 与 Windows 之间的认证层约定。它独立于 BLE；BLE 只负责传输完整的逻辑消息。实现 BLE 分片时，必须先重组出完整 JSON，再交给本协议层解析，不能对半个 JSON 做认证。

## 认证模型

首次配对时，Windows 保存 iPhone 的 P-256 公钥和指纹。正常认证时：

1. Windows 生成 32 字节密码学随机 `nonce`、随机 `requestID` 和短有效期 `issuedAtMilliseconds`。
2. Windows 把 `UnlockChallenge` 发给 iPhone。
3. iPhone 从 Secure Enclave 取出同一把私钥，对 canonical challenge 签名。
4. Windows 检查 `version`、`audience`、`requestID`、nonce 是否是当前未完成请求，并检查时间窗口和单次使用规则。
5. Windows 使用已登记公钥验证 DER 编码的 ECDSA P-256 签名，并拒绝 assertion 中的公钥指纹与已登记值不一致的情况。

认证成功只表示“持有这台已登记的 iPhone，并且该 iPhone 的 Keychain 在当前系统状态允许使用”。使用 `AfterFirstUnlockThisDeviceOnly` 时，这个状态可能在 iPhone 锁屏后仍然成立。

## Challenge JSON

`UnlockChallenge` 使用 JSON 编码，字段按字典序排序，`Data` 使用 JSON 默认的 Base64 编码：

```json
{
  "audience": "windows-unlock",
  "issuedAtMilliseconds": 0,
  "nonce": "<base64: 32 bytes>",
  "requestID": "<UUID>",
  "version": 1
}
```

实际签名输入为：

```text
ASCII("unlock-windows-with-iphone/v1") || 0x00 || UTF8(canonical challenge JSON)
```

这样可以避免把本项目的签名误用于另一个协议上下文。`ios/Core/UnlockProtocol.swift` 是当前编码的规范实现。

## Assertion JSON

```json
{
  "keyID": "<lowercase hex SHA-256 of publicKeyRawRepresentation>",
  "publicKeyRawRepresentation": "<base64: P-256 raw public key>",
  "requestID": "<same UUID as challenge>",
  "signatureDERRepresentation": "<base64: DER ECDSA signature>",
  "version": 1
}
```

Windows 不应仅信任 assertion 里附带的公钥。附带公钥用于配对/诊断；正常解锁必须将 `keyID` 和公钥与 Windows 本地登记的值逐字匹配。

## BLE 传输规划

推荐 Windows 作为 GATT Server、iPhone 作为 CoreBluetooth Central。建议先定义一个自有 128-bit service 和两个 characteristic：

- `challenge`：Windows → iPhone，Write/Write Without Response。
- `assertion`：iPhone → Windows，Notify/Read。

UUID、MTU 分片、状态恢复、配对授权和超时属于传输层，不改变上面的签名字节。尚未实现这些 characteristic 时，不应在 UI 中报告“Windows 已认证”。

## 必须测试的拒绝条件

- nonce 重复或已消费。
- `requestID` 不匹配当前请求。
- audience/version 不匹配。
- 签名无效、DER 解析失败或公钥指纹不匹配。
- challenge 超时。
- iPhone 重启后尚未第一次解锁，Keychain 返回不可访问。
- BLE 断开、消息截断或 JSON 解析失败。

所有拒绝都必须是显式错误；不能因为认证失败而自动尝试另一个身份或静默切换到软件密钥。
