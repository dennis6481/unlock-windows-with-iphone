<!-- Created by Rui MA on 26 Sep 2026 -->

# GATT host

`unlock_gatt_host` 是当前 Windows BLE transport。它仍是前台进程，不保存公钥、不保存密码，也不自行验证签名。

它暴露项目定义的 service 和四个 characteristic：request、challenge、assertion、result。

- request 只接受一个字节 `0x01`，请求 LocalSystem 服务签发 challenge。
- challenge 将服务返回的 challenge JSON 通知给 iPhone。
- assertion 将 iPhone 的 assertion 原样转交服务。
- result 返回服务的认证结果，例如 `unlock_approved`、`not_ready` 或具体签名拒绝原因。

公钥登记不经过 GATT。请在已解锁 Windows 控制台上以管理员身份运行 `unlock_pairing_tool`，人工核对指纹后登记。

## 当前运行方式

```powershell
cd windows
make run-gatt
```

该目标会触发构建，仅在用户明确要求构建时运行。已有可执行文件时可直接启动 `unlock_gatt_host.exe`。

启动 host 后锁定 Windows，再从 iPhone 发起认证。出现 `unlock_approved` 后仍需在 120 秒内手动点击 Credential Provider 的 **Unlock** 按钮。

下一步是在锁屏、注销、重启、蓝牙断线和 package identity 条件下验证后台实现；验证成功后应替换并删除此前台启动路径，不长期维护两套 transport。
