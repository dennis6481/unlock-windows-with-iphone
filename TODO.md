<!-- Created by Rui MA on 27 Sep 2026 -->

# TODO

## Windows 主线

- [ ] 把 `unlock_gatt_host` 封装成可持续运行的后台组件，并在锁屏、注销、重启和蓝牙断线场景验证生命周期。
- [ ] 验证后台组件后删除前台 host 启动路径，不长期并存两套 GATT 实现。
- [ ] 为已有有效 120 秒授权时的重复 challenge 请求定义明确结果，避免 iPhone 只看到通用 `not_ready`。
- [ ] 设计并验证 Credential Provider 自动提交；在验证前保留当前手动 **Unlock** 按钮。
- [ ] 验收错误签名、过期、重放、账户切换、console session 切换、非 LogonUI 调用者和服务重启。
- [ ] 完成生产签名、安装包、升级与卸载验收。

## 当前保留的临时工具

- [ ] 正式设置 UI 完成后，再删除 `unlock_saved_credential_manager`。在此之前保留 Refresh、Set credential、Update stored 和 Clear stored。
- [ ] 正式登记 UI 完成后，再评估是否删除独立 `unlock_pairing_tool`。

## iPhone 后续

- [ ] 在真实后台状态验证扫描、连接、状态恢复和签名。
- [ ] 等待 notify subscription 成功后再写认证 request。
- [ ] 实现并验证超过 ATT MTU 的分片、重组、超时和重复片段拒绝。
- [ ] 消费 Windows 的明确结果状态，并把拒绝原因显示给用户。

## 已删除的方向

以下内容不再作为待办或兼容目标：自定义 LSA 登录包、LSA token/conversion probes、旧的二进制登录交接格式、独立验证 host、GATT `0x02` 远程登记、Manager 的手动一次性授权、Credential Provider 手输密码路径、PowerShell 安装包装器和未验证的 emergency removal。
