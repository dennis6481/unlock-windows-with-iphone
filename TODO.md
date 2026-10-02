<!-- Created by Rui MA on 27 Sep 2026 -->

# TODO

## Windows 主线

- [ ] 把 `unlock_gatt_host` 封装成可持续运行的后台组件，并在锁屏、注销、重启和蓝牙断线场景验证生命周期。
- [ ] 验证后台组件后删除前台 host 启动路径，不长期并存两套 GATT 实现。
- [ ] 为已有有效 120 秒授权时的重复 challenge 请求定义明确结果，避免 iPhone 只看到通用 `not_ready`。
- [x] 加入 Credential Provider 自动提交：服务对每次手机批准只发出一次非秘密 offer；CP 在自身线程触发重新枚举，LogonUI 自动调用默认磁贴的 `GetSerialization()`。2026-10-02 用户实体机确认自动解锁成功。
- [x] 2026-10-02 用户确认三项回归通过：再次锁屏无手机批准保持锁定；重新手机批准再次自动解锁；原生 PIN/密码可用。保留手动 **Unlock** 按钮。
- [x] 定位并修正自动查询的 IPC 解析遗漏：`takeAutoSubmitOffer=12` 被原来最大 11 的校验拒绝，导致服务断开管道和 CP `0x800700e9`。两端改用同一合法操作列表，修复后用户确认端到端自动解锁通过；已补包读取回归用例，其自动化执行结果未另行确认。
- [ ] 补充自动提交的失败、重复枚举、CP 重建与服务重启验收，确认同一 offer 不再触发且旧批准失效。
- [ ] 验收错误签名、过期、重放、账户切换、console session 切换、非 LogonUI 调用者和服务重启。
- [ ] 完成生产签名、安装包、升级与卸载验收。
- [x] Components Wizard 加入保留密码副本与公钥的 Update：受保护暂存、重启边界、续办替换、文件与服务验证；2026-10-02 用户确认正常安装器更新流程通过。
- [ ] 补充 Update 专项验收：密文与登记文件前后哈希、重启前续办限制、中断续办、失败恢复和 over-the-shoulder UAC。正常更新通过不等于这些专项已通过。

## 冻结里程碑（2026-10-02）

依据用户实体机反馈，冻结“前台 iPhone 批准 → Windows 自动解锁已有会话”及安装器正常 Update。下一步先用最小实验验证 Windows GATT 后台运行与锁屏、断线重连，再接入安装器；不改变已验证的凭据保管和自动提交链路。iPhone 后台、完整负面测试及生产级更新恢复继续单列。

- [x] 2026-10-02 用户确认首次登录边界：重启后不显示自定义磁贴，使用原生密码登录；手机解锁仅用于已有会话再次锁屏。首次登录明确排除，不列为后续功能。
- [ ] 后台组件及安装器后续变更时回归此边界：首次登录不显示自定义磁贴，不接受手机批准登录；正常登录后再次锁屏仍能手机批准并自动解锁。

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
