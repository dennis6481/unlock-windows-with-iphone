<!-- Created by Rui MA on 26 Sep 2026 -->

# GATT host

`unlock_gatt_host` 复用现有 BLE transport，现为无终端窗口、带托盘的普通用户进程。只有进程所属会话是当前物理控制台、会话为 Active 且 `WTSSessionInfoEx` 明确报告锁定时才请求广播。已解锁、非当前控制台或状态无法确认时停止广播；所属会话注销时退出。同一用户会话内只允许一个实例。

2026-10-02：第一阶段代码已实现。用户运行 Release 构建时曾在托盘 `LoadIconW` 调用处遇到 C2664：未定义 `UNICODE` 时，`IDI_APPLICATION` 展开为 ANSI 资源指针。已改为显式 `MAKEINTRESOURCEW(32512)`，资源 ID 与 Windows SDK 的默认应用图标一致。用户随后反馈托盘 host 测试动作均符合预期，唯一报告的问题是实际解锁、广播停止后仍显示“错误”。最新提示修正尚未重新构建或运行验证，第一阶段最终验收仍待完成；此前旧前台 host 的自动解锁记录与本次托盘 host 测试反馈分别记录。

## 生命周期与诊断

用户随后反馈测试动作均符合预期，但已解锁、广播停止后托盘仍带“错误”前缀。静态检查确认原实现将历史错误持续用作当前错误提示，现已修正；具体触发的原始错误尚待详情确认。本次提示修正仅静态检查，未重新构建或运行，修正后回归仍待执行。

服务和四个 characteristic 只初始化一次。停止广播不撤销写事件、不销毁 characteristic 或订阅，也不主动断开已有 BLE 连接。`unlock_approved` 只转发到手机，不触发停止广播；实际 Windows 解锁状态才决定停止。广播停止不是授权边界，保留连接上的请求仍由保存凭据服务检查锁屏状态、验证签名并管理一次性批准。

隐藏的普通顶层窗口接收所有会话的 WTS 通知和睡眠恢复通知。启动、会话变化、广播状态事件及每秒状态核对都重新查询当前物理控制台和实际锁定状态；不把通知顺序或旧广播事件当作当前状态。睡眠及会话结束期间禁止启动广播。WinRT 回调把写请求、订阅变化和广播状态事件交回同一控制线程；广播启停和 IPC 转发串行执行。

托盘提示包括“已解锁，广播停止”“锁屏，正在广播”“广播启动中”和“错误”。右键菜单只有 **状态详情**、**重新检查** 和 **退出**，没有强制广播。状态详情保留最近的广播事件数值、BluetoothError、HRESULT、IPC 阶段和 Win32 错误，同时输出到调试器；不记录 challenge、assertion、密码或批准内容。托盘错误前缀表示尚未恢复的生命周期错误；实际会话查询成功且广播状态符合当前锁屏条件后自动清除。历史通信／回调错误仍单独标注并保留在详情中，不作为当前广播状态的错误前缀，重新检查也不删除历史记录。启动广播失败不在每秒核对中反复重试；广播中止后需重新检查，仍须满足实际锁屏条件。GATT 初始化失败需退出并重新启动同一 EXE。

退出时先拒绝新回调入队，停止广播、撤销事件，等待已进入的异步写请求完成 deferral 清理，再丢弃尚未处理的请求并移除托盘和窗口。撤销失败记录具体错误，不静默忽略。

## 启动方式（第一阶段）

在已经正常登录的物理控制台，以普通用户直接启动本次构建的 `unlock_gatt_host.exe`，无需保持终端窗口。构建和运行须分别获得当前任务的明确授权；旧构建文件不包含这些变更。

```powershell
Start-Process -FilePath '.\windows\build\unlock_gatt_host.exe'
```

本阶段仍需手动启动。Components Wizard 尚未安装 GATT EXE，也未创建登录任务；不要将手动启动成功写成登录自动启动已完成。不新增 LocalSystem 蓝牙服务、UWP 后台任务或打包体系。

## 保持现有协议

- service UUID：`F1E2D3C4-B5A6-4789-8012-3456789ABCDE`。
- request / challenge / assertion / result UUID 分别以 `ABCD1` / `ABCD2` / `ABCD3` / `ABCD4` 结尾。
- request 只接受一个字节 `0x01`，经受限 phone-only IPC 请求服务签发 challenge。
- challenge 通知服务返回的 JSON；assertion 原样转交服务；result 转发服务结果，例如 `unlock_approved`、`not_ready` 或拒绝原因。
- 公钥登记仍由管理员在已解锁控制台运行 `unlock_pairing_tool`，人工核对指纹；不经过 GATT。
- 密码保管、验签、一次性批准、CP 自动提交和 iPhone 前台操作保持现有实现。

## 实体机验收（记录与待验证项）

当前观察记录来自用户反馈：测试动作均符合预期，但实际解锁、广播停止后仍显示“错误”。尚未提供逐项、逐轮的托盘详情、广播事件和重新扫描记录，因此不将所有专项或五轮验收标记为完成；原始历史错误的具体来源也尚未确认。

下一步先使用包含最新提示修正的构建验证：实际解锁且确认广播停止后，托盘应显示“已解锁，广播停止”，不再带“错误”前缀；历史通信／回调错误仍保留在状态详情中。再锁屏时正常显示广播状态；当前生命周期故障仍应显示错误，恢复确认后清除。最新修正目前仅静态检查，构建和运行仍须当前任务明确授权。

第一阶段最终验收需补齐以下至少连续五轮的记录，包括每轮托盘详情、广播事件和手机重新扫描结果；已有测试反馈可在提供对应记录后纳入：

1. 已解锁时启动：托盘正常，广播停止；重复启动没有第二个实例。
2. Win+L：出现广播启动事件，手机可发现或复用连接；前台批准后 CP 自动解锁。
3. 实际解锁后广播停止；另用原生密码或 PIN 解锁，也应停止。手机仍显示已连接不等于仍在广播，须核对广播事件及重新扫描。
4. 再锁屏且不批准：Windows 保持锁定并持续广播；重新批准后再次自动解锁。密码校验失败时，`unlock_approved` 不应使广播停止。
5. 中断密码服务：手机不能解锁，原生入口可用；恢复服务后重新批准。
6. 分别验证手机断开重连、快速锁屏／解锁、蓝牙关闭再开启、睡眠恢复：核对实际会话状态，桌面不因旧事件继续广播。恢复失败保留具体错误，并在托盘重新检查。
7. 注销应退出；重新登录仍需手动启动。账户切换、非控制台会话及会话查询失败继续单列，不因前面通过而标为通过。

每项记录“观察结果／失败错误／未验证条件”，不要仅以手机连接状态推断广播状态。若保留连接导致重复认证失败，先复现并记录证据，再考虑最小修改 `ios/Core/BluetoothAuthenticator.swift` 复用连接和有效订阅、重发一次认证请求；本轮未修改 iOS，不加入后台扫描或自动批准。

## 安装器阶段（未接入）

第一阶段实体机验收通过后，才将同一 GATT EXE 纳入 Components Wizard 的 System32 安装、Update 暂存替换和卸载流程。登录任务 `UnlockWindowsWithIPhone-GattHost` 绑定安装时实际物理控制台用户 SID，使用普通权限交互用户 token，不保存密码，不使用提权管理员账户代替目标用户。

后续需单独实现并验收安装后启动、登录自动启动、Update 替换前停止任务及重启续办后恢复、卸载移除任务和文件；密码与公钥遵循现有更新／卸载语义。正式接入后仍只有同一 EXE，直接启动仅用于诊断。首次登录不显示自定义磁贴，正常登录后锁屏可手机解锁的边界必须再次回归。当前没有无限崩溃重启、自动回滚或身份格式迁移。

## 参考资料

- [Microsoft GATT foreground sample](https://github.com/microsoft/Windows-universal-samples/blob/main/Samples/BluetoothLE/cppwinrt/Scenario3_ServerForeground.cpp)
- [Microsoft: WTSRegisterSessionNotification](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsregistersessionnotification)
- [Microsoft: WTSINFOEX_LEVEL1_W](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/ns-wtsapi32-wtsinfoex_level1_w)
- [Microsoft: GattServiceProviderAdvertisementStatus](https://learn.microsoft.com/en-us/uwp/api/windows.devices.bluetooth.genericattributeprofile.gattserviceprovideradvertisementstatus)
