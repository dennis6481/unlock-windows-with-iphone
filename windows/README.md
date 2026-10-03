<!-- Created by Rui MA on 26 Sep 2026 -->

# Windows

Windows 主线只有一条：iPhone 签名经普通用户托盘 GATT host 转交 LocalSystem 服务验证，服务创建 120 秒单次授权，Credential Provider 领取本机加密保存的密码并提交给原生 Negotiate。host 按控制台锁定状态启停广播，持续自启只使用目标用户 Run。用户确认自动解锁、提示修正、安装器 Update 及自启项注册成功；五轮记录、实际重新登录自启及其他部署专项仍待补齐。

## 目录

- `Protocol`：固定签名载荷和 CNG P-256 验签。
- `PhoneApproval`：`PhoneApprovalCore` 与 `EnrollmentStore`，由保存凭据服务直接使用。
- `SavedCredential`：LocalSystem 服务、两条受限 named pipe、DPAPI vault 和临时密码管理 GUI。
- `GattHost`：普通用户托盘 BLE transport；`0x01` 认证请求、主动两分钟配对窗口接受 `0x02 + 公钥`。安装后由目标用户 Run 自启；项注册已确认，重新登录自启待验收。原广播、提示修正和 Windows 交互已获确认，完整蓝牙登记暂缓。
- `CredentialProvider`：LogonUI 磁贴，只领取有效手机授权对应的保存凭据。
- `PairingTool`：管理员确认并登记 iPhone 公钥。
- `ComponentsWizard`：唯一安装、更新、卸载和事务恢复入口。
- `Diagnostics`：只读组件状态检查。蓝牙登记身份实验的两种 UAC 场景已通过，探针源码已按用户要求移除，记录见 [GATT host](GattHost/README.md#蓝牙公钥登记代码已接入产品待验收)。

仓库不再包含自定义 LSA 包、LSA 探针、独立 phone-approval host、PowerShell 安装包装器或旧序列化格式。

## 构建

最低支持 Windows 10。使用目标机器原生架构的 Visual Studio C++ 工具链：

```powershell
cd windows
make build
make test
make build-release
```

`make test` 会触发编译。没有当前任务的明确授权时不要运行构建或测试。

## 安装、更新与卸载

2026-10-02：安装器已重写独立 Win32 页面并接入托盘、配对工具、密码管理工具和目标用户 Run。用户确认最新版 Update、自启项注册成功；这不覆盖全部 UI、自启和卸载专项。此次结构清理仅静态检查，代理未构建、安装或执行测试。

提前在开发机编译，把以下六个产物放在同一目录；目标电脑不需要编译环境：

- `unlock_windows_components_wizard.exe`
- `unlock_saved_credential_service.exe`
- `unlock_credential_provider.dll`
- `unlock_gatt_host.exe`
- `unlock_pairing_tool.exe`
- `unlock_saved_credential_manager.exe`

从仓库根目录启动：

```powershell
& '.\windows\build\unlock_windows_components_wizard.exe'
```

维护入口自行请求 UAC；普通结果提示模式不提权。安装将程序统一放到 System32，开始菜单提供 **Saved Windows credential** 和 **Install or maintain**。GATT 与配对工具保持同目录，图标不需要单独文件。

| 页面 | 操作 |
|---|---|
| 未安装 | Install / Cancel |
| 已安装 | Update / Uninstall / Cancel，显示目标 SID 和托盘运行状态 |
| 更新确认 | Back / Update / Cancel，保留密码、公钥与自启目标 |
| 卸载确认 | Back / Uninstall / Cancel，删除密码副本，保留公钥登记 |
| 进度 | 追加真实复制、替换、任务和删除日志；执行中不能关闭或取消 |
| 等待重启 | Restart now / Later；Later 只关闭窗口，不撤销已执行操作 |
| 重启后结果 | 显示系统验证成功或具体失败，Finish 关闭一次性结果提示 |

已有只安装服务和 CP 的记录可选择 Update 补齐工具与 Run 自启，不因缺少新增工具进入清密码的恢复路径。此前手动从 build 启动的 GATT 应先正常退出；安装器不会把其他路径的进程当作已安装托盘强制结束。

GATT 持续自启仅使用安装目标 SID 对应用户的 Run 项，值名 `Unlock Windows with iPhone`，由 Windows shell 以普通权限启动，可在任务管理器启动应用中管理。不保存用户密码、不使用 SYSTEM 运行蓝牙；更新保留已登记目标，不跟随另一管理员的 UAC 身份。

更新先暂存完整新产物，再移除 Run 自启、停用旧 GATT 任务并请求核实映像/PID/token/session 的托盘正常退出，同时等待配对窗口取消完成。完成更新后恢复 Run 并删除旧 GATT 任务。超时停止并保留事务，不强杀或覆盖使用中的文件；真正 Restart 后才替换文件，不调用密码清除。

重启续办任务 `UnlockWindowsWithIPhone-CompleteOperation` 以 SYSTEM 在开机时无窗口执行，只处理 HKLM 已登记且 ID/路径匹配的事务。目标用户登录任务 `UnlockWindowsWithIPhone-ComponentResult` 使用普通权限显示真实结果，不要求提权管理员登录；Finish 删除该提示任务。目标用户只获得结果任务读取/运行/删除权，不获得系统事务写入权。续办未完成时显示等待/日志，不宣称成功。

普通权限结果页核对目标用户及成功事务后首次启动托盘，后续由 Run 在登录后启动；不直接从 SYSTEM 或提权进程启动。第一次登录仍使用原生 PIN/密码，只有已有会话锁屏才可手机批准。

失败保留事务、具体错误与暂存文件，不自动清密码或回滚旧版本。待重启事务存在时不允许开始另一操作。受保护暂存目录 `System32\UnlockWindowsUpdate-<transactionID>` 保留程序和诊断线索，不存密码、公钥候选、签名断言或授权 nonce；一次性完成提示来自该目录中的安装器。HKLM 的 `ComponentResult` 仅保存非秘密结果与操作日志。

正常卸载首先必须获得服务的密码删除确认，再移除 Run 及旧 GATT 任务、快捷方式、工具及 CP/服务。重启后检查剩余文件和登记；清除无法确认时不报告成功。没有强制绕过密码清理的卸载入口。

完整操作与待验收清单见 [安装器说明](ComponentsWizard/README.md)。安装器系统检查不能代替更新后的手机解锁回归；完整蓝牙配对、跨管理员权限、自启、失败/中断和一次性提示仍待验收。

## RSSI 自动批准入口（2026-10-03，待验收）

本次代码将认证起点改为 **Unlock with iPhone** 磁贴提交箭头，iPhone 不再主动请求 challenge。手机先完成 BLE 配对以记住目标电脑，再开启持久自动批准开关，默认阈值 −60 dBm。每次 Windows 点击后手机读取新 RSSI，达标签名，否则拒绝；整次请求由服务限定为 30 秒，等待有效连接及两项通知订阅；iOS 收到 challenge 后仍须在 3 秒内完成新鲜 RSSI 和签名。时钟页、进入头像页和仅选择磁贴均不触发。服务、host、CP 与 iOS 须一致更新；此前已验证链路不代表本次后台/锁屏实现已通过。代理未构建、安装或运行，验收清单见根 README。

## 当前使用顺序

1. Components Wizard 安装六个程序并重启，目标用户正常登录后由任务启动托盘（新路径待验收）。
2. 从开始菜单打开 Saved Windows credential，在已解锁控制台设置或更新密码。
3. `unlock_pairing_tool` 确认并登记 iPhone 公钥。
4. 确认托盘已启动，锁定 Windows，在 iPhone 发起认证。
5. 显示锁屏登录选项，收到 `unlock_approved` 后 Windows 自动解锁，无需点击 Credential Provider 的 **Unlock**；手动按钮仍保留。

Manager GUI 在正式设置 UI 出现前必须保留；它的 Refresh、Set、Update 和 Clear 是当前唯一凭据维护入口。

新增蓝牙登记路径：在同一目录放置本次构建的 host 和 PairingTool，以普通用户启动 host，在已解锁控制台从托盘选择配对／更换，再在前台 iPhone 发送公钥，允许 UAC 后核对完整指纹。PairingTool 绑定实际控制台 SID，使用另一管理员提权也不改目标账户；保存并成功重新加载才报成功。[步骤及待验收项](GattHost/README.md#蓝牙公钥登记代码已接入产品待验收)。此路径目前仅完成代码与静态检查，原有正常 Update 的通过记录不覆盖它，新 Wizard 已接入这些 EXE 的部署，尚未执行安装验收。

2026-10-02 用户实体机确认上述自动解锁和三项回归通过，现冻结这一旧前台 host 原型里程碑。用户还确认重启后首次登录不显示自定义磁贴，使用原生密码登录，符合仅解锁已有会话的目标；首次登录明确不支持手机登录，不是待实现功能。随后用户反馈托盘 host 测试动作均符合预期，但实际解锁、广播停止后仍显示“错误”；提示逻辑修正后，2026-10-02 用户确认回归成功；原始历史错误的具体来源仍未提供。此前托盘 GATT 实测为手动启动，新登录任务尚未验收，iPhone App 保持前台；五轮验收步骤与当前记录见 [GATT host](GattHost/README.md#实体机验收记录与待验证项)。完整负面路径继续待验收，CP 回归步骤见 [Credential Provider](CredentialProvider/README.md)。按用户要求已跳过独立验证并接入安装器代码，不新增 LocalSystem 蓝牙服务。

## 更新实现参考

- [Microsoft: RegCreateKeyExW / REG_OPTION_VOLATILE](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regcreatekeyexw)
- [Microsoft: ChangeServiceConfigW](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-changeserviceconfigw)

## 配对 UI 调整（2026-10-02，Windows 交互已获用户确认）

应用图标以iOS `Assets.xcassets/AppIcon.appiconset/Contents.json` 中无 `appearances` 的标准图标为唯一来源，转换为多尺寸 ICO 后嵌入所有 Windows EXE，托盘使用同一资源，部署无需额外 PNG；菜单的退出始终位于最底部。新增移除手机登记按钮：一次 UAC 后显示目标账户和删除确认窗口，取消不修改登记，确认仅删除手机公钥并重新加载服务，不修改密码副本。移除期间不开放桌面配对广播。用户已确认 Windows 交互符合预期；完整登记、移除后的实际效力和失败专项尚未验收，测试暂缓。

点击配对立即请求一次 UAC；窗口显示等待手机，工具就绪后才开启配对广播。公钥经受限本地命名管道交给工具，同一窗口随后显示完整指纹并允许确认，无第二次 UAC。通道拒绝远程连接、限定 ACL 并核对双方实际进程身份和原控制台用户 SID。用户明确要求跳过独立通信实验，已直接接入产品并删除新探针；Windows 交互已获用户确认；跨管理员产品通信及完整生命周期尚未逐项验证，测试暂缓。

## 当前验证状态（2026-10-02）

用户已确认 Windows 方面的交互符合预期。本记录覆盖用户对当前 Windows 交互的总体反馈，不将首次登记后解锁、更换后旧手机失效、移除后的实际效力、密码副本不变、另一管理员凭据通信及取消／超时／失败专项分别记为通过。iOS 改动及完整两端蓝牙登记仍待验证，用户明确暂缓后续测试；原子保存回归用例也未由代理编译或执行。

安装器、System32 部署、目标用户 Run 与重启续办已实现；用户确认 Update、自启项注册成功，其余部署专项待验收。暂缓测试不表示蓝牙登记已经最终验收。

## Windows 程序图标

所有 CMake EXE 目标（包括服务、管理器、GATT host、PairingTool、Components Wizard 和测试程序）统一嵌入由 iOS `Assets.xcassets/AppIcon.appiconset/Contents.json` 中无 `appearances` 的标准图标 派生的 `windows/Resources/AppIcon.ico`。ICO 包含 16、24、32、48、64、128、256 像素尺寸；GUI 窗口及 GATT 托盘也使用同一图标资源。Windows ICO（16/24/32/48/64/128/256）与 CP 的 72×72 位图直接从该标准图像派生并提交，EXE 和 CP DLL 内嵌资源；不新增生成脚本。根目录旧 `icon.png` 保留但不再作为当前资源来源。修改标准图像时须同步更新两个派生资源，再在获得构建授权后构建。运行和部署不需要外置 PNG 或 ICO。

2026-10-02：图标资源已接入，ICO 内容与 EXE 目标覆盖已做静态检查；本次未构建或运行，新 EXE 图标及窗口显示仍待验证。

## GATT 安装后的自动启动要求

蓝牙自启现使用目标用户 `Run` 注册表项，值名 `Unlock Windows with iPhone`，可在任务管理器启动应用中管理。更新时移除原 GATT 登录任务，不保留双入口；SYSTEM 仍仅运行密码服务和安装续办，普通权限结果页负责安装后的首次托盘启动。用户禁用自启的选择不被强制覆盖。

这里的开机自启在目标用户登录时发生；登录前只有现有密码服务运行。GATT 启动后仍按实际锁屏状态控制广播，桌面上只在主动配对时广播。重启后的首次登录继续使用原生 PIN／密码。

用户确认 Update 和 Run 自启项注册成功；再次重启登录自启、禁用/启用、另一管理员及离线 hive 专项、卸载仍待确认。清理后的代码仅静态检查，详见 ComponentsWizard/README.md。

## 2026-10-03 后台与首次登录变更（未执行验收）

CP 仅在服务核实已有且锁定的物理控制台用户后枚举，首登无手机磁贴；正常锁屏默认手机候选，一次 Enter 发起，手机批准后仍按原链路自动提交。服务权威请求期限为 30 秒，iOS 新鲜 RSSI／签名仍限 3 秒。连接／订阅未就绪、RSSI 失败、超时及真实会话变化分开显示；托盘不提前消耗没有接收者的 challenge。

内部 IPC 升为 v2，部署必须同一新构建替换服务、CP 和工具。Windows 新用例及 iOS Swift 策略用例均只新增、未执行；后台整夜待机、默认候选和 Enter、重启／注销边界及图标显示仍待实机确认，历史前台解锁结果不覆盖本次变更。
