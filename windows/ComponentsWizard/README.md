<!-- Created by Rui MA on 02 Oct 2026 -->

# Components installer

2026-10-03 外观追加调整：对外安装产物改为 `setup.exe`；已安装页的窗口标题与页标题为 **Unlock Windows with iPhone® installed**，其他页面显示 **Unlock Windows with iPhone® Setup**。默认窗口更窄、更矮；展开详情／操作日志才增加高度，收起后恢复，调整尺寸保持窗口中心而非固定角落。首次打开居于当前活动显示器工作区中心，跨 DPI 后按逻辑尺寸重新布局。仅静态检查，尚未构建或实测。

CMake 目标名、系统内维护文件名、注册键、Run 值名、任务名与开始菜单目录路径不改，避免本次外观／发布文件重命名破坏既有事务。对外命令使用 `& '.\windows\build\setup.exe'`，安装及暂存时沿用唯一内部维护文件名，不并存两个安装逻辑。

2026-10-02：独立 Win32 窗口取代旧 Wizard97 导航与更新复选框。当前部署六个预编译组件，使用目标用户 Run 自启、SYSTEM 开机续办和普通用户结果页。用户确认最新版 Update 成功、自启项注册成功；不据此标记重新登录自动启动或完整卸载通过。随后的重复代码清理仅静态检查，代理未构建、测试或安装。

已有凭据保管、手机批准及自动提交的用户实测记录不变；此前“两组件正常 Update 通过”不覆盖新的六组件安装、自启、任务权限或重启交接。

## 页面与动作

窗口使用系统主题控件、Segoe UI 约 10 pt 正文及 14 pt 标题、紧凑按钮；沿用原有 PerMonitorV2，不引入第二套缩放。非破坏性页面默认主要动作，卸载确认默认 Cancel，待重启页优先 Later，完成页为 Finish。页面说明与日志分开：只有执行页持续追加滚动日志，其他页面通过 Operation details 查看已有日志，失败页默认展开；已安装页的 SID 在 Technical details，主区域显示账户名和托盘状态。日志可通过键盘选择和滚动。2026-10-03 本次外观仅静态检查，原事务、更新及结果验证流程不变，实际显示待验收。

| 页面 | 按钮及规则 |
|---|---|
| 未安装 | Install / Cancel |
| 已安装 | Update / Uninstall / Cancel；目标账户与托盘是否运行分别显示 |
| 更新确认 | Back / Update / Cancel；保留密码、公钥和既有目标 |
| 卸载确认 | Back / Uninstall / Cancel；明确清除保存密码，保留公钥登记 |
| 执行中 | 原生进度条、追加滚动操作日志；关闭、取消和 Esc 不结束执行 |
| 待重启 | Restart now / Later；不强制关闭其他应用，Later 不撤销事务 |
| 重启后 | SYSTEM 记录的真实验证结果；Finish 清理一次性提示任务 |
| 失败 | 显示具体错误和日志，保留事务；不假报成功、不自动清密码 |

同一机器一次只能进行一个维护操作。重新运行只能进入对应待重启状态，或显式 Continue 已登记失败事务；不能开始另一项安装/更新/卸载。无法自动完成的初始安装中断只保留错误，不做猜测式清除。

## 部署和权限

六个产物必须与新安装器同目录：安装器、saved credential service、CP DLL、GATT host、pairing tool、saved credential manager。安装器不编译或下载工具链，统一安装到 System32。开始菜单提供 Saved Windows credential 和 Install or maintain。

密码管理工具仍要求管理员权限；其快捷方式配置 Run as administrator。维护安装器按模式自行请求 UAC，普通完成结果不提权。快捷方式启动与另一管理员 UAC 的新部署路径同样待验收。

- 安装目标由 WTS 实际物理控制台用户解析，不能用提升进程的用户代替。更新保留 TargetSid；既有两组件安装首次扩展时捕获实际控制台 SID。
- 密码服务继续 LocalSystem 开机自动启动；蓝牙不改成 SYSTEM 服务。
- 蓝牙自启使用目标 SID 对应用户的 `Software\Microsoft\Windows\CurrentVersion\Run`，值名 `Unlock Windows with iPhone`，命令为带引号的 System32 GATT EXE。由用户登录后的 Windows shell 以普通权限启动，可在任务管理器“启动应用”中管理。不写提权管理员 HKCU、不保存密码、不运行 SYSTEM 蓝牙。
- 更新/卸载先移除目标用户 Run 项并禁用原 GATT 登录任务，核对并 pin 托盘映像、PID、token、session，发 WM_CLOSE 等正常退出。更新完成重新注册 Run 并移除原登录任务；卸载删除两种入口。已出现的配对 helper 窗口也 pin 映像/session/句柄并等待取消。超时明确暂停，不强杀。
- 当前从 build 手动运行的 host 不被当成 System32 安装进程；维护前应手动正常退出它。
- 更新暂存全部文件，真重启后统一替换并逐字节检查；不清除密码和登记。原生登录入口保留。
- 卸载必须先由服务确认密码清除；重启后删除工具、任务、快捷方式、CP 和服务，检查结果后才报告完成。

暂存目录为 System32 下的 UnlockWindowsUpdate-事务ID，关闭 ACL 继承，仅 SYSTEM/Administrators 可写，普通用户仅执行/读取续办 UI 所需程序。它不含密码、公钥候选、签名断言或 nonce，当前保留为结果提示程序及诊断线索来源，不声称已物理擦除历史数据。

## 重启交接

UnlockWindowsWithIPhone-CompleteOperation 以 SYSTEM 在开机时执行受保护暂存安装器的 --resume-operation 事务ID 模式。必须匹配已登记 ID、路径及允许续办的阶段；Session 0 不显示窗口。真正重启边界仍使用 volatile HKLM key。

结果存在 HKLM/SOFTWARE/UnlockWindowsWithIPhone/ComponentResult，只包含目标 SID、事务 ID、非秘密状态及操作日志。UnlockWindowsWithIPhone-ComponentResult 在目标用户登录后以普通权限运行 --show-result 事务ID，等待已完成状态后展示成功/失败，不请求 UAC。结果任务只授予目标用户读取、运行和删除权，不授予系统事务写权限；该删除权限仍须实测。

续办按保存的 TargetSid 写入目标用户 Run 项：用户 hive 已加载时使用 HKEY_USERS/SID；未登录时从 ProfileList 定位现有 NTUSER.DAT，临时启用 backup/restore 权限加载、写入并卸载 hive，恢复权限。失败明确报告，不创建替代用户配置。普通权限结果页在核对成功事务、目标 SID、物理控制台会话后启动托盘，补足用户已登录而错过本次 Run 启动的情况；SYSTEM 不直接启动蓝牙。后续正常登录由 Run 启动。

首次登录继续使用原生 PIN/密码；登录后锁屏才走手机批准及 CP 自动提交。系统部署验证不是手机解锁成功证明。

## 待验收

已观察：用户确认 Update 成功及自启项注册成功。以下未确认项继续待验收：

- 新 UI 构建及实际显示：4K 100%/150%/200%/250%、跨屏 DPI、键盘导航、默认焦点、日志滚动及 Back/Cancel/Later，见 [统一验收步骤](../README.md#windows-ui-验收2026-10-03)。
- 干净安装、已安装核心组件扩展、重复更新、正常卸载。
- 普通用户登录托盘自启、注销退出再登录、另一管理员 UAC 不改目标。
- SYSTEM 开机续办、普通用户无 UAC 提示及 Finish 成功删除任务、提示仅一次。
- 更新保留密文与登记，安装目录托盘能正确调用同目录配对工具。
- 托盘退出或配对取消超时、续办失败、中途重启、重复启动不假报完成。
- 原生首次登录和 PIN/密码可用；正常登录后手机批准自动解锁已有 SID/session。
- 完整配对专项及旧负面测试继续单列，不因新部署功能完成代码而通过。

## 代码职责与权威来源

- ComponentFiles.h 唯一定义部署文件名及六组件清单；暂存、替换、工具检查、移除和路径校验均复用，不保留独立工具数组。
- DesktopDeployment.cpp 统一处理续办/结果任务、目标用户 Run、快捷方式及托盘交接；WindowsAdapter.cpp 不再保留另一套任务调度器封装，也没有转调的 registerBootHandoff。
- TargetSid 来自安装事务；ComponentSnapshot 与 ComponentResult 是观察/通知数据，不另行选择目标用户。
- 持续 GATT 自启只注册 Run。旧任务名仅用于停用、移除和诊断；结果页只进行一次普通权限启动，不注册第二套持续自启。
- 保留 UI、事务、状态及 Windows 适配职责，不把认证或蓝牙产品代码合入安装器。

参考：[Task Scheduler schema](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-scheduler-schema)、[DeleteTask](https://learn.microsoft.com/en-us/windows/win32/api/taskschd/nf-taskschd-itaskfolder-deletetask)、[Shell link flags](https://learn.microsoft.com/en-us/windows/win32/api/shlobj_core/ne-shlobj_core-shell_link_data_flags)、[Run keys](https://learn.microsoft.com/en-us/windows/win32/setupapi/run-and-runonce-registry-keys)。


## GATT 安装后的自动启动要求

安装完成（包含必要的重启续办）后，普通权限结果页负责首次启动托盘；后续由目标用户 Run 项启动 `System32\unlock_gatt_host.exe`。任务管理器允许用户禁用或重新启用自启；安装器不读写 Windows 内部 StartupApproved 数据、不强制覆盖用户的禁用选择。Run 注册完整与实际是否运行是两个独立状态。

这里的开机自启在目标用户登录时发生；登录前只有现有密码服务运行。GATT 启动后仍按实际锁屏状态控制广播，桌面上只在主动配对时广播。重启后的首次登录继续使用原生 PIN／密码。

历史观察：原登录任务启用、登录时运行后返回 1，但直接启动和稍后手动运行任务均正常；任务栏就绪前注册图标失败是疑似时序原因，未捕获开机异常。当前托盘注册失败时保留进程并记录错误，利用定时器与 TaskbarCreated 重试，不添加固定延迟或无限进程重启。用户已确认改用 Run 后 Update 及自启项注册成功；真实重新登录自启、用户禁用/启用、离线 hive 与另一管理员 UAC 专项、卸载及托盘等待专项未单独确认。
