<!-- Created by Rui MA on 28 Sep 2026 -->

# Windows Setup

发布安装包名为 **UnlockWithIPhone_<版本号>_setup.exe**，构建时自动读取 [ProductVersion.h](../ProductVersion.h)；暂存及正式维护程序仍为 **setup.exe**，产品版本从 **0.1.0** 开始。四个正式组件的固定名称由 [ComponentFiles.h](../ComponentFiles.h) 定义。安装 schema、阶段／操作、注册表路径和值名、任务／维护互斥／事件及结果快照布局唯一来源为 [SetupContract.h](SetupContract.h)；C++ 直接使用，内嵌 PowerShell 从它生成所需参数和字段顺序。本轮是发布前源码整理，未构建、安装或运行回归。

## 正式部署与维护入口

| 位置 | 内容 |
|---|---|
| System32 | Credential Provider DLL、自动 LocalSystem 凭据服务 |
| Program Files / Unlock Windows with iPhone | UnlockWithIPhone.exe、setup.exe |
| ProgramData / UnlockWindowsWithIPhone / Setup / Transactions / 事务 ID | 仅进行中的受保护事务暂存 |
| Windows 设置：已安装的应用／应用和功能 | 单个 Unlock with iPhone® 条目及产品版本 |

不创建开始菜单快捷方式。密码管理保留托盘入口；更新运行新包中的带版本安装器。安装包命名模式唯一来源为 CMake 的 UNLOCK_SETUP_OUTPUT_NAME，只读诊断读取该模式及产品版本，不另外维护命名规则。产品目录及暂存目录要求管理员／SYSTEM 所有，禁止普通用户写入；重解析点或不安全 ACL 明确拒绝。

安装账户取自实际物理控制台，另一管理员 UAC 不改变目标 SID。GATT 只通过该用户 Run 登录自启，仍以普通权限运行；服务自动以 LocalSystem 启动。Run 与托盘当前运行状态分开显示，不覆盖用户在任务管理器中的禁用选择。

正式卸载入口为带引号的绝对 setup.exe 路径和 --uninstall。一次 UAC 后直接显示确认页，默认 Cancel。未安装不转为 Install；待处理事务优先续办。准备期间入口指向本事务暂存 setup，收尾期间转为系统 PowerShell 的受限续办命令，避免引用即将删除的暂存程序；正常完成后恢复正式 setup 入口或移除卸载条目。

## 版本与确认

四个组件都带同源的三段产品版本，PE 数字版本第四段固定为零。包内架构及版本必须一致；已安装文件版本必须符合安装记录。缺失／混合版本报错，不猜测版本。

- 新包版本较高：Update，替换四个固定目标。
- 相同：显示 Reinstall，仍需用户进入确认页再执行。
- 较低：拒绝降级；卸载入口仍可使用。
- Update／Reinstall 保留密码、手机公钥登记及 ComputerId。
- Uninstall 清除 Windows 密码副本、手机公钥登记及安装用户 ComputerId。iPhone 的私钥和保存电脑记录由用户在手机端删除。

当前安装契约 schema 为 5；无版本、旧 schema、旧六组件或旧 System32 工具布局均不迁移，旧待办事务也不由新安装器续办。切换到本版前，先用当前已安装的旧维护工具完成卸载；旧卸载器的保留数据和暂存残留需要独立核验处理，不能认为新源码已改变旧二进制行为。

## 事务与退出收尾

开始操作前重新查询系统，共用维护决策。先持久登记事务及目标路径，再创建目录、写暂存文件。准备失败保留归属和原始错误；只允许继续同一事务，不自动猜测式删除或回滚。

Update／Uninstall 先移除 Run，按已安装主程序的实际路径固定所有实例句柄，核对托盘用户／session 后请求托盘正常退出；配对随托盘取消，密码管理和手工操作须完成或关闭。逐实例等待 30 秒，仍运行或重新启动实例则暂停，不强杀，不报告文件已释放。更新停用 CP、停止服务，实际重启后逐文件替换固定目标并逐字节验证，恢复服务、CP、Run。卸载先取得服务密码清除确认，重启后删除组件及登记数据。

安装与更新共用事务类的私有 finishDeployment：记录安装版本、注册桌面集成、验证版本与完整安装，再写入 finalizing。各自的部署步骤、操作文案和失败持久化保留。未定义阶段（包括已删除的编号 1、5）明确拒绝；当前有效阶段编号保持不变。

正式记录位于 InstalledProduct，进行中的事务位于 ComponentsWizard；正式记录仅保留 schema、目标 SID、版本、正式 setup 路径及最近操作 ID。事务源路径与暂存引用在收尾成功后移除。结果快照继续使用原来的版本、标志、四个 UTF-16 字段顺序和大小上限。登记目录／文件／写入锁来自 EnrollmentStore.h，凭据目录来自 SavedCredentialVault.h，服务名与 CP GUID 继续复用各自组件定义；Windows 已知目录仍由路径函数解析。

- SYSTEM 的 CompleteOperation 任务只运行本事务受保护暂存 setup。
- SYSTEM 的 FinalizeOperation 任务运行短期、无脚本文件的系统 Windows PowerShell，等待已核验的续办进程退出，并持有同一维护互斥。
- 收尾只删除该事务清单中的文件和空目录，不递归扫描历史目录。未知文件、不安全 ACL、重解析点或删除失败均留下具体错误。
- Install／Update 释放暂存后，目标用户结果任务再启动正式 setup 的结果窗口；成功结果只在收尾核验后发布。Finish 删除一次性结果任务及记录。
- Uninstall 释放文件后，短期收尾进程退出等待结果交接，不长期阻塞开机。目标用户结果进程复制非秘密结果，创建绑定用户与事务的事件并调用串行 SYSTEM 收尾任务；事件只表示结果已接收，不提供删除路径或授权认证。
- SYSTEM 打开结果已接收事件时明确申请 ReadPermissions 和 Synchronize，以读取所有者并检查交接信号；对象 ACL 允许访问不等于打开的句柄已申请读取权限。保留目标用户所有者核验。
- 卸载最后清除任务、事务／正式记录及应用条目，事件确认后普通用户窗口报告最终成功。无用户交接时仍显示未完成，并保留受限续办入口。
- 收尾任务排队串行执行；旧或不匹配任务不得改写其他事务。失败恢复收尾记录与入口，不把任务已启动、排队删除或组件已删除当作全部完成。
- 手动继续在交接成功后退出当前维护窗口，避免占用正在替换或释放的 setup；主动启动目标用户结果任务。目标用户未登录时保留登录触发，等待其登录完成结果交接。

未预期内容不被自动删除。密码删除不等于 SSD、备份或快照中的历史内容被物理擦除。

## 静态检查与获授权后的验收

已加入版本排序、同版本重新安装、拒绝降级、混合安装版本、准备／收尾占有状态以及未定义阶段拒绝的用例源码。当前静态检查和编码长度样本集中记录在 [Windows 验收记录](../Validation.md)。生成器继续强制 32,000 字符上限，只输出脚本实际使用的契约参数；PowerShell 检查仅解析语法，不运行命令。

[只读诊断脚本](../Diagnostics/Get-ComponentsStatus.ps1) 从两字段组件清单读取全部组件，区分构建目录、System32 和 Program Files，展示版本、架构、SHA-256 及记录版本。它读取共享契约、服务名和 CP GUID，解析失败直接报错；Registry64 分别读取进行中事务、正式安装记录和完成结果，区分不存在与读取失败。启动账户优先取事务，否则取正式记录；同时展示三个短期任务。脚本不挂载离线用户 hive、不启动任务、不修复安装状态。本轮只检查脚本语法与源码定义解析，未运行机器状态诊断。

获授权后验证：

1. 全新安装：四个版本一致，正式路径正确，单个应用条目，原生 PIN／密码首次登录、Run 与托盘管理正常。
2. 同版本 Reinstall、较高版本 Update、较低版本拒绝，确认取消／UAC 取消均不改数据。
3. 连续更新至少五次，只有一套正式文件；Finish 后不存在事务目录、替换临时文件或一次性任务。
4. 暂存中断、错误版本／架构、写入及替换失败、进程未退出、收尾删除失败与重启续办；归属可查，错误不被成功提示覆盖。
5. 完整卸载：清除密码、登记、目标用户 ComputerId、正式目录、暂存、任务、Run、产品记录和应用列表条目。未知内容应阻止成功提示。
6. 两种 UAC 身份、离线用户 hive、结果显示与 SYSTEM 完成的竞态、无人登录时的待交接及同一事务重复续办。
7. 不改 BLE／验签／批准／CP 自动提交，更新后的手机解锁仍需专项回归。

2026-10-04 独立实机清理已移除 16 个旧暂存目录、90 个文件，共 25,198,080 字节；清理前后六个正式组件 SHA-256 一致，没有修改登记或密码。此结果不证明新安装器收尾已经运行通过。详情见 [Windows 验收记录](../Validation.md)。

## 参考资料

- [Task Scheduler schema](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-scheduler-schema)
- [DeleteTask](https://learn.microsoft.com/en-us/windows/win32/api/taskschd/nf-taskschd-itaskfolder-deletetask)
- [Run and RunOnce](https://learn.microsoft.com/en-us/windows/win32/setupapi/run-and-runonce-registry-keys)
- [Windows uninstall registry values](https://learn.microsoft.com/en-us/windows/win32/msi/uninstall-registry-key)
- [Closing and deleting files](https://learn.microsoft.com/en-us/windows/win32/fileio/closing-and-deleting-files)
- [MoveFileEx: scheduling does not verify deletion](https://learn.microsoft.com/windows/win32/api/winbase/nf-winbase-movefileexa)
- [IRegisteredTask::Run](https://learn.microsoft.com/en-us/windows/win32/api/taskschd/nf-taskschd-iregisteredtask-run)
- [Task Scheduler result codes](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-scheduler-error-and-success-constants)
- [EventWaitHandle.GetAccessControl 所需句柄权限](https://learn.microsoft.com/en-us/dotnet/api/system.threading.eventwaithandle.getaccesscontrol?view=netframework-4.8.1)
