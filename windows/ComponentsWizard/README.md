<!-- Created by Rui MA on 28 Sep 2026 -->

# Components Wizard

独立 Win32 安装器负责六个预编译组件。发布文件为 **setup.exe**；已安装页标题为 **Unlock Windows with iPhone® installed**，其他页为 **Unlock Windows with iPhone® Setup**。系统内维护文件名保持当前部署约定，不保留旧安装迁移支持。

## 页面流程

| 页面 | 按钮 |
|---|---|
| 未安装 | Install / Cancel |
| 已安装 | Update / Uninstall / Cancel |
| 更新或卸载确认 | Back / Update 或 Uninstall / Cancel |
| 执行中 | 滚动日志；禁止取消和关闭 |
| 等待重启 | Restart now / Later，焦点 Later |
| 完成 | 真实验证结果 / Finish |
| 失败 | 具体错误与日志；仅当前事务适用的续办或关闭 |

窗口紧凑、居中，扩展详情保持窗口中心；主题控件、PerMonitorV2，正文约 10 pt、标题约 14 pt。非破坏性页默认主要动作，卸载确认默认 Cancel。Later 不撤销操作。

## 安装与维护条件

[ComponentFiles.h](../ComponentFiles.h) 是安装／build 文件名及六组件清单的唯一来源；CMake 输出、暂存替换、托盘工具调用、IPC 服务映像核验和诊断均复用。

页面与开始维护共用 `determineMaintenancePlan`；执行前重新查询系统，不信任此前 UI 快照。只有当前完整安装可 Update／Uninstall；旧两组件、旧 schema、缺失目标 SID 或不完整安装明确拒绝，不重绑当前管理员或自动清密码。

当前版本待重启事务优先判断，维护期间暂时停用的组件不会被当作旧安装。失败事务保留；初次安装中断不触发猜测式清理或回滚。

## 部署、自启与重启交接

System32 部署组件。安装目标 SID 来自实际物理控制台，更新／卸载沿用记录。正常维护要求管理员，结果显示不提权。

- 密码服务为自动 LocalSystem；托盘只注册目标用户 Run。
- 更新／卸载先移除 Run，核实并持有托盘／配对 helper 的映像、PID、token、session 和句柄，请求正常退出；超时暂停，不强杀。
- Update 暂存完整文件，真正重启后替换并逐字节验证，恢复服务、CP、Run 和快捷方式，保留密码与公钥。
- SYSTEM 任务 `UnlockWindowsWithIPhone-CompleteOperation` 从受保护暂存目录无窗口续办，仅处理已登记事务。
- 目标用户任务 `UnlockWindowsWithIPhone-ComponentResult` 普通权限展示非秘密结果，核验成功后首次启动托盘；后续由 Run 自启。Finish 删除一次性提示任务。
- 卸载必须取得服务密码清除确认，再删除当前组件；手机公钥保留。清除未确认不报告成功。

旧 GATT 登录任务不再注册、停用、迁移、删除或诊断。当前续办／结果任务不是持续蓝牙自启。历史残留须另行处理。

Run 注册与托盘当前运行状态分开显示，不操作 StartupApproved 内部数据或覆盖用户禁用选择。

## 验收

已确认基线、本次静态清理及待验收项统一见 [Windows 验收记录](../Validation.md)。部署验证成功不等于手机功能回归成功。

## 参考资料

- [Task Scheduler schema](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-scheduler-schema)
- [DeleteTask](https://learn.microsoft.com/en-us/windows/win32/api/taskschd/nf-taskschd-itaskfolder-deletetask)
- [Shell link flags](https://learn.microsoft.com/en-us/windows/win32/api/shlobj_core/ne-shlobj_core-shell_link_data_flags)
- [Run and RunOnce](https://learn.microsoft.com/en-us/windows/win32/setupapi/run-and-runonce-registry-keys)
