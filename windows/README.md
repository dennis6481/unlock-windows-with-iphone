<!-- Created by Rui MA on 26 Sep 2026 -->

# Windows

当前只有一条认证链：**Windows 手机磁贴发起 → 普通用户 GATT 托盘传输 → iPhone 签名 → LocalSystem 服务验证 → 一次性批准 → CP 自动提交保存的 MSA 密码给原生 Negotiate**。仅解锁已有物理控制台会话；首次登录使用原生 PIN／密码。

## 组件

- [Components Wizard](ComponentsWizard/README.md)：六组件安装、更新、卸载及重启续办。
- [GattHost](GattHost/README.md)：普通用户托盘、锁屏广播及配对传输。
- [PairingTool](PairingTool/README.md)：短期提权登记，一台电脑一份手机公钥登记。
- [SavedCredential](SavedCredential/README.md)：密码服务、受限 IPC 及本机密码副本管理。
- [CredentialProvider](CredentialProvider/README.md)：LogonUI 磁贴、身份核验及原生序列化。
- [PhoneApproval](PhoneApproval/README.md)、[Protocol](Protocol/README.md)：签名验证、登记存储及共享加密实现。
- `Diagnostics/Get-ComponentsStatus.ps1`：只读诊断，读取共享组件清单。

没有自定义 LSA 包、旧探针、独立审批 host、旧 UI 或旧 IPC 接受路径。手工配对 CLI 仍受支持。

## 构建与诊断

最低 Windows 10，支持原生 x64／ARM64，要求 C++20、CMake 3.25+ 及对应 Visual Studio C++ 工具。目标电脑只安装预编译文件，不编译或下载开发环境。

下列命令从仓库根目录执行，构建／测试须另行明确授权：

```powershell
make -C windows build-release
ctest --test-dir '.\windows\build' -C Release --output-on-failure
& '.\windows\Diagnostics\Get-ComponentsStatus.ps1'
```

`make test` 会触发构建。清理实现默认仅静态检查。

## 安装、更新与卸载

```powershell
& '.\windows\build\setup.exe'
```

六个部署组件及 build／安装文件名映射由 [ComponentFiles.h](ComponentFiles.h) 唯一定义。对外安装器是 `setup.exe`；System32／受保护暂存目录维护文件为 `unlock_windows_components_wizard.exe`。这是同一程序的部署映射，不是两套安装逻辑。

安装器自行请求 UAC。目标为实际物理控制台用户，不是另一管理员的提权账户。System32 安装组件与工具；开始菜单提供密码管理及安装维护入口。

- 未安装：Install / Cancel；已安装：Update / Uninstall / Cancel。
- 确认页：Back、明确操作按钮和 Cancel。执行页展示实际滚动日志，禁止取消和关闭。
- Restart now / Later：Later 保留事务；再次打开只处理当前事务。
- SYSTEM 开机任务完成受保护事务；目标用户普通权限结果页显示真实结果，Finish 清除一次性提示任务。

只支持当前完整安装。旧两组件安装、旧版本记录、缺失目标 SID 或不完整安装明确拒绝维护，不自动迁移、修复、重绑用户或清密码。当前待重启事务仍沿用续办，不要求维护期间已停用的组件正在运行。历史残留须另行处理，新安装器不清理旧 GATT 登录任务。

Update 保留密码、公钥及目标用户；先移除 Run，核实托盘／配对进程后请求正常退出，超时暂停，不强杀。真正重启后统一替换和验证文件，再恢复组件；失败保留事务及日志，不自动回滚或假报成功。

正常卸载先取得服务密码清除确认，再移除当前 Run、工具、快捷方式、CP 和服务；手机公钥保留。删除文件不代表 SSD、备份或快照历史数据被物理擦除。

## 登录自启与解锁

2026-10-04 二次锁屏回归：用户更新重启后首轮成功、第二轮失败。已定位停止调用返回后旧 Started 属性被当作仍在发布，导致遗漏下一次 StartAdvertising；应用层判断已修正，回归源码已补，尚未构建／执行。当前只需更新 Windows 修正版，已匹配的 iOS 与登记不变；详细证据见 [验收记录](Validation.md#待验收)。

密码服务为自动 LocalSystem 服务。托盘通过目标用户 Run 项 `Unlock Windows with iPhone` 在正常登录后以普通权限启动，可由任务管理器管理；不使用 SYSTEM 蓝牙或另一套 GATT 登录任务，不写提权管理员 HKCU，不覆盖用户自启禁用选择。

托盘仅在当前控制台明确锁屏或主动配对窗口广播。锁屏时按 Enter／Unlock 发起；选中磁贴或刚锁屏不发请求。服务权威请求期限 30 秒，等待唯一有效连接、双通知订阅及绑定本次请求的手机就绪回执后才投递 challenge；iPhone 按现有规则读取新鲜 RSSI 并签名。批准领取期独立为 120 秒，首次合格领取先消费再解密，失败不恢复授权。

成功批准之间没有固定冷却期；快速再次锁屏仍须新的 challenge 与有效签名，旧批准不能再次使用。移除原 5 秒限制后的执行状态见 [Windows 验收记录](Validation.md)。

2026-10-03 锁屏恢复修复已写入源码：广播启停串行推进、五秒操作期限及最多三次退避重试，phone-only IPC 新增不消费 challenge 的状态查询。iOS 确认服务缺失后释放连接并等待服务广播，两端新增 `transport_ready_required`／`0x04` 就绪握手。回归用例已补，未构建、执行或实机验收；需匹配版本一起更新，已有有效 ComputerId／公钥无需重新登记。验收至少 20 轮锁屏／解锁、后台 15 分钟及隔夜、睡眠／蓝牙恢复，全程无手动刷新，详见 [GATT host](GattHost/README.md)。广播中止底层原因仍未确认，本任务不修改安装器。

密码管理只修改本机加密副本，不修改在线 MSA 密码。移除手机登记不删除密码、ComputerId 或系统蓝牙配对。详细步骤见对应组件文档。

## Windows UI 验收（2026-10-03）

Win32 主题控件、紧凑按钮、英文用户文案及桌面 PerMonitorV2；桌面 DPI 设置不注入 CP／服务。图像唯一来源为 iOS AppIcon 标准 appearance，派生 ICO／CP 位图嵌入程序，部署不依赖外置图片。

已确认基线与全部待验收项统一见 [验收记录](Validation.md)。本次清理仅静态检查，未自动构建、测试、安装或提交。

## 参考资料

- [RegCreateKeyExW](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regcreatekeyexw)
- [ChangeServiceConfigW](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-changeserviceconfigw)
