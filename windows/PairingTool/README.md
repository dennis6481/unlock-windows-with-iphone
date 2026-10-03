<!-- Created by Rui MA on 26 Sep 2026 -->

# Pairing tool

`unlock_pairing_tool.exe` 为短期提权公钥登记工具；一台电脑保存一份手机登记。普通托盘 Pair iPhone… 请求一次 UAC，同一窗口先等待手机，再核对实际控制台账户和完整 SHA-256 指纹。另一管理员 UAC 不改变目标用户。

## 确认和提交

工具根据真实记录分类：无记录首次保存；同一公钥和 SID 明确已登记，确认后只重新加载服务、不重写；不同手机提示原手机失效，Cancel 为默认选择，用户确认才替换。

deadline 为两分钟，不因 UAC 延长。目标控制台、锁屏状态、管理员权限、取消事件及父进程存活在确认和提交时重新核对；修改入口共用写入互斥。取消、超时及提交前失败保留原记录。

记录为 `%ProgramData%\UnlockWindowsWithIPhone\enrollment.dat`，保留当前 DPAPI machine scope 和受保护 ACL；它是公钥登记，不是保存密码。验证合法 P-256 曲线点后，写受保护临时文件、刷新、再次核对，再原子替换；不退回原地覆盖。

提交前确认服务可加载，提交后重新加载；失败明确区分“未保存”与“已保存／移除但服务加载失败”，不自动恢复旧文件。指纹使用共享加密实现，不自行维护第二份算法。

## 托盘与手工入口

host 与工具同目录。内部 `--bluetooth` 参数只由当前配对／移除流程提供，不是手工操作入口。工具就绪后才广播；公钥仅传一次，实际管道客户端 PID／SID／session 核验保留。

手工 CLI 仍支持，须管理员权限并明确操作。从仓库根目录执行：

```powershell
& '.\windows\build\unlock_pairing_tool.exe' --key-hex '<130-hex-digit-public-key>'
& '.\windows\build\unlock_pairing_tool.exe' --key-clipboard
& '.\windows\build\unlock_pairing_tool.exe' --key-clipboard --replace
& '.\windows\build\unlock_pairing_tool.exe' --clear
```

手工不同手机替换要求显式 `--replace`；清除要求输入 REMOVE 并确认。公钥是手机提供的公开材料，不是密码；仍须完整指纹核对。

Remove paired iPhone 只删除登记和重新加载服务，不删除保存密码、ComputerId 或 Windows 系统蓝牙配对。取消不修改记录。

## 验收

当前交互说明和实测结果分开；完整登记、跨管理员、取消、替换、保存失败和加载失败状态见 [集中验收记录](../Validation.md)。流程详见 [GattHost](../GattHost/README.md#蓝牙公钥登记代码已接入产品待验收)。
