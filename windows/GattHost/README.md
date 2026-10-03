<!-- Created by Rui MA on 26 Sep 2026 -->

# GATT host

`unlock_gatt_host.exe` 是控制台普通用户的单实例托盘 BLE transport，不持有密码、不自行形成可信批准。安装后由目标用户 Run 在登录后启动；首次登录使用原生 PIN／密码。

## 生命周期与认证

仅进程会话为当前物理控制台且明确锁定时广播；桌面只有主动两分钟配对窗口例外。注销退出，睡眠／结束期间不启动广播。WTS／恢复／广播事件及定期查询核对实际状态，不用历史错误代替当前状态。

服务和 characteristic 初始化后复用。停止广播不主动断开 BLE、不销毁订阅；实际 Windows 解锁决定停止，手机 `unlock_approved` 不单独触发停止。保留连接上的请求仍由服务核对锁屏身份及授权。

磁贴发起后，host 等待唯一同时订阅 challenge／result 的连接；无接收者或多个接收者时不领取 challenge，不立即消耗请求。总期限由服务限定 30 秒。投递后通知失败或断连明确报告；assertion 原样交 LocalSystem 验签。密码不进入 host。

服务 UUID 为 `F1E2D3C4-B5A6-4789-8012-3456789ABCDE`；request／challenge／assertion／result／ComputerId 依次以 ABCD1–ABCD5 结尾。ComputerId 为当前用户 HKCU 中的持久 UUID；异常已有值报错，不重新生成。手机用它核对目标，不以名称或 peripheral UUID 授权。

request 接受失败帧 `0x03 + requestID + 原因`；配对窗口接受 `0x02 + 65 字节 P-256 公钥`，不接受旧 `0x01`。配对期间不处理认证 request／assertion。

## 托盘菜单

- **Status…**：当前连接、广播及登记；Refresh 核对当前状态，Technical details 展示历史诊断。
- **Pair iPhone…**：统一首次、重复和替换入口。
- **Manage saved password…**：安装目录密码管理工具，请求 UAC。
- **Remove paired iPhone…**：删除公钥登记，不删除密码、ComputerId 或系统蓝牙配对。
- **Quit**：停止广播、撤销事件、清理配对／异步请求并退出。

历史错误不覆盖恢复后的当前状态。托盘注册失败明确记录，等待任务栏事件和定期重试，不增加无限进程重启。

## 蓝牙公钥登记代码（已接入产品，待验收）

1. 已解锁桌面选择 Pair iPhone，请求一次 UAC；同一窗口等待手机，受限本地通道报告工具就绪后开始广播。
2. iPhone 登记到 Windows，窗口核对实际控制台账户和完整八组指纹；另一管理员 UAC 不改变目标。
3. 同一手机及账户确认已登记，不重写文件；不同手机只有明确确认才替换原登记。
4. 取消、超时、断连、锁屏、会话变化、睡眠或退出终止操作；提交前检查原记录未变。

两分钟从点击开始，不因 UAC 或候选到达延长。host／工具保持同目录。保存后加载失败明确报告已保存但服务加载失败，不假装回滚。详见 [PairingTool](../PairingTool/README.md)。

## 实体机验收记录与待验证项

唯一记录见 [Windows 验收记录](../Validation.md)。旧交互或前台成功不代表完整配对、整夜后台或部署专项通过。

获授权的诊断启动命令从仓库根目录执行；不要与已安装托盘同时运行：

```powershell
& '.\windows\build\unlock_gatt_host.exe'
```

## 参考资料

- [Microsoft GATT sample](https://github.com/microsoft/Windows-universal-samples/blob/main/Samples/BluetoothLE/cppwinrt/Scenario3_ServerForeground.cpp)
- [WTS notifications](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsregistersessionnotification)
- [WTS lock state](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/ns-wtsapi32-wtsinfoex_level1_w)
- [Advertisement status](https://learn.microsoft.com/en-us/uwp/api/windows.devices.bluetooth.genericattributeprofile.gattserviceprovideradvertisementstatus)
