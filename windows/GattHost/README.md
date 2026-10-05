<!-- Created by Rui MA on 26 Sep 2026 -->

# 主应用后台模块

`UnlockWithIPhone.exe` 的无参数角色是控制台普通用户的单实例托盘 BLE transport，不持有密码、不自行形成可信批准。安装后由目标用户 Run 在登录后启动；首次登录使用原生 PIN／密码。

## 生命周期与认证

仅进程会话为当前物理控制台且明确锁定时广播；桌面只有主动两分钟配对窗口例外。注销退出，睡眠／结束期间不启动广播。WTS／恢复／广播事件及定期查询核对实际状态，不用历史错误代替当前状态。

服务和 characteristic 初始化后复用。停止发布不主动断开 BLE，但不保证远端服务和订阅仍可用；iPhone 确认服务缺失后会释放连接，等待下次服务广播。实际 Windows 解锁决定停止，手机 `unlock_approved` 不单独触发停止。保留可用连接上的请求仍由服务核对锁屏身份及授权。

目标广播状态、原始 WinRT 状态和启停调用结果分别记录。控制线程串行启停，启动观察最多五秒，期间合并新的目标状态。StopAdvertising 成功返回即记录应用已停止发布，不等待属性变为 Stopped；若属性保留上一轮 Started，不重复停止，下一次锁屏仍重新调用 StartAdvertising。该记录表示 API 调用成功，不是无线抓包验证。启动失败／实际中止最多按 1、2、4 秒重试三次，耗尽明确提示；解锁、睡眠或退出取消待重试，新锁屏周期重建预算。成功确认后清除当前错误，历史原始状态、BluetoothError 和 HRESULT 保留；启动时上一轮 Aborted 不立即认作新故障。

磁贴发起后，host 用 phone-only IPC `peekPhoneAuthentication = 17` 查询状态，等待唯一同时订阅 challenge／result 的连接，向其 result 发送 `transport_ready_required`，每秒最多一次。收到当前连接的 `0x04 + 36 字节小写 requestID` 后重新核对请求与订阅，才单次领取 challenge。未就绪时不消费请求，总期限仍为服务原有 30 秒；断连、停止发布、服务失效、配对或请求结束清除准备状态。assertion 原样交 LocalSystem 验签，密码不进入 host。

服务 UUID 为 `F1E2D3C4-B5A6-4789-8012-3456789ABCDE`；request／challenge／assertion／result／ComputerId 依次以 ABCD1–ABCD5 结尾。ComputerId 为当前用户 HKCU 中的持久 UUID；异常已有值报错，不重新生成。手机用它核对目标，不以名称或 peripheral UUID 授权。

request 接受失败帧 `0x03 + requestID + 原因` 和固定 37 字节的 `0x04` 就绪回执；配对窗口接受 `0x02 + 65 字节 P-256 公钥`，不接受旧 `0x01`。配对期间不处理认证 request／assertion。

## 托盘菜单

- **Status…**：当前连接、广播及登记；Refresh 核对当前状态，Technical details 展示历史诊断。
- **Pair iPhone…**：统一首次、重复和替换入口。
- **Manage saved password…**：同一主程序的密码管理角色，请求一次 UAC。
- **Remove paired iPhone…**：删除公钥登记，不删除密码、ComputerId 或系统蓝牙配对。
- **Quit**：停止广播、撤销事件、清理配对／异步请求并退出。

普通角色拒绝管理员提权运行；关闭操作窗口不退出托盘。角色分派见 [主应用](../README.md)。

历史错误不覆盖恢复后的当前状态。托盘注册失败明确记录，等待任务栏事件和定期重试，不增加无限进程重启。

## 蓝牙公钥登记代码（已接入产品，待验收）

1. 已解锁桌面选择 Pair iPhone，请求一次 UAC；同一窗口等待手机，受限本地通道报告工具就绪后开始广播。
2. iPhone 登记到 Windows，窗口核对实际控制台账户和完整八组指纹；另一管理员 UAC 不改变目标。
3. 同一手机及账户确认已登记，不重写文件；不同手机只有明确确认才替换原登记。
4. 取消、超时、断连、锁屏、会话变化、睡眠或退出终止操作；提交前检查原记录未变。

两分钟从点击开始，不因 UAC 或候选到达延长。配对窗口由同一主程序的临时提权角色承接。保存后加载失败明确报告已保存但服务加载失败，不假装回滚。详见 [登记模块](../Enrollment/README.md)。

## 实体机验收记录与待验证项

唯一记录见 [Windows 验收记录](../Validation.md)。旧交互或前台成功不代表完整配对、整夜后台或部署专项通过。

2026-10-03 锁屏恢复修复：日志已证明成功解锁后 iOS 服务失效并长期等待，广播中止的底层原因尚未确认。广播状态机和手机就绪握手已实现，回归源码覆盖启停交错、重试／取消、连接与请求绑定、过期和 peek 不消费 challenge；仅静态检查，未构建或执行测试。

2026-10-04 用户更新并重启后，首次锁屏解锁成功，日志有准备消息、就绪回执、challenge 投递及服务验签结果；第二次未恢复。应用层根因已定位：停止调用返回后属性仍为 Started，旧状态机先误报停止超时，随后跳过重新发布，重复停止又报 HRESULT 0x8000000E。停止调用结果与旧属性分离的修正及相应用例已写入，未构建或运行；底层属性不更新的原因及完整后台可靠性仍待确认。此修正仅涉及 Windows，已匹配的 iOS 无需改动或重新登记。

获得授权后，Windows／iOS 一起更新为匹配版本，保留已有登记；连续锁屏／解锁至少 20 轮、手机后台 15 分钟及隔夜、电脑睡眠恢复、手机离开返回和蓝牙关闭恢复。全程不 Refresh、不点击手机 Retry。特别核对服务缺失无连接循环、未就绪时 challenge 未投递、30 秒准确失败、重复回执不重复批准，以及正常配对与保存凭据回归。双端日志记录 UTC、单调时间、generation 和 requestID，不含密码或签名正文。

获授权的诊断启动命令从仓库根目录执行；不要与已安装托盘同时运行：

```powershell
& '.\windows\build\UnlockWithIPhone.exe'
```

## 参考资料

- [Microsoft GATT sample](https://github.com/microsoft/Windows-universal-samples/blob/main/Samples/BluetoothLE/cppwinrt/Scenario3_ServerForeground.cpp)
- [WTS notifications](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsregistersessionnotification)
- [WTS lock state](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/ns-wtsapi32-wtsinfoex_level1_w)
- [Advertisement status](https://learn.microsoft.com/en-us/uwp/api/windows.devices.bluetooth.genericattributeprofile.gattserviceprovideradvertisementstatus)
- [Microsoft: GATT server publication](https://learn.microsoft.com/en-us/windows/apps/develop/devices-sensors/gatt-server)
- [Microsoft: StopAdvertising](https://learn.microsoft.com/en-us/uwp/api/windows.devices.bluetooth.genericattributeprofile.gattserviceprovider.stopadvertising)
