// Created by Rui MA on 26 Sep 2026

import SwiftUI

struct ContentView: View {
    let model: UnlockSetupModel
    @State private var showingEnrollment = false

    private var state: BluetoothViewState { model.bluetooth }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Label(state.enrollment.isActive ? state.connectedComputer?.name ?? "正在寻找登记电脑" :
                          state.target?.name ?? "尚未登记 Windows 电脑",
                          systemImage: state.connection == .ready ? "desktopcomputer" : "antenna.radiowaves.left.and.right")
                        .font(.headline)
                    Text(state.connection.title)
                        .foregroundStyle(state.connection == .ready ? Color.green : Color.secondary)
                    Text(connectionHint)
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                    if let failure = state.connection.failure {
                        Text(failure).foregroundStyle(.red).textSelection(.enabled)
                        Button("重试连接", action: model.retryConnection)
                    }
                    if let issue = state.issue, issue != state.connection.failure {
                        Text(issue).font(.footnote).foregroundStyle(.orange).textSelection(.enabled)
                    }
                    Button(state.target == nil ? "登记电脑" : "重新登记电脑") {
                        showingEnrollment = true
                    }
                    .disabled(state.enrollment.isActive)
                } header: {
                    Text("目标电脑")
                }

                Section {
                    Toggle("自动响应 Windows 请求",
                           isOn: Binding(get: { state.automaticEnabled }, set: model.setAutomaticEnabled))
                    Text(state.authentication.title)
                        .textSelection(.enabled)
                    Text("仅响应已登记电脑的请求。断连不会改变此开关；关闭后暂停自动批准。")
                        .font(.footnote).foregroundStyle(.secondary)
                } header: {
                    Text("解锁")
                }

                Section {
                    Text("RSSI 批准阈值：\(state.threshold) dBm")
                    Slider(value: Binding(get: { Double(state.threshold) }, set: model.setRSSIThreshold),
                           in: -100 ... -30, step: 1)
                    if let rssi = state.rssi, let date = state.rssiMeasuredAt {
                        Text("最近认证 RSSI：\(rssi) dBm")
                        Text(date, style: .time).font(.footnote).foregroundStyle(.secondary)
                    } else {
                        Text("尚无本次认证的有效 RSSI 读数").foregroundStyle(.secondary)
                    }
                    Text("每次请求都读取新信号。最近读数不用于下一次批准，也不代表固定距离。")
                        .font(.footnote).foregroundStyle(.secondary)
                } header: {
                    Text("距离设置")
                }

                Section {
                    DisclosureGroup("登记信息与诊断") {
                        Text("登记状态：\(state.enrollment.title)")
                        if let id = state.target?.computerID {
                            Text("ComputerId：\(id.uuidString.lowercased())")
                                .font(.caption.monospaced()).textSelection(.enabled)
                        }
                        if let fingerprint = model.publicKeyFingerprint {
                            Text("手机公钥指纹")
                            Text(fingerprint).font(.caption.monospaced()).textSelection(.enabled)
                        }
                        if let error = model.keyError {
                            Text("手机密钥不可用：\(error)").foregroundStyle(.red)
                        }
                        Text("蓝牙诊断（最近 64 条）").font(.caption)
                        Text(model.bluetoothDiagnostics.joined(separator: "\n"))
                            .font(.caption.monospaced()).textSelection(.enabled)
                    }
                }

                Section {
                    Text("只解锁已有 Windows 会话。重启后首次登录仍使用原生 PIN／密码，锁屏后按一次 Enter 发起手机认证。")
                    Text("后台及整夜待机仍待实机验收；强制退出 App 后需重新打开。")
                        .foregroundStyle(.secondary)
                } header: {
                    Text("使用边界")
                }
            }
            .navigationTitle("iPhone Unlock")
            .sheet(isPresented: $showingEnrollment) {
                EnrollmentView(model: model)
            }
        }
    }

    private var connectionHint: String {
        if !state.automaticEnabled {
            return "自动响应已暂停；登记仍可单独进行。"
        }
        if state.enrollment.isActive { return "当前连接用于登记，Windows 确认前不会自动批准解锁。" }
        switch state.connection {
        case .unregistered: return "先在 Windows 托盘开启配对，再登记电脑。"
        case .waitingComputer: return "等待电脑广播，尚未建立连接；不能据此判断电脑是否锁屏。"
        case .connecting: return "发现了候选电脑，正在建立连接；尚未核对身份。"
        case .discovering, .verifyingComputer, .subscribing, .recovering:
            return "已进入连接准备流程，身份与双通知订阅完成前不会批准。"
        case .ready: return "目标身份与双通知订阅已就绪，等待 Windows 发起请求。"
        case .bluetoothUnavailable: return "请检查手机蓝牙权限和系统蓝牙开关。"
        case .failed: return "没有无限重连；确认电脑广播与组件状态后可重试连接。"
        }
    }
}

private struct EnrollmentView: View {
    let model: UnlockSetupModel
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Text("在 Windows 托盘选择配对／替换手机，并完成本地确认。电脑应处于已解锁桌面。")
                    Text("沿用现有手机密钥；失败或取消不会覆盖此前有效的目标电脑。")
                    if let fingerprint = model.publicKeyFingerprint {
                        Text("确认 Windows 上的指纹与此处一致")
                        Text(fingerprint).font(.caption.monospaced()).textSelection(.enabled)
                    }
                    if let error = model.keyError {
                        Text(error).foregroundStyle(.red)
                    }
                }
                Section {
                    Text(model.bluetooth.enrollment.title)
                    if let candidate = model.bluetooth.connectedComputer, model.bluetooth.enrollment.isActive {
                        Text("候选电脑：\(candidate.name)")
                        Text("ComputerId：\(candidate.computerID.uuidString.lowercased())")
                            .font(.caption.monospaced()).textSelection(.enabled)
                    }
                    if !model.bluetooth.enrollment.isActive {
                        Button("开始登记", action: model.startEnrollment)
                            .disabled(model.keyError != nil)
                    }
                }
            }
            .navigationTitle("登记 Windows 电脑")
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button(model.bluetooth.enrollment.isActive ? "取消登记" : "完成") {
                        if model.bluetooth.enrollment.isActive { model.cancelEnrollment() }
                        dismiss()
                    }
                }
            }
            .interactiveDismissDisabled(model.bluetooth.enrollment.isActive)
        }
    }
}

#Preview {
    ContentView(model: UnlockSetupModel.shared)
}
