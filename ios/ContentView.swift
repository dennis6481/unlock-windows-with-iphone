// Created by Rui MA on 26 Sep 2026

import SwiftUI

struct ContentView: View {
    let model: UnlockSetupModel

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    AppIntroSection()
                    KeyStatusSection(
                        state: model.state,
                        fingerprint: model.publicKeyFingerprint,
                        errorMessage: model.lastError,
                        testResult: model.lastTestResult
                    )
                    ActionSection(
                        prepareKey: model.prepareKey,
                        signTestChallenge: model.signTestChallenge,
                        copyPublicKey: model.copyPublicKey,
                        copyStatus: model.publicKeyCopyStatus
                    )
                    BluetoothSection(
                        status: model.bluetoothStatus,
                        errorMessage: model.bluetoothError,
                        start: model.startBluetooth,
                        enroll: model.startEnrollment,
                        stop: model.stopBluetooth
                    )
                    AutomaticUnlockSection(
                        enabled: Binding(get: { model.automaticEnabled }, set: model.setAutomaticEnabled),
                        threshold: Binding(get: { model.rssiThreshold }, set: model.setRSSIThreshold),
                        rssi: model.currentRSSI,
                        targetIdentifier: model.targetIdentifier
                    )
                    ScopeSection()
                }
                .padding()
            }
            .navigationTitle("iPhone Unlock")
        }
        .onAppear {
            model.prepareKey()
        }
    }
}

private struct AppIntroSection: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Windows 解锁 PoC")
                .font(.title2)
                .fontWeight(.semibold)
            Text("先在 Windows 托盘开启配对，在手机登记并核对指纹。之后点击 Windows 的 iPhone 磁贴箭头，手机按 RSSI 自动批准。")
                .foregroundStyle(.secondary)
        }
    }
}

private struct KeyStatusSection: View {
    let state: UnlockSetupModel.State
    let fingerprint: String?
    let errorMessage: String?
    let testResult: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Label(state.title, systemImage: state == .ready ? "checkmark.shield" : "exclamationmark.shield")
                .font(.headline)

            if let fingerprint {
                Text("公钥指纹")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                Text(fingerprint)
                    .font(.footnote.monospaced())
                    .textSelection(.enabled)
            }

            if let errorMessage {
                Text(errorMessage)
                    .foregroundStyle(.red)
                    .textSelection(.enabled)
            }

            if let testResult {
                Text(testResult)
                    .foregroundStyle(.green)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding()
        .background(.thinMaterial, in: RoundedRectangle(cornerRadius: 12))
    }
}

private struct ActionSection: View {
    let prepareKey: () -> Void
    let signTestChallenge: () -> Void
    let copyPublicKey: () -> Void
    let copyStatus: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Button("准备密钥", action: prepareKey)
                .buttonStyle(.borderedProminent)
            Button("执行本地签名测试", action: signTestChallenge)
                .buttonStyle(.bordered)
            Button("复制原始公钥（Windows 登记用）", action: copyPublicKey)
                .buttonStyle(.bordered)
            if let copyStatus {
                Text(copyStatus)
                    .font(.footnote)
                    .foregroundStyle(.green)
            }
        }
    }
}

private struct ScopeSection: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("使用边界")
                .font(.headline)
            Text("只解锁 Windows 已有会话，重启后首次登录仍用原生方式。后台与手机锁屏响应尚待实机验收；强制退出 App 后需重新打开。RSSI 是信号强度，不代表固定距离。")
                .foregroundStyle(.secondary)
        }
    }
}

private struct BluetoothSection: View {
    let status: String
    let errorMessage: String?
    let start: () -> Void
    let enroll: () -> Void
    let stop: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("BLE 状态")
                .font(.headline)
            Text(status)
                .foregroundStyle(.secondary)
            if let errorMessage {
                Text(errorMessage)
                    .foregroundStyle(.red)
                    .textSelection(.enabled)
            }
            HStack {
                Button("连接目标电脑", action: start)
                    .buttonStyle(.borderedProminent)
                Button("登记到 Windows", action: enroll)
                    .buttonStyle(.bordered)
                Button("停止", action: stop)
                    .buttonStyle(.bordered)
            }
        }
    }
}

private struct AutomaticUnlockSection: View {
    @Binding var enabled: Bool
    @Binding var threshold: Double
    let rssi: Int?
    let targetIdentifier: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("手机自动批准")
                .font(.headline)
            Toggle("自动响应 Windows 请求", isOn: $enabled)
                .disabled(targetIdentifier == nil)
            if let targetIdentifier {
                Text("目标设备：\(targetIdentifier)")
                    .font(.footnote.monospaced())
            } else {
                Text("请先在 Windows 托盘开启配对，并点击手机的登记按钮。")
                    .foregroundStyle(.secondary)
            }
            if let rssi {
                Text("当前 RSSI：\(rssi) dBm")
            } else {
                Text("当前 RSSI：尚无有效读数")
            }
            Text("批准阈值：\(Int(threshold)) dBm")
            Slider(value: $threshold, in: -100 ... -30, step: 1)
            Text("每次挑战读取新 RSSI，达到阈值才签名；信号不足直接拒绝，靠近后需重新点击 Windows 箭头。")
                .font(.footnote)
                .foregroundStyle(.secondary)
        }
    }
}

#Preview {
    ContentView(model: UnlockSetupModel.shared)
}
