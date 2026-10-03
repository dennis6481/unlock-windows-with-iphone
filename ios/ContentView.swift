// Created by Rui MA on 26 Sep 2026

import SwiftUI

struct ContentView: View {
    let model: UnlockSetupModel
    @Environment(\.scenePhase) private var scenePhase
    @State private var showingSettings = false
    @State private var showingEnrollment = false

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 28) {
                    ComputerDisplayView(
                        name: model.bluetooth.target?.name,
                        authentication: model.bluetooth.authentication,
                        isVisible: scenePhase == .active && !showingSettings && !showingEnrollment
                    )
                    HomeStatusView(state: model.bluetooth, keyError: model.keyError,
                                   retry: model.retryConnection)
                    if model.bluetooth.target == nil {
                        Button("登记电脑") { showingEnrollment = true }
                            .buttonStyle(.borderedProminent)
                            .controlSize(.large)
                            .disabled(model.bluetooth.enrollment.isActive)
                    }
                }
                .padding(24)
                .frame(maxWidth: 600)
                .frame(maxWidth: .infinity)
            }
            .background(Color(uiColor: .systemGroupedBackground))
            .navigationTitle("Unlock with iPhone®")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button("设置", systemImage: "gearshape") { showingSettings = true }
                }
            }
            .sheet(isPresented: $showingSettings) {
                SettingsView(model: model)
            }
            .sheet(isPresented: $showingEnrollment) {
                EnrollmentView(model: model)
            }
        }
    }
}

private struct ComputerDisplayView: View {
    let name: String?
    let authentication: PhoneAuthenticationState
    let isVisible: Bool
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @ScaledMetric(relativeTo: .largeTitle) private var symbolSize = 100
    @State private var symbol = "desktopcomputer"
    @State private var resetTask: Task<Void, Never>?

    var body: some View {
        VStack(spacing: 24) {
            Image(systemName: symbol)
                .font(.system(size: symbolSize, weight: .light))
                .foregroundStyle(Color.accentColor)
                .contentTransition(
                    .symbolEffect(
                        .replace.magic(fallback: .downUp.wholeSymbol),
                        options: .nonRepeating
                    )
                )
                .symbolEffectsRemoved(reduceMotion)
                .accessibilityHidden(true)
            VStack(spacing: 8) {
                Text(name == nil ? "尚未配对" : "已配对电脑")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                Text(name ?? "添加你的 Windows 电脑")
                    .font(.title2.weight(.semibold))
                    .multilineTextAlignment(.center)
                    .textSelection(.enabled)
            }
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 40)
        .onAppear { synchronizeSymbol() }
        .onChange(of: displayState) { oldValue, newValue in
            guard oldValue.isVisible, newValue.isVisible else {
                synchronizeSymbol()
                return
            }
            if oldValue.authentication != newValue.authentication,
               newValue.authentication == .approved {
                cancelReset()
                setSymbol("lock.open.desktopcomputer", animated: true)
                resetTask = Task { @MainActor in
                    do { try await Task.sleep(for: .seconds(5)) }
                    catch { return }
                    guard !Task.isCancelled else { return }
                    setSymbol("desktopcomputer", animated: true)
                    resetTask = nil
                }
            }
        }
        .onDisappear {
            cancelReset()
            setSymbol("desktopcomputer", animated: false)
        }
    }

    private struct DisplayState: Equatable {
        let authentication: PhoneAuthenticationState
        let isVisible: Bool
    }

    private var displayState: DisplayState {
        DisplayState(authentication: authentication, isVisible: isVisible)
    }

    private func synchronizeSymbol(animated: Bool = false) {
        cancelReset()
        setSymbol("desktopcomputer", animated: animated)
    }

    private func setSymbol(_ value: String, animated: Bool) {
        var transaction = Transaction(animation: animated && !reduceMotion ? .default : nil)
        transaction.disablesAnimations = !animated || reduceMotion
        withTransaction(transaction) { symbol = value }
    }

    private func cancelReset() {
        resetTask?.cancel()
        resetTask = nil
    }
}

private struct HomeStatusView: View {
    let state: BluetoothViewState
    let keyError: String?
    let retry: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("状态").font(.subheadline).foregroundStyle(.secondary)
            StatusLine(presentation: connectionPresentation, isHeadline: true)
            StatusLine(presentation: authenticationPresentation, isHeadline: false)
            if state.enrollment.isActive {
                Text(state.enrollment.title).foregroundStyle(.secondary)
            }
            if state.connection == .bluetoothUnavailable {
                Text("请检查手机蓝牙权限和系统蓝牙开关。")
                    .font(.subheadline).foregroundStyle(.secondary)
            }
            if let failure = state.connection.failure {
                Text(failure).foregroundStyle(.red).textSelection(.enabled)
                Button("重试连接", action: retry).buttonStyle(.bordered)
            }
            if let issue = state.issue, issue != state.connection.failure {
                Text(issue).foregroundStyle(.orange).textSelection(.enabled)
            }
            if let keyError {
                Text("手机密钥不可用：\(keyError)").foregroundStyle(.red).textSelection(.enabled)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(24)
        .background(Color(uiColor: .secondarySystemGroupedBackground),
                    in: RoundedRectangle(cornerRadius: 24))
    }

    private var connectionPresentation: StatusPresentation {
        let title: String
        let immediate: Bool
        switch state.connection {
        case .unregistered:
            title = String(localized: "尚未登记电脑")
            immediate = true
        case .bluetoothUnavailable:
            title = String(localized: "蓝牙不可用")
            immediate = true
        case .waitingComputer:
            let paused = !state.automaticEnabled && !state.enrollment.isActive
            title = paused ? String(localized: "自动响应已暂停") : String(localized: "正在搜索Windows电脑")
            immediate = paused
        case .connecting, .discovering, .verifyingComputer, .subscribing, .recovering:
            title = String(localized: "正在连接")
            immediate = false
        case .ready:
            title = String(localized: "已连接，等待请求")
            immediate = false
        case .failed:
            title = String(localized: "连接异常")
            immediate = true
        }
        return StatusPresentation(title: title,
                                  symbol: state.connection == .ready ? "checkmark.circle.fill" : "circle.dotted",
                                  color: state.connection == .ready ? .green : .primary,
                                  immediate: immediate)
    }

    private var authenticationPresentation: StatusPresentation {
        let immediate: Bool
        switch state.authentication {
        case .approved, .rejected, .paused: immediate = true
        case .waiting, .readingRSSI, .signing, .awaitingWindows: immediate = !state.automaticEnabled
        }
        return StatusPresentation(title: authenticationTitle, symbol: nil,
                                  color: authenticationColor, immediate: immediate)
    }

    private var authenticationTitle: String {
        if !state.automaticEnabled { return String(localized: "自动响应已暂停") }
        switch state.authentication {
        case .waiting: return String(localized: "等待电脑发起解锁请求")
        case .paused: return String(localized: "自动响应已暂停")
        case .readingRSSI, .signing: return String(localized: "正在认证")
        case .awaitingWindows: return String(localized: "等待电脑确认")
        case .approved: return String(localized: "请求已获批准")
        case let .rejected(message): return message
        }
    }

    private var authenticationColor: Color {
        if !state.automaticEnabled { return .secondary }
        switch state.authentication {
        case .approved: return .green
        case .rejected: return .red
        default: return .secondary
        }
    }
}

private struct StatusPresentation: Equatable {
    let title: String
    let symbol: String?
    let color: Color
    let immediate: Bool
}

private struct StatusLine: View {
    let presentation: StatusPresentation
    let isHeadline: Bool
    @State private var displayed: StatusPresentation?

    var body: some View {
        let visible = displayed ?? presentation
        Group {
            if let symbol = visible.symbol {
                Label(visible.title, systemImage: symbol)
            } else {
                Text(visible.title)
            }
        }
        .font(isHeadline ? .headline : .body)
        .foregroundStyle(visible.color)
        .textSelection(.enabled)
        .task(id: presentation) {
            if displayed != nil && !presentation.immediate {
                do { try await Task.sleep(for: .milliseconds(300)) }
                catch { return }
            }
            guard !Task.isCancelled else { return }
            displayed = presentation
        }
    }
}

private struct SettingsView: View {
    let model: UnlockSetupModel
    @Environment(\.dismiss) private var dismiss
    @State private var showingEnrollment = false

    var body: some View {
        NavigationStack {
            Form {
                UnlockSettingsSection(model: model)
                DistanceSettingsSection(model: model)
                Section("电脑") {
                    if let name = model.bluetooth.target?.name {
                        LabeledContent("已配对电脑", value: name)
                    }
                    Button(model.bluetooth.target == nil ? "登记电脑" : "重新登记电脑") {
                        showingEnrollment = true
                    }
                    .disabled(model.bluetooth.enrollment.isActive)
                    NavigationLink("登记信息与诊断") {
                        DiagnosticsView(model: model)
                    }
                }
                UsageSection()
            }
            .navigationTitle("设置")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("完成") { dismiss() }
                }
            }
            .sheet(isPresented: $showingEnrollment) {
                EnrollmentView(model: model)
            }
        }
    }
}

private struct UnlockSettingsSection: View {
    let model: UnlockSetupModel

    var body: some View {
        Section {
            Toggle("自动响应 Windows 请求",
                   isOn: Binding(get: { model.bluetooth.automaticEnabled }, set: model.setAutomaticEnabled))
            Text("仅响应已登记电脑的请求。断连不会改变此开关；关闭后暂停自动批准。")
                .font(.footnote).foregroundStyle(.secondary)
        } header: {
            Text("解锁")
        }
    }
}

private struct DistanceSettingsSection: View {
    let model: UnlockSetupModel

    var body: some View {
        Section {
            Text("RSSI 批准阈值：\(model.bluetooth.threshold) dBm")
            Slider(value: Binding(get: { Double(model.bluetooth.threshold) }, set: model.setRSSIThreshold),
                   in: -100 ... -30, step: 1)
                .accessibilityLabel("RSSI 批准阈值")
                .accessibilityValue("\(model.bluetooth.threshold) dBm")
            if let rssi = model.bluetooth.rssi, let date = model.bluetooth.rssiMeasuredAt {
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
    }
}

private struct DiagnosticsView: View {
    let model: UnlockSetupModel

    var body: some View {
        Form {
            Section("登记信息") {
                Text("登记状态：\(model.bluetooth.enrollment.title)")
                if let id = model.bluetooth.target?.computerID {
                    Text("ComputerId：\(id.uuidString.lowercased())")
                        .font(.caption.monospaced()).textSelection(.enabled)
                }
                if let fingerprint = model.publicKeyFingerprint {
                    Text("手机公钥指纹")
                    Text(fingerprint).font(.caption.monospaced()).textSelection(.enabled)
                }
                if let error = model.keyError {
                    Text("手机密钥不可用：\(error)").foregroundStyle(.red).textSelection(.enabled)
                }
            }
            Section("连接与认证") {
                Text(model.bluetooth.connection.title)
                Text(model.bluetooth.authentication.title)
                if let failure = model.bluetooth.connection.failure {
                    Text(failure).foregroundStyle(.red).textSelection(.enabled)
                }
                if let issue = model.bluetooth.issue, issue != model.bluetooth.connection.failure {
                    Text(issue).foregroundStyle(.orange).textSelection(.enabled)
                }
            }
            Section("蓝牙诊断（最近 64 条）") {
                if model.bluetoothDiagnostics.isEmpty {
                    Text("暂无诊断记录").foregroundStyle(.secondary)
                } else {
                    Text(model.bluetoothDiagnostics.joined(separator: "\n"))
                        .font(.caption.monospaced()).textSelection(.enabled)
                }
            }
        }
        .navigationTitle("登记信息与诊断")
        .navigationBarTitleDisplayMode(.inline)
    }
}

private struct UsageSection: View {
    var body: some View {
        Section("使用说明") {
            Text("只解锁已有 Windows 会话。重启后首次登录仍使用原生 PIN／密码，锁屏后按一次 Enter 发起手机认证。")
            Text("请求获批不代表电脑已完成解锁；App 不显示电脑实时锁定状态。")
            Text("后台及整夜待机仍待实机验收；强制退出 App 后需重新打开。")
                .foregroundStyle(.secondary)
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
