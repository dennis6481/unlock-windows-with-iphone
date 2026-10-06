// Created by Rui MA on 07 Oct 2026

import SwiftUI

struct PairedHomeView: View {
    let model: UnlockSetupModel
    let isVisible: Bool
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var showingApproval = false
    @State private var resetTask: Task<Void, Never>?

    private struct DisplayInput: Equatable {
        let connection: BluetoothConnectionState
        let authentication: PhoneAuthenticationState
        let result: AuthenticationHistory.Result?
        let visible: Bool
    }

    private var displayInput: DisplayInput {
        DisplayInput(connection: model.bluetooth.connection, authentication: model.bluetooth.authentication,
                     result: model.bluetooth.lastResult, visible: isVisible)
    }

    var body: some View {
        @Bindable var model = model
        ScrollView {
            VStack(spacing: 24) {
                ComputerDisplayView(name: model.bluetooth.target?.name, showingApproval: showingApproval)
                HomeStatusCard(status: status, color: statusColor,
                               approvedAt: model.bluetooth.lastResult?.approvedAt,
                               rssi: model.bluetooth.lastResult?.rssi)
                DistanceSettingsSection(threshold: $model.rssiThreshold)
                HomeIssuesView(connection: model.bluetooth.connection, authentication: model.bluetooth.authentication,
                               issue: model.bluetooth.issue, keyError: model.keyError, retry: model.retryConnection)
            }
            .padding(20)
            .frame(maxWidth: 600)
            .frame(maxWidth: .infinity)
        }
        .onChange(of: displayInput) { old, new in
            guard old.visible, new.visible else {
                resetApproval()
                return
            }
            if new.authentication == .approved, new.result?.approvedAt != nil,
               old.result != new.result {
                resetApproval()
                setApproval(true)
                resetTask = Task { @MainActor in
                    do { try await Task.sleep(for: .seconds(5)) }
                    catch { return }
                    guard !Task.isCancelled else { return }
                    setApproval(false)
                    resetTask = nil
                }
                return
            }
            switch new.authentication {
            case .readingRSSI, .signing, .awaitingWindows, .rejected:
                resetApproval()
            case .waiting, .approved:
                if old.result != new.result || new.connection.failure != nil ||
                    new.connection == .bluetoothUnavailable {
                    resetApproval()
                }
            }
        }
        .onDisappear { resetApproval() }
    }

    private var status: LocalizedStringResource {
        if showingApproval { return PhoneAuthenticationState.approved.title }
        if model.bluetooth.connection != .ready { return model.bluetooth.connection.title }
        switch model.bluetooth.authentication {
        case .readingRSSI, .signing, .awaitingWindows, .rejected:
            return model.bluetooth.authentication.title
        case .waiting, .approved: return model.bluetooth.connection.title
        }
    }

    private var statusColor: Color {
        if showingApproval { return .green }
        if case .rejected = model.bluetooth.authentication, model.bluetooth.connection == .ready { return .red }
        return .secondary
    }

    private func setApproval(_ value: Bool) {
        var transaction = Transaction(animation: reduceMotion ? nil : .default)
        transaction.disablesAnimations = reduceMotion
        withTransaction(transaction) { showingApproval = value }
    }

    private func resetApproval() {
        resetTask?.cancel()
        resetTask = nil
        setApproval(false)
    }
}

struct HomeIssuesView: View {
    let connection: BluetoothConnectionState
    let authentication: PhoneAuthenticationState
    let issue: String?
    let keyError: String?
    let retry: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            if connection == .bluetoothUnavailable {
                Label("Bluetooth is unavailable. Check Bluetooth permission and the system Bluetooth switch.",
                      systemImage: "antenna.radiowaves.left.and.right.slash")
            }
            if let failure = connection.failure {
                Text(failure).foregroundStyle(.red).textSelection(.enabled)
                Button("Retry Connection", action: retry).buttonStyle(.bordered)
            }
            if let issue = issue, issue != connection.failure {
                Text(issue).foregroundStyle(.orange).textSelection(.enabled)
            }
            if case let .rejected(message) = authentication, connection != .ready {
                Text(message).foregroundStyle(.red).textSelection(.enabled)
            }
            if let keyError {
                Text("iPhone key unavailable: \(keyError)").foregroundStyle(.red).textSelection(.enabled)
            }
        }
        .font(.subheadline)
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.horizontal, 14)
    }
}

private struct DistanceSettingsSection: View {
    @Binding var threshold: Double
    private static let tickValues = stride(from: Double(BluetoothViewState.thresholdRange.lowerBound),
                                           through: Double(BluetoothViewState.thresholdRange.upperBound),
                                           by: 20).map { $0 }

    var body: some View {
        let thresholdLabel = Text("\(Int(threshold)) dBm")
        VStack(alignment: .leading, spacing: 8) {
            Text("Unlock Distance").font(.subheadline.weight(.medium)).foregroundStyle(.secondary)
            VStack(alignment: .leading) {
                Slider(
                    value: $threshold,
                    in: Double(BluetoothViewState.thresholdRange.lowerBound) ... Double(BluetoothViewState.thresholdRange.upperBound),
                    label: { EmptyView() },
                    currentValueLabel: { thresholdLabel },
                    ticks: {
                        SliderTickContentForEach(Self.tickValues, id: \.self) { value in
                            SliderTick(value)
                        }
                    }
                )
                .accessibilityLabel("Approval signal threshold")
                .accessibilityValue(thresholdLabel)
                SliderTickLabels(values: Self.tickValues)
            }
            .padding(14)
            .background(Color(uiColor: .secondarySystemGroupedBackground),
                        in: RoundedRectangle(cornerRadius: 22))
            Text("Your iPhone uses signal strength to estimate its distance from your PC.")
                .font(.footnote).foregroundStyle(.secondary).padding(.horizontal, 14)
        }
    }
}

private struct SliderTickLabels: View {
    let values: [Double]

    var body: some View {
        HStack(spacing: 0) {
            ForEach(values, id: \.self) { value in
                if value != values.first { Spacer(minLength: 0) }
                Text("\(Int(value)) dBm")
            }
        }
        .font(.caption)
        .monospacedDigit()
        .foregroundStyle(.secondary)
        .accessibilityHidden(true)
    }
}


private struct ComputerDisplayView: View {
    let name: String?
    let showingApproval: Bool
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @ScaledMetric(relativeTo: .largeTitle) private var symbolSize = 100

    var body: some View {
        VStack(spacing: 24) {
            Image(systemName: showingApproval ? "lock.open.desktopcomputer" : "desktopcomputer")
                .font(.system(size: symbolSize, weight: .light))
                .foregroundStyle(Color.accentColor)
                .contentTransition(.symbolEffect(.replace.magic(fallback: .downUp.wholeSymbol), options: .nonRepeating))
                .symbolEffectsRemoved(reduceMotion)
                .accessibilityHidden(true)
            Text(name ?? "")
                .font(.title2.weight(.semibold))
                .multilineTextAlignment(.center)
                .textSelection(.enabled)
        }
        .padding(.top, 28)
    }
}

private struct HomeStatusCard: View {
    let status: LocalizedStringResource
    let color: Color
    let approvedAt: Date?
    let rssi: Int?

    var body: some View {
        VStack(spacing: 0) {
            HStack(alignment: .firstTextBaseline) {
                Text("Status")
                Spacer()
                Text(status).foregroundStyle(color).multilineTextAlignment(.trailing)
            }
            .padding(14)
            Divider().padding(.horizontal, 14)
            HStack(alignment: .firstTextBaseline) {
                Text("Last approval")
                Spacer()
                if let approvedAt {
                    TimelineView(.periodic(from: .now, by: 60)) { _ in
                        if let rssi {
                            Text("\(approvedAt, format: .relative(presentation: .numeric, unitsStyle: .wide)) / \(rssi) dBm")
                        } else {
                            Text("\(approvedAt, format: .relative(presentation: .numeric, unitsStyle: .wide)) / N/A")
                        }
                    }
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.trailing)
                } else { Text("N/A").foregroundStyle(.secondary) }
            }
            .padding(14)
        }
        .background(Color(uiColor: .secondarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 22))
    }
}
