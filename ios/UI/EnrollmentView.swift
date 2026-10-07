// Created by Rui MA on 07 Oct 2026

import SwiftUI
import UIKit

struct EnrollmentView: View {
    let model: UnlockSetupModel
    @Environment(\.dismiss) private var dismiss
    @State private var path: [Destination] = []

    private enum Destination: Hashable {
        case verification, success, failure, cancelled
    }

    var body: some View {
        NavigationStack(path: $path) {
            EnrollmentIntroductionPage(
                issue: model.bluetooth.issue, keyError: model.keyError,
                beginPairing: beginPairing, close: close
            )
            .navigationDestination(for: Destination.self) { destination in
                switch destination {
                case .verification:
                    EnrollmentVerificationPage(
                        fingerprint: model.publicKeyFingerprint,
                        computerName: model.bluetooth.connectedComputer?.name,
                        computerID: model.bluetooth.connectedComputer?.computerID,
                        status: model.bluetooth.enrollment.title,
                        isActive: model.bluetooth.enrollment.isActive,
                        issue: model.bluetooth.issue, keyError: model.keyError, close: close
                    )
                case .success:
                    SetupSheetPage(
                        title: "You’re all set!", description: "Enjoy unlocking with iPhone!",
                        symbol: "checkmark.shield.fill", color: .green,
                        buttonTitle: "Done", action: close
                    ) { EmptyView() }
                case .cancelled:
                    SetupSheetPage(
                        title: "Pairing Cancelled",
                        description: "Pairing was cancelled on this iPhone.",
                        symbol: "xmark.shield.fill", color: .secondary,
                        buttonTitle: "Done", action: close,
                        secondaryAction: (title: "Retry Pairing", disabled: model.keyError != nil,
                                          action: beginPairing)
                    ) { EmptyView() }
                    .navigationBarBackButtonHidden(true)
                case .failure:
                    SetupSheetPage(
                        title: "Pairing Failed",
                        description: "Pairing could not be completed. Check your PC and try again.",
                        symbol: "exclamationmark.shield.fill", color: .red,
                        buttonTitle: "Try Again", disabled: model.keyError != nil, action: beginPairing
                    ) {
                        Text(model.bluetooth.enrollment.title).foregroundStyle(.red).textSelection(.enabled)
                        EnrollmentIssuesView(issue: model.bluetooth.issue, keyError: model.keyError)
                    }
                }
            }
        }
        .interactiveDismissDisabled(model.bluetooth.enrollment.isActive)
        .onChange(of: model.bluetooth.enrollment) { _, _ in showOutcome() }
        .onChange(of: path) { old, new in
            if old.contains(.verification), new.isEmpty, model.bluetooth.enrollment.isActive {
                model.cancelEnrollment()
            }
        }
    }

    private func beginPairing() {
        model.startEnrollment()
        switch model.bluetooth.enrollment {
        case .idle: break
        default:
            path = [.verification]
            showOutcome()
        }
    }

    private func showOutcome() {
        guard path.last == .verification else { return }
        guard let destination = destination(for: model.bluetooth.enrollment) else { return }
        path.append(destination)
    }

    private func destination(for enrollment: ComputerEnrollmentState) -> Destination? {
        switch enrollment {
        case .succeeded: model.bluetooth.target == nil ? nil : .success
        case .failed, .rejected: .failure
        case .cancelled: .cancelled
        case .idle, .searching, .waitingConfirmation: nil
        }
    }

    private func close() {
        if model.bluetooth.enrollment.isActive {
            model.cancelEnrollment()
            showOutcome()
            return
        }
        dismiss()
    }
}

private struct EnrollmentIntroductionPage: View {
    let issue: String?
    let keyError: String?
    let beginPairing: () -> Void
    let close: () -> Void

    var body: some View {
        SetupSheetPage(
            title: "Pair your PC",
            description: "On your unlocked Windows desktop, right-click the Unlock with iPhone tray icon and select Pair iPhone. Continue here, then verify the fingerprint on your PC.",
            symbol: "pc", multicolor: true,
            buttonTitle: "Continue", disabled: keyError != nil,
            action: beginPairing
        ) {
            EnrollmentIssuesView(issue: issue, keyError: keyError)
        }
        .toolbar {
            ToolbarItem(placement: .topBarLeading) {
                Button("Close pairing", systemImage: "xmark", action: close)
                    .labelStyle(.iconOnly)
            }
        }
    }
}


private struct EnrollmentVerificationPage: View {
    let fingerprint: String?
    let computerName: String?
    let computerID: UUID?
    let status: LocalizedStringResource
    let isActive: Bool
    let issue: String?
    let keyError: String?
    let close: () -> Void
    @State private var copied = false

    var body: some View {
        SetupSheetPage(
            title: "Confirm on your PC",
            description: "Compare this iPhone’s fingerprint with the one shown on Windows, then confirm on your PC.",
            symbol: "key.shield.fill",
            buttonTitle: isActive ? "Cancel Pairing" : "Done",
            destructive: isActive,
            action: close
        ) {
            VStack(alignment: .leading, spacing: 14) {
                if let fingerprint = fingerprint {
                    HStack(alignment: .top) {
                        VStack(alignment: .leading, spacing: 8) {
                            Text("iPhone SHA-256 fingerprint").font(.caption).foregroundStyle(.secondary)
                            Text(fingerprint).font(.body.monospaced()).textSelection(.enabled)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                        Button {
                            UIPasteboard.general.string = fingerprint
                            copied = true
                        } label: { Image(systemName: copied ? "checkmark" : "document.on.document") }
                        .accessibilityLabel(Text(copied ? LocalizedStringResource("Fingerprint copied") : LocalizedStringResource("Copy fingerprint")))
                    }
                }
                HStack {
                    if isActive { ProgressView() }
                    Text(status)
                }
                if let computerName { Text(computerName).font(.headline) }
                if let computerID {
                    Text(computerID.uuidString.lowercased())
                        .font(.caption.monospaced()).textSelection(.enabled)
                }
            }
            .padding(16)
            .background(Color(uiColor: .secondarySystemGroupedBackground),
                        in: RoundedRectangle(cornerRadius: 20))
            EnrollmentIssuesView(issue: issue, keyError: keyError)
        }
    }

}

private struct EnrollmentIssuesView: View {
    let issue: String?
    let keyError: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            if let issue { Text(issue).foregroundStyle(.orange).textSelection(.enabled) }
            if let keyError { Text(keyError).foregroundStyle(.red).textSelection(.enabled) }
        }
    }
}

#Preview {
    EnrollmentVerificationPage(
        fingerprint: "xsncdnis-dsnbciez-cdqse<-àé888",
        computerName: "Windows PC",
        computerID: UUID(uuidString: "00000000-0000-0000-0000-000000000001"),
        status: "status",
        isActive: true,
        issue: "issue",
        keyError: "keyError",
        close: {}
    )
}
