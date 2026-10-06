// Created by Rui MA on 07 Oct 2026

import SwiftUI

struct AboutView: View {
    let model: UnlockSetupModel

    var body: some View {
        Form {
            Section {
                Link("Privacy Policy", destination: URL(string: "https://github.com/dennis6481/unlock-windows-with-iphone")!)
                NavigationLink("Diagnostics") { DiagnosticsView(model: model) }
            } footer: {
                AppVersionFooter()
            }
        }
        .navigationTitle("About")
    }
}

private struct DiagnosticsView: View {
    let model: UnlockSetupModel

    var body: some View {
        Form {
            PairingDiagnosticsSection(
                status: model.bluetooth.enrollment.title, computerID: model.bluetooth.target?.computerID,
                fingerprint: model.publicKeyFingerprint, keyError: model.keyError
            )
            ConnectionDiagnosticsSection(
                connection: model.bluetooth.connection.title, authentication: model.bluetooth.authentication.title,
                failure: model.bluetooth.connection.failure, issue: model.bluetooth.issue
            )
            BluetoothDiagnosticsSection(entries: model.bluetoothDiagnostics)
        }
        .navigationTitle("Diagnostics")
        .navigationBarTitleDisplayMode(.inline)
    }
}

private struct AppVersionFooter: View {
    var body: some View {
        let version = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "—"
        let build = Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "—"
        Text("v\(version) Build \(build)")
            .font(.footnote)
            .foregroundStyle(.secondary)
            .frame(maxWidth: .infinity)
    }
}

private struct PairingDiagnosticsSection: View {
    let status: LocalizedStringResource
    let computerID: UUID?
    let fingerprint: String?
    let keyError: String?

    var body: some View {
        Section("Pairing") {
            Text(status)
            if let computerID {
                LabeledContent("Computer ID") {
                    Text(computerID.uuidString.lowercased()).font(.caption.monospaced()).textSelection(.enabled)
                }
            }
            if let fingerprint {
                Text("iPhone public key fingerprint")
                Text(fingerprint).font(.caption.monospaced()).textSelection(.enabled)
            }
            if let keyError { Text(keyError).foregroundStyle(.red).textSelection(.enabled) }
        }
    }
}

private struct ConnectionDiagnosticsSection: View {
    let connection: LocalizedStringResource
    let authentication: LocalizedStringResource
    let failure: String?
    let issue: String?

    var body: some View {
        Section("Connection and Authentication") {
            Text(connection)
            Text(authentication)
            if let failure { Text(failure).foregroundStyle(.red).textSelection(.enabled) }
            if let issue, issue != failure { Text(issue).foregroundStyle(.orange).textSelection(.enabled) }
        }
    }
}

private struct BluetoothDiagnosticsSection: View {
    let entries: [String]

    var body: some View {
        Section("Bluetooth Diagnostics · Latest 64 Entries") {
            if entries.isEmpty { Text("No diagnostic entries").foregroundStyle(.secondary) }
            else {
                Text(entries.joined(separator: "\n"))
                    .font(.caption.monospaced()).textSelection(.enabled)
            }
        }
    }
}
