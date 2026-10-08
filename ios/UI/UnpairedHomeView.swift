// Created by Rui MA on 08 Oct 2026

import SwiftUI

struct UnpairedHomeView: View {
    let connection: BluetoothConnectionState
    let authentication: PhoneAuthenticationState
    let issue: String?
    let keyError: String?
    let retry: () -> Void
    let addComputer: () -> Void

    var body: some View {
        VStack {
            Spacer()
            VStack(spacing: 4) {
                Text("No Paired PC").font(.headline)
                Text("Start by adding a PC")
            }
            .foregroundStyle(.secondary)
            .frame(maxWidth: .infinity)
            HomeIssuesView(connection: connection, authentication: authentication,
                           issue: issue, keyError: keyError, retry: retry)
            Spacer()
        }
        .safeAreaInset(edge: .bottom) {
            Button("Add a Windows PC", action: addComputer)
                .buttonSizing(.flexible)
                .buttonStyle(.glassProminent)
                .controlSize(.large)
                .padding(24)
        }
    }
}
