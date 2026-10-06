// Created by Rui MA on 26 Sep 2026

import SwiftUI

struct ContentView: View {
    let model: UnlockSetupModel
    @Environment(\.scenePhase) private var scenePhase
    @State private var showingAbout = false
    @State private var showingEnrollment = false
    @State private var confirmingRemoval = false
    @State private var showingRemovalSuccess = false

    var body: some View {
        NavigationStack {
            Group {
                if model.bluetooth.target == nil {
                    UnpairedHomeView(
                        connection: model.bluetooth.connection,
                        authentication: model.bluetooth.authentication,
                        issue: model.bluetooth.issue,
                        keyError: model.keyError,
                        retry: model.retryConnection,
                        addComputer: { showingEnrollment = true }
                    )
                } else {
                    PairedHomeView(model: model,
                                   isVisible: scenePhase == .active && !showingAbout && !showingEnrollment)
                }
            }
            .background(Color(uiColor: model.bluetooth.target == nil ? .systemBackground : .systemGroupedBackground))
            .navigationTitle("Unlock with iPhone®")
            .navigationBarTitleDisplayMode(.large)
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Menu {
                        Button("About", systemImage: "info.circle") { showingAbout = true }
                        if model.bluetooth.target != nil {
                            Button("Remove Paired PC", systemImage: "trash", role: .destructive) {
                                confirmingRemoval = true
                            }
                        }
                    } label: {
                        Image(systemName: "gear")
                    }
                    .accessibilityLabel("Settings")
                }
            }
            .navigationDestination(isPresented: $showingAbout) { AboutView(model: model) }
            .sheet(isPresented: $showingEnrollment) { EnrollmentView(model: model) }
            .alert("Remove Paired PC confirmation", isPresented: $confirmingRemoval) {
                Button("Remove \(model.bluetooth.target?.name ?? "")", role: .destructive) {
                    model.forgetComputer()
                    showingRemovalSuccess = true
                }
                Button("Cancel", role: .cancel) { }
            } message: {
                Text("Forget \(model.bluetooth.target?.name ?? "") on this iPhone? You must remove the iPhone authorization separately on Windows.")
            }
            .alert("Your paired PC has been removed from this iPhone.", isPresented: $showingRemovalSuccess) {
                Button("OK", role: .cancel) { }
            }
        }
    }
}

private struct UnpairedHomeView: View {
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

#Preview {
    ContentView(model: UnlockSetupModel.shared)
}
