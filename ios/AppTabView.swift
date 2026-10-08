// Created by Rui MA on 08 Oct 2026

import SwiftUI

struct AppTabView: View {
    let model: UnlockSetupModel
    @Environment(\.scenePhase) private var scenePhase
    @State private var selectedTab = AppTab.home
    @State private var showingEnrollment = false
    @State private var confirmingRemoval = false
    @State private var showingRemovalSuccess = false

    var body: some View {
        TabView(selection: $selectedTab) {
            Tab("Home", systemImage: "house", value: .home) {
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
                            PairedHomeView(
                                model: model,
                                isVisible: scenePhase == .active && selectedTab == .home && !showingEnrollment
                            )
                        }
                    }
                    .background(
                        Color(uiColor: model.bluetooth.target == nil ? .systemBackground : .systemGroupedBackground)
                    )
                    .navigationTitle("Unlock with iPhone®")
                    .navigationBarTitleDisplayMode(.large)
                    .toolbar {
                        ToolbarItem(placement: .topBarTrailing) {
                            if model.bluetooth.target != nil {
                                Menu {
                                    Button("Remove Paired PC", systemImage: "trash", role: .destructive) {
                                        confirmingRemoval = true
                                    }
                                } label: {
                                    Image(systemName: "ellipsis")
                                }
                                .accessibilityLabel("More")
                            }
                        }
                    }
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

            Tab("Settings", systemImage: "gear", value: .settings) {
                NavigationStack {
                    SettingsView(model: model)
                }
            }
        }
    }
}

private enum AppTab: Hashable {
    case home
    case settings
}

#Preview {
    AppTabView(model: UnlockSetupModel.shared)
}
