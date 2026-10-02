// Created by Rui MA on 26 Sep 2026

import SwiftUI
import UIKit

@MainActor
final class UnlockAppDelegate: NSObject, UIApplicationDelegate {
    func application(_ application: UIApplication,
                     didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil) -> Bool {
        _ = UnlockSetupModel.shared
        return true
    }
}

@main
struct MyApp: App {
    @UIApplicationDelegateAdaptor(UnlockAppDelegate.self) private var appDelegate
    @Environment(\.scenePhase) private var scenePhase

    var body: some Scene {
        WindowGroup {
            ContentView(model: UnlockSetupModel.shared)
        }
        .onChange(of: scenePhase, initial: true) { _, phase in
            UnlockSetupModel.shared.setForeground(phase == .active)
        }
    }
}
