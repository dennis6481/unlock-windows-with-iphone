import SwiftUI

struct ContentView: View {
    @State private var model = UnlockSetupModel()

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
                        signTestChallenge: model.signTestChallenge
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
            Text("此阶段验证 Secure Enclave 私钥、AfterFirstUnlockThisDeviceOnly 和 challenge 签名链路。BLE 尚未接入。")
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

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Button("准备密钥", action: prepareKey)
                .buttonStyle(.borderedProminent)
            Button("执行本地签名测试", action: signTestChallenge)
                .buttonStyle(.bordered)
        }
    }
}

private struct ScopeSection: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("当前明确未实现")
                .font(.headline)
            Text("Windows GATT Server、iPhone 后台 BLE 会话、Credential Provider、LSA Authentication Package 和自动解锁。认证失败不会静默退回软件密钥。")
                .foregroundStyle(.secondary)
        }
    }
}

#Preview {
    ContentView()
}
