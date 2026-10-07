// Created by Rui MA on 07 Oct 2026

import SwiftUI

struct SetupSheetPage<Content: View>: View {
    let title: LocalizedStringResource
    let description: LocalizedStringResource
    let symbol: String
    var color: Color = .accentColor
    var multicolor = false
    let buttonTitle: LocalizedStringResource
    var disabled = false
    var destructive = false
    let action: () -> Void
    var secondaryAction: (title: LocalizedStringResource, disabled: Bool, action: () -> Void)? = nil
    @ViewBuilder let content: () -> Content

    var body: some View {
        VStack(spacing: 0) {
            ScrollView {
                VStack(alignment: .leading, spacing: 24) {
                    SetupSheetHeader(title: title, description: description, symbol: symbol,
                                     color: color, multicolor: multicolor)
                    content()
                }
                .padding(24)
                .frame(maxWidth: 600)
                .frame(maxWidth: .infinity)
            }
            SetupSheetActions(buttonTitle: buttonTitle, disabled: disabled,
                              destructive: destructive, action: action,
                              secondaryAction: secondaryAction)
                .padding(.horizontal, 24)
                .padding(.bottom, 24)
        }
        .background(Color(uiColor: .systemBackground))
    }

}

private struct SetupSheetActions: View {
    let buttonTitle: LocalizedStringResource
    let disabled: Bool
    let destructive: Bool
    let action: () -> Void
    let secondaryAction: (title: LocalizedStringResource, disabled: Bool, action: () -> Void)?

    var body: some View {
        VStack(spacing: 12) {
            if destructive {
                Button(role: .destructive, action: action) { Text(buttonTitle) }
                    .buttonSizing(.flexible)
                    .buttonStyle(.glass)
                    .controlSize(.large)
                    .tint(.red)
                    .disabled(disabled)
            } else {
                Button(action: action) { Text(buttonTitle) }
                    .buttonSizing(.flexible)
                    .buttonStyle(.glassProminent)
                    .controlSize(.large)
                    .disabled(disabled)
            }
            if let secondaryAction {
                Button(action: secondaryAction.action) { Text(secondaryAction.title) }
                    .buttonSizing(.flexible)
                    .buttonStyle(.glass)
                    .controlSize(.large)
                    .disabled(secondaryAction.disabled)
            }
        }
    }
}

private struct SetupSheetHeader: View {
    let title: LocalizedStringResource
    let description: LocalizedStringResource
    let symbol: String
    let color: Color
    let multicolor: Bool
    @ScaledMetric(relativeTo: .largeTitle) private var illustrationSize = 150

    var body: some View {
        VStack(alignment: .leading, spacing: 24) {
            Group {
                if multicolor {
                    Image(systemName: symbol).symbolRenderingMode(.multicolor)
                } else {
                    Image(systemName: symbol).symbolRenderingMode(.monochrome).foregroundStyle(color)
                }
            }
            .font(.system(size: illustrationSize, weight: .regular))
            .frame(maxWidth: .infinity)
            .padding(.vertical, 28)
            .accessibilityHidden(true)
            Text(title).font(.largeTitle.bold()).fixedSize(horizontal: false, vertical: true)
            Text(description).font(.title3).foregroundStyle(.secondary)
        }
    }
}
