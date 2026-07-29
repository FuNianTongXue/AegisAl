import SwiftUI

enum LanguagePickerMenuVariant {
    case sidebar
    case settings
}

struct LanguagePickerMenu: View {
    @EnvironmentObject private var model: AppModel

    var compact = false
    var variant: LanguagePickerMenuVariant = .settings

    private var foreground: Color {
        switch variant {
        case .sidebar: AppPalette.onBrand
        case .settings: AppPalette.text
        }
    }

    private var muted: Color {
        switch variant {
        case .sidebar: AppPalette.onBrandMuted
        case .settings: AppPalette.textMuted
        }
    }

    private var background: Color {
        switch variant {
        case .sidebar: Color.white.opacity(0.09)
        case .settings: AppPalette.cardMuted
        }
    }

    private var stroke: Color {
        switch variant {
        case .sidebar: Color.white.opacity(0.14)
        case .settings: AppPalette.border.opacity(0.86)
        }
    }

    var body: some View {
        Menu {
            ForEach(AppLanguage.allCases) { language in
                Button {
                    model.setLanguage(language)
                } label: {
                    Label(
                        language.displayName,
                        systemImage: language == model.appLanguage ? "checkmark.circle.fill" : "circle"
                    )
                }
            }
        } label: {
            HStack(spacing: compact ? 0 : 9) {
                Image(systemName: "globe")
                    .font(AppTypography.system(size: 14, weight: .semibold))
                    .foregroundStyle(AppPalette.primary)
                    .frame(width: compact ? 30 : 24, height: compact ? 30 : 24)
                    .background(AppPalette.primary.opacity(0.14))
                    .clipShape(RoundedRectangle(cornerRadius: compact ? 8 : 7, style: .continuous))

                if !compact {
                    VStack(alignment: .leading, spacing: 1) {
                        Text(model.text(.interfaceLanguage))
                            .font(AppTypography.caption2.weight(.semibold))
                            .foregroundStyle(muted)
                        Text(model.appLanguage.displayName)
                            .font(AppTypography.caption.weight(.semibold))
                            .foregroundStyle(foreground)
                            .lineLimit(1)
                    }

                    Spacer(minLength: 0)

                    Image(systemName: "chevron.up.chevron.down")
                        .font(AppTypography.system(size: 10, weight: .bold))
                        .foregroundStyle(muted)
                }
            }
            .padding(.horizontal, compact ? 0 : 10)
            .frame(width: compact ? 36 : nil, height: compact ? 36 : 44, alignment: .leading)
            .frame(maxWidth: compact ? 36 : .infinity, alignment: .leading)
            .background(background)
            .clipShape(RoundedRectangle(cornerRadius: compact ? 10 : 12, style: .continuous))
            .overlay {
                RoundedRectangle(cornerRadius: compact ? 10 : 12, style: .continuous)
                    .stroke(stroke)
            }
            .contentShape(RoundedRectangle(cornerRadius: compact ? 10 : 12, style: .continuous))
        }
        .menuStyle(.borderlessButton)
        .buttonStyle(.plain)
        .tint(variant == .sidebar ? AppPalette.onBrand : AppPalette.text)
        .help(model.text(.languageHint))
        .accessibilityLabel(model.text(.interfaceLanguage))
    }
}
