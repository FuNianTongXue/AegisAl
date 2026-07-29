import AppKit
import SwiftUI

enum AppBrand {
    static let chineseName = "安全智脑"
    static let englishName = "SecFlow AI"
    static let subtitle = "Security AI Assistant"
    static let fallbackVersion = "1.2.0"
    static let releaseChannel = "内测版"

    static var version: String {
        if let bundleVersion = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String {
            let clean = bundleVersion.trimmingCharacters(in: .whitespacesAndNewlines)
            if !clean.isEmpty {
                return clean
            }
        }
        return fallbackVersion
    }

    static var versionLabel: String {
        "v\(version) \(releaseChannel)"
    }
}

struct AppBrandLogo: View {
    let size: CGFloat
    var shadow: Bool = true

    var body: some View {
        ZStack {
            RoundedRectangle(cornerRadius: size * 0.22, style: .continuous)
                .fill(
                    LinearGradient(
                        colors: [AppPalette.brandNavy, AppPalette.brandCyan],
                        startPoint: .topLeading,
                        endPoint: .bottomTrailing
                    )
                )
                .overlay {
                    RoundedRectangle(cornerRadius: size * 0.22, style: .continuous)
                        .stroke(Color.white.opacity(0.18), lineWidth: max(1, size * 0.025))
                }

            ZStack {
                Image(systemName: "shield")
                    .font(.system(size: size * 0.49, weight: .bold))
                    .foregroundStyle(.white)
                Image(systemName: "star.fill")
                    .font(.system(size: size * 0.17, weight: .bold))
                    .foregroundStyle(.white)
                    .offset(y: -size * 0.015)
            }
            .symbolRenderingMode(.monochrome)
        }
        .frame(width: size, height: size)
        .shadow(color: shadow ? AppPalette.primary.opacity(0.22) : .clear, radius: shadow ? size * 0.15 : 0, y: shadow ? size * 0.06 : 0)
        .accessibilityHidden(true)
    }
}

struct AppUserAvatar: View {
    let displayName: String
    let imageData: Data?
    var size: CGFloat = 36

    var body: some View {
        ZStack {
            Circle()
                .fill(
                    LinearGradient(
                        colors: [AppPalette.primary, AppPalette.primaryStrong],
                        startPoint: .topLeading,
                        endPoint: .bottomTrailing
                    )
                )
            if let imageData, let image = NSImage(data: imageData) {
                Image(nsImage: image)
                    .resizable()
                    .scaledToFill()
                    .frame(width: size, height: size)
                    .clipShape(Circle())
            } else {
                Text(initial)
                    .font(.system(size: size * 0.4, weight: .bold))
                    .foregroundStyle(.white)
            }
        }
        .frame(width: size, height: size)
        .overlay(Circle().stroke(Color.white.opacity(0.3), lineWidth: 1))
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(displayName)
        .accessibilityIdentifier("app-user-avatar")
    }

    private var initial: String {
        let cleanName = displayName.trimmingCharacters(in: .whitespacesAndNewlines)
        return cleanName.first.map(String.init) ?? "安"
    }
}
