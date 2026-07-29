import SwiftUI

struct RootView: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        VStack(spacing: 0) {
            TrialStatusBanner(status: model.trialStatus)
            appContent
        }
        .overlay {
            TrialStatusBlocker(status: model.trialStatus)
        }
        .task {
            await model.refreshTrialStatus()
            await model.runTrialStatusLoop()
        }
    }

    @ViewBuilder
    private var appContent: some View {
        if !model.isAuthenticated {
            AuthView()
        } else {
            switch model.initialSetupState {
            case .loading:
                InitialSetupLoadingView()
                    .task { await model.refreshAll() }
            case .required:
                PostLoginSetupView()
            case .ready:
                workspace
            case let .failed(message):
                InitialSetupFailureView(message: message)
            }
        }
    }

    private var workspace: some View {
        WorkspaceShellView()
    }
}

private struct TrialStatusBanner: View {
    let status: TrialStatusSnapshot?

    var body: some View {
        if let status, status.enabled {
            TimelineView(.periodic(from: .now, by: 1)) { context in
                if status.isUsable(at: context.date) {
                    HStack(spacing: 10) {
                        Image(systemName: "clock.badge.exclamationmark")
                            .font(AppTypography.system(size: 13, weight: .semibold))
                        Text("\(status.durationLabel)试用版")
                            .font(AppTypography.caption.weight(.semibold))
                        Spacer(minLength: 12)
                        Text("剩余 \(countdown(status.remainingSeconds(at: context.date)))")
                            .font(AppTypography.caption.monospaced().weight(.semibold))
                    }
                    .foregroundStyle(Color(red: 0.46, green: 0.25, blue: 0.03))
                    .padding(.horizontal, 16)
                    .frame(maxWidth: .infinity, minHeight: 34)
                    .background(Color(red: 1.0, green: 0.95, blue: 0.82))
                    .overlay(alignment: .bottom) {
                        Rectangle()
                            .fill(Color(red: 0.85, green: 0.62, blue: 0.18).opacity(0.45))
                            .frame(height: 1)
                    }
                }
            }
        }
    }

    private func countdown(_ totalSeconds: Int) -> String {
        let days = totalSeconds / 86_400
        let hours = (totalSeconds % 86_400) / 3_600
        let minutes = (totalSeconds % 3_600) / 60
        let seconds = totalSeconds % 60
        return String(format: "%d天 %02d:%02d:%02d", days, hours, minutes, seconds)
    }
}

struct TrialStatusBlocker: View {
    let status: TrialStatusSnapshot?

    var body: some View {
        if let status, status.enabled {
            TimelineView(.periodic(from: .now, by: 1)) { context in
                TrialBlockedContent(status: status, date: context.date)
            }
        }
    }
}

private struct TrialBlockedContent: View {
    let status: TrialStatusSnapshot
    let date: Date

    var body: some View {
        if !status.isUsable(at: date) {
            ZStack {
                AppPalette.page.opacity(0.98)
                VStack(spacing: 16) {
                    Image(systemName: status.state == "expired" ? "clock.badge.xmark.fill" : "exclamationmark.shield.fill")
                        .font(AppTypography.system(size: 42, weight: .semibold))
                        .foregroundStyle(AppPalette.danger)
                    Text(status.state == "expired" ? "\(status.durationLabel)试用已结束" : "试用授权不可用")
                        .font(AppTypography.title2.weight(.bold))
                        .foregroundStyle(AppPalette.text)
                    Text(status.message)
                        .font(AppTypography.callout)
                        .foregroundStyle(AppPalette.textMuted)
                        .multilineTextAlignment(.center)
                        .frame(maxWidth: 520)
                    if let started = status.startedDate, let expires = status.expirationDate {
                        VStack(spacing: 8) {
                            trialDateRow("首次启动", started)
                            trialDateRow("到期时间", expires)
                        }
                        .padding(14)
                        .frame(width: 420)
                        .background(AppPalette.card)
                        .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
                        .overlay {
                            RoundedRectangle(cornerRadius: 8, style: .continuous)
                                .stroke(AppPalette.border)
                        }
                    }
                }
                .padding(32)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        } else {
            Color.clear
                .frame(width: 0, height: 0)
                .allowsHitTesting(false)
        }
    }

    private func trialDateRow(_ label: String, _ date: Date) -> some View {
        HStack {
            Text(label)
                .foregroundStyle(AppPalette.textMuted)
            Spacer()
            Text(date.formatted(date: .numeric, time: .standard))
                .foregroundStyle(AppPalette.text)
                .monospacedDigit()
        }
        .font(AppTypography.caption)
    }
}

private struct InitialSetupLoadingView: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        VStack(spacing: 14) {
            ProgressView()
                .controlSize(.large)
            Text(model.text(.setupChecking))
                .font(AppTypography.headline)
                .foregroundStyle(AppPalette.text)
            Text(model.text(.setupCheckingSubtitle))
                .font(AppTypography.callout)
                .foregroundStyle(AppPalette.textMuted)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(AppPalette.page)
    }
}

private struct InitialSetupFailureView: View {
    @EnvironmentObject private var model: AppModel
    let message: String

    var body: some View {
        VStack(spacing: 16) {
            Image(systemName: "exclamationmark.triangle.fill")
                .font(AppTypography.system(size: 30))
                .foregroundStyle(AppPalette.warning)
            Text(model.text(.setupFailed))
                .font(AppTypography.title3.weight(.semibold))
                .foregroundStyle(AppPalette.text)
            Text(message)
                .font(AppTypography.callout)
                .foregroundStyle(AppPalette.textMuted)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 520)
            Button {
                model.initialSetupState = .loading
            } label: {
                Label(model.text(.retry), systemImage: "arrow.clockwise")
            }
            .buttonStyle(PrimaryActionButtonStyle())
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(AppPalette.page)
    }
}
