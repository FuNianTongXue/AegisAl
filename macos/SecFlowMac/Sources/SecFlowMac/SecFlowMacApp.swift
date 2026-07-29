import AppKit
import SwiftUI

private enum WeChatLikeWindowMetrics {
    static let defaultSize = CGSize(width: 1100, height: 720)
    static let minSize = CGSize(width: 960, height: 620)
    static let cornerRadius: CGFloat = 12
}

@MainActor
final class SecFlowAppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.appearance = nil
    }

    func applicationWillTerminate(_ notification: Notification) {
        LocalBackendManager.shared.stop()
    }
}

@main
struct SecFlowMacApp: App {
    @NSApplicationDelegateAdaptor(SecFlowAppDelegate.self) private var appDelegate
    @StateObject private var model = AppModel()
    @StateObject private var informationPanel = InformationPanelPresenter()
    @StateObject private var workspaceNavigation = WorkspaceNavigationModel()
    @StateObject private var dashboardWindow = DashboardWindowPresenter()

    var body: some Scene {
        WindowGroup("") {
            RootView()
                .environmentObject(model)
                .environmentObject(informationPanel)
                .environmentObject(workspaceNavigation)
                .appAppearance(model: model)
                .environment(\.locale, model.appLanguage.locale)
                .appTypography()
                .tint(AppPalette.primary)
                .frame(
                    minWidth: WeChatLikeWindowMetrics.minSize.width,
                    minHeight: WeChatLikeWindowMetrics.minSize.height
                )
                .background(WeChatLikeWindowConfigurator())
                .onAppear {
                    informationPanel.configure(model: model)
                    synchronizeInformationPanel(authenticated: model.isAuthenticated)
                }
                .onChange(of: model.isAuthenticated) { _, authenticated in
                    synchronizeInformationPanel(authenticated: authenticated)
                }
        }
        .defaultSize(
            width: WeChatLikeWindowMetrics.defaultSize.width,
            height: WeChatLikeWindowMetrics.defaultSize.height
        )
        .windowStyle(.hiddenTitleBar)
        .windowToolbarStyle(.unifiedCompact)
        .commands {
            CommandGroup(replacing: .newItem) {
                Button {
                    model.startNewAssistantConversation()
                    workspaceNavigation.startNewTask()
                    NSApp.activate(ignoringOtherApps: true)
                } label: {
                    Label(
                        WorkspaceSidebarItem.newTask.title(model.appLanguage),
                        systemImage: WorkspaceSidebarItem.newTask.icon
                    )
                }
                .keyboardShortcut("n", modifiers: .command)
                .disabled(!model.isAuthenticated)
            }

            CommandGroup(after: .appInfo) {
                Button {
                    informationPanel.show(model: model)
                } label: {
                    Label(model.text(.navInformation), systemImage: "newspaper")
                }
                .keyboardShortcut("i", modifiers: [.command, .shift])
                .disabled(!model.isAuthenticated)

                Divider()

                Button(model.text(.refreshData)) {
                    Task { await model.refreshAll() }
                }
                .keyboardShortcut("r", modifiers: .command)
            }

            CommandGroup(before: .appSettings) {
                Button {
                    dashboardWindow.show(model: model, informationPanel: informationPanel)
                } label: {
                    Label(model.text(.navOverview), systemImage: "square.grid.2x2")
                }
                .keyboardShortcut("1", modifiers: .command)
                .disabled(!model.isAuthenticated)
            }
        }

        Settings {
            SettingsView()
                .environmentObject(model)
                .overlay {
                    TrialStatusBlocker(status: model.trialStatus)
                }
                .appAppearance(model: model)
                .environment(\.locale, model.appLanguage.locale)
                .appTypography()
                .tint(AppPalette.primary)
                .frame(
                    width: SettingsWindowMetrics.defaultSize.width,
                    height: SettingsWindowMetrics.defaultSize.height
                )
        }
    }

    private func synchronizeInformationPanel(authenticated: Bool) {
        if authenticated {
            informationPanel.show(model: model)
        } else {
            informationPanel.close()
            dashboardWindow.close()
        }
    }
}

private struct WeChatLikeWindowConfigurator: NSViewRepresentable {
    func makeCoordinator() -> Coordinator {
        Coordinator()
    }

    func makeNSView(context: Context) -> NSView {
        let view = NSView()
        DispatchQueue.main.async {
            configure(view.window)
            context.coordinator.observeTitleChanges(in: view.window)
        }
        return view
    }

    func updateNSView(_ nsView: NSView, context: Context) {
        DispatchQueue.main.async {
            configure(nsView.window)
            context.coordinator.observeTitleChanges(in: nsView.window)
        }
    }

    private func configure(_ window: NSWindow?) {
        guard let window else { return }
        window.styleMask.insert(.resizable)
        window.styleMask.insert(.fullSizeContentView)
        clearNativeWindowTitle(window)
        window.titleVisibility = .hidden
        window.titlebarAppearsTransparent = true
        window.titlebarSeparatorStyle = .none
        window.isOpaque = false
        window.backgroundColor = .clear
        window.hasShadow = true
        window.isMovableByWindowBackground = false
        window.minSize = NSSize(
            width: WeChatLikeWindowMetrics.minSize.width,
            height: WeChatLikeWindowMetrics.minSize.height
        )
        window.resizeIncrements = NSSize(width: 1, height: 1)
        window.collectionBehavior.insert(.fullScreenPrimary)
        window.contentView?.wantsLayer = true
        window.contentView?.layer?.backgroundColor = NSColor.clear.cgColor
        window.contentView?.layer?.cornerRadius = WeChatLikeWindowMetrics.cornerRadius
        window.contentView?.layer?.cornerCurve = .continuous
        window.contentView?.layer?.masksToBounds = true

        DispatchQueue.main.async {
            clearNativeWindowTitle(window)
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.15) {
            clearNativeWindowTitle(window)
        }
    }

    final class Coordinator {
        private weak var observedWindow: NSWindow?
        private var titleObservation: NSKeyValueObservation?

        func observeTitleChanges(in window: NSWindow?) {
            guard let window, observedWindow !== window else { return }
            observedWindow = window
            titleObservation = window.observe(\.title, options: [.new]) { window, change in
                guard !(change.newValue ?? "").isEmpty else { return }
                DispatchQueue.main.async {
                    clearNativeWindowTitle(window)
                }
            }
        }
    }
}

func clearNativeWindowTitle(_ window: NSWindow) {
    window.title = ""
    window.subtitle = ""
    window.representedURL = nil
    window.titleVisibility = .hidden

    if let titlebarView = window.standardWindowButton(.closeButton)?.superview {
        hideTitleTextFields(in: titlebarView)
    }

    if let frameView = window.contentView?.superview {
        for subview in frameView.subviews where String(describing: type(of: subview)).contains("Titlebar") {
            hideTitleTextFields(in: subview)
        }
    }
}

private func hideTitleTextFields(in view: NSView) {
    if let textField = view as? NSTextField {
        textField.stringValue = ""
        textField.isHidden = true
        textField.alphaValue = 0
    }
    view.subviews.forEach(hideTitleTextFields)
}
