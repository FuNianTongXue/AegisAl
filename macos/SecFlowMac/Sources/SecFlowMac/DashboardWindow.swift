import AppKit
import SwiftUI

enum DashboardWindowMetrics {
    static let defaultSize = NSSize(width: 1180, height: 780)
    static let minSize = NSSize(width: 900, height: 640)
    static let autosaveName = "ai.secflow.knowledge-assistant.dashboard"
}

@MainActor
final class DashboardWindowPresenter: NSObject, ObservableObject, NSWindowDelegate {
    private(set) var window: NSWindow?

    func show(model: AppModel, informationPanel: InformationPanelPresenter) {
        let targetWindow: NSWindow
        if let window {
            targetWindow = window
        } else {
            targetWindow = makeWindow(model: model, informationPanel: informationPanel)
            window = targetWindow
        }

        targetWindow.title = model.text(.navOverview)
        targetWindow.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    func close() {
        window?.close()
    }

    func makeWindow(model: AppModel, informationPanel: InformationPanelPresenter) -> NSWindow {
        let window = NSWindow(
            contentRect: NSRect(origin: .zero, size: DashboardWindowMetrics.defaultSize),
            styleMask: [.titled, .closable, .miniaturizable, .resizable, .fullSizeContentView],
            backing: .buffered,
            defer: false
        )
        window.title = model.text(.navOverview)
        window.titleVisibility = .hidden
        window.titlebarAppearsTransparent = true
        window.isReleasedWhenClosed = false
        window.minSize = DashboardWindowMetrics.minSize
        window.contentMinSize = DashboardWindowMetrics.minSize
        window.collectionBehavior.insert(.fullScreenPrimary)
        window.setFrameAutosaveName(DashboardWindowMetrics.autosaveName)
        window.delegate = self

        let rootView = DashboardView()
            .environmentObject(model)
            .environmentObject(informationPanel)
            .overlay {
                TrialStatusBlocker(status: model.trialStatus)
            }
            .appAppearance(model: model)
            .environment(\.locale, model.appLanguage.locale)
            .appTypography()
            .tint(AppPalette.primary)
        window.contentViewController = NSHostingController(rootView: rootView)
        window.center()
        return window
    }

    func windowWillClose(_ notification: Notification) {
        guard let closingWindow = notification.object as? NSWindow, closingWindow === window else { return }
        closingWindow.contentViewController = nil
        window = nil
    }
}
