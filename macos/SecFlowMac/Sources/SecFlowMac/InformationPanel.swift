import AppKit
import SwiftUI

enum InformationPanelMetrics {
    static let defaultSize = NSSize(width: 340, height: 650)
    static let screenMargin: CGFloat = 8
    static let menuBarOverlap: CGFloat = 5
    static let statusItemAutosaveName = "ai.secflow.knowledge-assistant.information"
}

func informationPanelFrame(
    visibleFrame: NSRect,
    panelSize: NSSize = InformationPanelMetrics.defaultSize,
    margin: CGFloat = InformationPanelMetrics.screenMargin
) -> NSRect {
    NSRect(
        x: visibleFrame.maxX - panelSize.width - margin,
        y: visibleFrame.maxY - panelSize.height - margin,
        width: panelSize.width,
        height: panelSize.height
    )
}

func informationPopoverFrame(
    visibleFrame: NSRect,
    buttonFrame: NSRect,
    panelSize: NSSize = InformationPanelMetrics.defaultSize,
    margin: CGFloat = InformationPanelMetrics.screenMargin
) -> NSRect {
    let idealX = buttonFrame.midX - panelSize.width / 2
    let minimumX = visibleFrame.minX + margin
    let maximumX = visibleFrame.maxX - panelSize.width - margin
    let x = min(max(idealX, minimumX), maximumX)
    let idealY = buttonFrame.minY - panelSize.height + InformationPanelMetrics.menuBarOverlap
    let y = max(visibleFrame.minY + margin, idealY)
    return NSRect(origin: NSPoint(x: x, y: y), size: panelSize)
}

@MainActor
final class InformationPanelPresenter: NSObject, ObservableObject, NSWindowDelegate {
    private(set) var panel: NSPanel?
    private var statusItem: NSStatusItem?
    private weak var model: AppModel?
    private var screenParametersObserver: NSObjectProtocol?

    deinit {
        if let screenParametersObserver {
            NotificationCenter.default.removeObserver(screenParametersObserver)
        }
        if let statusItem {
            NSStatusBar.system.removeStatusItem(statusItem)
        }
    }

    func configure(model: AppModel) {
        self.model = model
        guard statusItem == nil else { return }
        let statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
        statusItem.autosaveName = InformationPanelMetrics.statusItemAutosaveName
        if let button = statusItem.button {
            let image = NSImage(systemSymbolName: "newspaper.fill", accessibilityDescription: model.text(.navInformation))
            image?.isTemplate = true
            button.image = image
            button.imagePosition = .imageOnly
            button.toolTip = model.text(.navInformation)
            button.target = self
            button.action = #selector(togglePanelFromStatusItem)
            button.sendAction(on: [.leftMouseUp])
        }
        self.statusItem = statusItem
    }

    func show(model: AppModel) {
        configure(model: model)
        let targetPanel: NSPanel
        if let panel {
            targetPanel = panel
        } else {
            targetPanel = makePanel(model: model)
            panel = targetPanel
        }

        targetPanel.title = model.text(.navInformation)
        position(targetPanel)
        targetPanel.orderFrontRegardless()
        statusItem?.button?.state = .on
    }

    func close() {
        panel?.close()
        statusItem?.button?.state = .off
    }

    @objc private func togglePanelFromStatusItem() {
        if panel?.isVisible == true {
            close()
        } else if let model {
            show(model: model)
        }
    }

    func makePanel(model: AppModel) -> NSPanel {
        let panel = SecFlowInformationPanel(
            contentRect: NSRect(origin: .zero, size: InformationPanelMetrics.defaultSize),
            styleMask: [.borderless, .nonactivatingPanel],
            backing: .buffered,
            defer: false
        )
        panel.title = model.text(.navInformation)
        panel.contentMinSize = InformationPanelMetrics.defaultSize
        panel.contentMaxSize = InformationPanelMetrics.defaultSize
        panel.isReleasedWhenClosed = false
        panel.isFloatingPanel = true
        panel.hidesOnDeactivate = false
        panel.level = .floating
        panel.animationBehavior = .utilityWindow
        panel.collectionBehavior = [.canJoinAllSpaces, .stationary, .fullScreenAuxiliary]
        panel.becomesKeyOnlyIfNeeded = true
        panel.isMovable = false
        panel.isMovableByWindowBackground = false
        panel.isOpaque = false
        panel.backgroundColor = .clear
        panel.hasShadow = true
        panel.delegate = self

        let rootView = InformationPopoverView { [weak panel] in
            panel?.close()
        }
            .environmentObject(model)
            .overlay {
                TrialStatusBlocker(status: model.trialStatus)
            }
            .appAppearance(model: model)
            .environment(\.locale, model.appLanguage.locale)
            .appTypography()
            .tint(AppPalette.primary)
        panel.contentViewController = NSHostingController(rootView: rootView)

        position(panel)
        observeScreenChanges()
        return panel
    }

    private func position(_ panel: NSPanel) {
        let buttonFrame: NSRect? = statusItem?.button.flatMap { button in
            guard let window = button.window else { return nil }
            let frameInWindow = button.convert(button.bounds, to: nil)
            return window.convertToScreen(frameInWindow)
        }
        guard let screen = statusItem?.button?.window?.screen ?? NSScreen.main ?? NSScreen.screens.first else {
            return
        }
        let frame: NSRect
        if let buttonFrame {
            frame = informationPopoverFrame(visibleFrame: screen.visibleFrame, buttonFrame: buttonFrame)
        } else {
            frame = informationPanelFrame(visibleFrame: screen.visibleFrame)
        }
        panel.setFrame(
            frame,
            display: panel.isVisible,
            animate: false
        )
    }

    private func observeScreenChanges() {
        guard screenParametersObserver == nil else { return }
        screenParametersObserver = NotificationCenter.default.addObserver(
            forName: NSApplication.didChangeScreenParametersNotification,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            Task { @MainActor [weak self] in
                guard let self, let panel = self.panel else { return }
                self.position(panel)
            }
        }
    }

    private func stopObservingScreenChanges() {
        guard let screenParametersObserver else { return }
        NotificationCenter.default.removeObserver(screenParametersObserver)
        self.screenParametersObserver = nil
    }

    func windowWillClose(_ notification: Notification) {
        guard let closingPanel = notification.object as? NSPanel, closingPanel === panel else { return }
        stopObservingScreenChanges()
        closingPanel.contentViewController = nil
        panel = nil
        statusItem?.button?.state = .off
    }
}

private final class SecFlowInformationPanel: NSPanel {
    override var canBecomeKey: Bool { true }
    override var canBecomeMain: Bool { false }
}
