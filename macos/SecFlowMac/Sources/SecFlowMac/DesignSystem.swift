import AppKit
import SwiftUI

enum AppInterfaceFontSize: String, CaseIterable, Identifiable {
    case small
    case `default`
    case large

    var id: String { rawValue }

    var dynamicTypeSize: DynamicTypeSize {
        switch self {
        case .small: .large
        case .default: .xLarge
        case .large: .xxLarge
        }
    }

    var scale: CGFloat {
        switch self {
        case .small: 0.9
        case .default: 1.0
        case .large: 1.12
        }
    }

    static func resolve(_ value: String?) -> AppInterfaceFontSize {
        AppInterfaceFontSize(rawValue: String(value ?? "").trimmingCharacters(in: .whitespacesAndNewlines)) ?? .default
    }
}

struct AppAppearancePreferences: Equatable {
    static let darkModeKey = "secflow.appearance.darkMode"
    static let fontSizeKey = "secflow.appearance.fontSize"

    let darkMode: Bool
    let fontSize: AppInterfaceFontSize

    static func load(defaults: UserDefaults = .standard) -> AppAppearancePreferences {
        AppAppearancePreferences(
            darkMode: defaults.bool(forKey: darkModeKey),
            fontSize: AppInterfaceFontSize.resolve(defaults.string(forKey: fontSizeKey))
        )
    }

    func persist(defaults: UserDefaults = .standard) {
        defaults.set(darkMode, forKey: Self.darkModeKey)
        defaults.set(fontSize.rawValue, forKey: Self.fontSizeKey)
    }
}

enum AppTypography {
    static let latinFamily = "SF Pro Text"
    static let simplifiedChineseFamily = "PingFang SC"
    static let emojiFamily = "Apple Color Emoji"
    static let webFontFamily =
        "\"SF Pro Text\", \"PingFang SC\", \"Apple Color Emoji\", -apple-system, BlinkMacSystemFont, sans-serif"

    // The macOS system font provides the native SF Pro -> PingFang SC ->
    // Apple Color Emoji glyph cascade while preserving semantic font metrics.
    static var body: Font { system(size: 15) }
    static var bodyMedium: Font { system(size: 15, weight: .medium) }
    static var sectionTitle: Font { system(size: 16, weight: .semibold) }
    static var pageTitle: Font { system(size: 22, weight: .semibold) }
    static var label: Font { system(size: 13, weight: .semibold) }
    static var caption: Font { system(size: 13) }
    static var caption2: Font { system(size: 11) }
    static var callout: Font { system(size: 14) }
    static var footnote: Font { system(size: 12) }
    static var headline: Font { system(size: 16, weight: .semibold) }
    static var subheadline: Font { system(size: 13) }
    static var title3: Font { system(size: 20, weight: .semibold) }
    static var title2: Font { system(size: 22, weight: .semibold) }
    static var title: Font { system(size: 28, weight: .semibold) }
    static var largeTitle: Font { system(size: 34, weight: .semibold) }
    static var metric: Font { system(size: 30, weight: .semibold) }
    static var sidebarBrandTitle: Font { system(size: 16, weight: .bold) }
    static var sidebarBrandSubtitle: Font { system(size: 13) }
    static var sidebarItem: Font { system(size: 14, weight: .semibold) }
    static var sidebarIdentity: Font { system(size: 13, weight: .semibold) }
    static var sidebarIdentityCaption: Font { system(size: 12) }

    private static var scale: CGFloat {
        AppAppearancePreferences.load().fontSize.scale
    }

    static func system(
        size: CGFloat,
        weight: Font.Weight = .regular,
        design: Font.Design = .default
    ) -> Font {
        .system(size: size * scale, weight: weight, design: design)
    }
}

enum AppPalette {
    static let brandNavy = Color(red: 15.0 / 255.0, green: 25.0 / 255.0, blue: 58.0 / 255.0)
    static let brandNavyDeep = Color(red: 10.0 / 255.0, green: 17.0 / 255.0, blue: 42.0 / 255.0)
    static let brandCyan = Color(red: 45.0 / 255.0, green: 170.0 / 255.0, blue: 206.0 / 255.0)
    static let onBrand = Color(red: 0.957, green: 0.973, blue: 0.996)
    static let onBrandMuted = Color(red: 0.733, green: 0.765, blue: 0.839)
    static let page = adaptiveColor(
        light: (0.933, 0.965, 0.988),
        dark: (0.027, 0.106, 0.184)
    )
    static let card = adaptiveColor(
        light: (0.973, 0.984, 0.996),
        dark: (0.051, 0.153, 0.259)
    )
    static let cardMuted = adaptiveColor(
        light: (0.898, 0.941, 0.973),
        dark: (0.082, 0.212, 0.325)
    )
    static let border = adaptiveColor(
        light: (0.788, 0.867, 0.929),
        dark: (0.165, 0.325, 0.447)
    )
    static let selected = primary.opacity(0.12)
    static let selectedStrong = adaptiveColor(
        light: (0.804, 0.906, 0.965),
        dark: (0.078, 0.290, 0.404)
    )
    static let text = Color(nsColor: .labelColor)
    static let textMuted = Color(nsColor: .secondaryLabelColor)
    static let textSubtle = Color(nsColor: .tertiaryLabelColor)
    static let sidebar = adaptiveColor(
        light: (0.843, 0.918, 0.969),
        dark: (0.043, 0.137, 0.251)
    )
    static let sidebarDeep = adaptiveColor(
        light: (0.765, 0.867, 0.941),
        dark: (0.024, 0.086, 0.165)
    )
    static let sidebarText = adaptiveColor(
        light: (0.090, 0.200, 0.306),
        dark: (0.949, 0.973, 0.996)
    )
    static let sidebarTextMuted = adaptiveColor(
        light: (0.325, 0.455, 0.573),
        dark: (0.667, 0.753, 0.835)
    )
    static let sidebarSelected = adaptiveColor(
        light: (0.659, 0.824, 0.929),
        dark: (0.094, 0.286, 0.431)
    )
    static let sidebarHover = adaptiveColor(
        light: (0.753, 0.875, 0.953),
        dark: (0.071, 0.216, 0.341)
    )
    static let sidebarDivider = adaptiveColor(
        light: (0.565, 0.714, 0.824),
        dark: (0.196, 0.357, 0.486)
    )
    static let windowBackground = Color(nsColor: .windowBackgroundColor)
    static let textBackground = Color(nsColor: .textBackgroundColor)
    static let controlBackground = Color(nsColor: .controlBackgroundColor)
    static let separator = Color(nsColor: .separatorColor)
    static let primary = brandCyan
    static let primaryStrong = Color(red: 21.0 / 255.0, green: 154.0 / 255.0, blue: 191.0 / 255.0)
    static let danger = Color(red: 0.957, green: 0.247, blue: 0.235)
    static let warning = Color(red: 0.965, green: 0.604, blue: 0.000)
    static let medium = Color(red: 0.929, green: 0.741, blue: 0.000)
    static let success = Color(red: 0.118, green: 0.769, blue: 0.357)
}

private func adaptiveColor(
    light: (CGFloat, CGFloat, CGFloat),
    dark: (CGFloat, CGFloat, CGFloat)
) -> Color {
    Color(
        nsColor: NSColor(name: nil) { appearance in
            let usesDark = appearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua
            let value = usesDark ? dark : light
            return NSColor(srgbRed: value.0, green: value.1, blue: value.2, alpha: 1)
        }
    )
}

private struct LiquidGlassSurfaceModifier: ViewModifier {
    let cornerRadius: CGFloat
    let tint: Color

    @ViewBuilder
    func body(content: Content) -> some View {
        if #available(macOS 26.0, *) {
            content
                .background(tint.opacity(0.08), in: RoundedRectangle(cornerRadius: cornerRadius, style: .continuous))
                .glassEffect(.regular, in: .rect(cornerRadius: cornerRadius))
        } else {
            content
                .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: cornerRadius, style: .continuous))
                .background(tint.opacity(0.08), in: RoundedRectangle(cornerRadius: cornerRadius, style: .continuous))
        }
    }
}

extension View {
    func appTypography() -> some View {
        font(AppTypography.body)
    }

    func appAppearance(model: AppModel) -> some View {
        modifier(AppAppearanceModifier(model: model))
    }

    func liquidGlassSurface(cornerRadius: CGFloat = 8, tint: Color = AppPalette.card) -> some View {
        modifier(LiquidGlassSurfaceModifier(cornerRadius: cornerRadius, tint: tint))
    }
}

private struct AppAppearanceModifier: ViewModifier {
    @ObservedObject var model: AppModel

    func body(content: Content) -> some View {
        content
            .preferredColorScheme(appColorScheme(darkMode: model.darkModeEnabled))
            .environment(\.dynamicTypeSize, model.interfaceFontSize.dynamicTypeSize)
    }
}

func appColorScheme(darkMode: Bool) -> ColorScheme {
    darkMode ? .dark : .light
}

struct SidebarGlassBackground: View {
    var body: some View {
        Rectangle()
            .fill(.ultraThinMaterial)
            .overlay {
                LinearGradient(
                    colors: [
                        AppPalette.sidebar.opacity(0.76),
                        AppPalette.sidebarDeep.opacity(0.58)
                    ],
                    startPoint: .topLeading,
                    endPoint: .bottomTrailing
                )
            }
            .overlay(AppPalette.primary.opacity(0.025))
            .overlay(alignment: .trailing) {
                Rectangle()
                    .fill(AppPalette.separator.opacity(0.46))
                    .frame(width: 1)
            }
    }
}

struct AppWorkspaceBackground: View {
    var body: some View {
        ZStack {
            AppPalette.textBackground
            AppPalette.page.opacity(0.72)
        }
    }
}

struct Panel<Content: View>: View {
    @ViewBuilder let content: Content

    init(@ViewBuilder content: () -> Content) {
        self.content = content()
    }

    var body: some View {
        content
            .padding(18)
            .foregroundStyle(AppPalette.text)
            .liquidGlassSurface(cornerRadius: 8)
            .overlay {
                RoundedRectangle(cornerRadius: 8, style: .continuous)
                    .stroke(AppPalette.border.opacity(0.82))
            }
            .shadow(color: Color.black.opacity(0.055), radius: 14, y: 5)
    }
}

struct StatusBadge: View {
    let text: String
    let tone: StatusTone

    var body: some View {
        Text(text)
            .font(AppTypography.caption.weight(.semibold))
            .foregroundStyle(tone.color)
            .padding(.horizontal, 8)
            .padding(.vertical, 4)
            .background(tone.color.opacity(0.12))
            .clipShape(Capsule())
    }
}

enum StatusTone {
    case good
    case warning
    case medium
    case critical
    case info
    case neutral

    var color: Color {
        switch self {
        case .good: AppPalette.success
        case .warning: AppPalette.warning
        case .medium: AppPalette.medium
        case .critical: AppPalette.danger
        case .info: AppPalette.primary
        case .neutral: AppPalette.textMuted
        }
    }

    static func severity(_ value: String) -> StatusTone {
        switch value.trimmingCharacters(in: .whitespacesAndNewlines).uppercased() {
        case "CRITICAL", "SEVERE", "严重": .critical
        case "HIGH", "高危": .warning
        case "MEDIUM", "MODERATE", "中危": .medium
        case "LOW", "低危": .info
        default: .neutral
        }
    }

    static func operation(_ value: String) -> StatusTone {
        switch value.lowercased() {
        case "success", "completed": .good
        case "warning": .warning
        case "failed", "error": .critical
        case "running": .info
        default: .neutral
        }
    }
}

struct PageHeader<Trailing: View>: View {
    let title: String
    let subtitle: String?
    @ViewBuilder let trailing: Trailing

    init(_ title: String, subtitle: String? = nil, @ViewBuilder trailing: () -> Trailing) {
        self.title = title
        self.subtitle = subtitle
        self.trailing = trailing()
    }

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 16) {
            VStack(alignment: .leading, spacing: 3) {
                Text(title).font(AppTypography.title2.weight(.semibold))
                    .foregroundStyle(AppPalette.text)
                if let subtitle {
                    Text(subtitle).font(AppTypography.callout).foregroundStyle(AppPalette.textMuted)
                }
            }
            Spacer()
            trailing
        }
    }
}

extension PageHeader where Trailing == EmptyView {
    init(_ title: String, subtitle: String? = nil) {
        self.init(title, subtitle: subtitle) { EmptyView() }
    }
}

struct TraceView: View {
    @EnvironmentObject private var model: AppModel
    let trace: [TraceItem]

    var body: some View {
        if trace.isEmpty {
            ContentUnavailableView(model.uiText("暂无执行记录"), systemImage: "point.3.connected.trianglepath.dotted")
        } else {
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 0) {
                    ForEach(Array(trace.enumerated()), id: \.element.id) { index, item in
                        HStack(alignment: .top, spacing: 11) {
                            VStack(spacing: 0) {
                                Circle()
                                    .fill(StatusTone.operation(item.status).color)
                                    .frame(width: 9, height: 9)
                                    .padding(.top, 5)
                                if index < trace.count - 1 {
                                    Rectangle()
                                        .fill(AppPalette.textSubtle.opacity(0.25))
                                        .frame(width: 1)
                                        .frame(minHeight: 42)
                                }
                            }
                            VStack(alignment: .leading, spacing: 4) {
                                HStack {
                                    Text(nodeLabel(item.node, language: model.appLanguage)).font(AppTypography.callout.weight(.semibold))
                                    Spacer()
                                    StatusBadge(text: statusLabel(item.status, language: model.appLanguage), tone: .operation(item.status))
                                }
                                Text(model.localizedMessage(item.message) ?? item.message).font(AppTypography.caption).foregroundStyle(AppPalette.textMuted)
                                if !item.time.isEmpty {
                                    Text(item.time).font(AppTypography.caption2.monospacedDigit()).foregroundStyle(AppPalette.textSubtle)
                                }
                            }
                            .padding(.bottom, 12)
                        }
                    }
                }
                .padding(2)
            }
        }
    }
}

struct ErrorBanner: View {
    @EnvironmentObject private var model: AppModel
    let message: String
    let dismiss: () -> Void

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.red)
            Text(message).font(AppTypography.callout).lineLimit(2).foregroundStyle(AppPalette.text)
            Spacer()
            Button(action: dismiss) { Image(systemName: "xmark") }
                .buttonStyle(.plain)
                .help(model.uiText("关闭"))
        }
        .padding(10)
        .background(Color.red.opacity(0.08))
        .clipShape(RoundedRectangle(cornerRadius: 6))
    }
}

struct PrimaryActionButtonStyle: ButtonStyle {
    @Environment(\.isEnabled) private var isEnabled

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(AppTypography.callout.weight(.semibold))
            .foregroundStyle(isEnabled ? Color.white : AppPalette.textSubtle)
            .padding(.horizontal, 13)
            .frame(height: 36)
            .background(
                isEnabled
                    ? (configuration.isPressed ? AppPalette.primaryStrong : AppPalette.primary)
                    : AppPalette.cardMuted
            )
            .clipShape(RoundedRectangle(cornerRadius: 7, style: .continuous))
            .overlay {
                if !isEnabled {
                    RoundedRectangle(cornerRadius: 7, style: .continuous)
                        .stroke(AppPalette.border)
                }
            }
            .shadow(
                color: isEnabled
                    ? AppPalette.primary.opacity(configuration.isPressed ? 0.08 : 0.16)
                    : .clear,
                radius: 8,
                y: 3
            )
    }
}

struct SecondaryActionButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(AppTypography.callout.weight(.semibold))
            .foregroundStyle(AppPalette.text)
            .padding(.horizontal, 13)
            .frame(height: 36)
            .liquidGlassSurface(
                cornerRadius: 7,
                tint: configuration.isPressed ? AppPalette.cardMuted : AppPalette.card
            )
            .overlay {
                RoundedRectangle(cornerRadius: 7, style: .continuous)
                    .stroke(AppPalette.border.opacity(0.82))
            }
            .shadow(color: Color.black.opacity(configuration.isPressed ? 0.025 : 0.05), radius: 8, y: 3)
    }
}

struct LightFieldStyle: TextFieldStyle {
    func _body(configuration: TextField<Self._Label>) -> some View {
        configuration
            .font(AppTypography.callout)
            .foregroundStyle(AppPalette.text)
            .padding(.horizontal, 11)
            .frame(height: 38)
            .liquidGlassSurface(cornerRadius: 7)
            .overlay {
                RoundedRectangle(cornerRadius: 7, style: .continuous)
                    .stroke(AppPalette.border.opacity(0.86))
            }
    }
}

func severityLabel(_ value: String) -> String {
    switch value.trimmingCharacters(in: .whitespacesAndNewlines).uppercased() {
    case "CRITICAL", "SEVERE", "严重": "严重"
    case "HIGH", "高危": "高危"
    case "MEDIUM", "MODERATE", "中危": "中危"
    case "LOW", "低危": "低危"
    default: "未知"
    }
}

func severityLabel(_ value: String, language: AppLanguage) -> String {
    switch value.trimmingCharacters(in: .whitespacesAndNewlines).uppercased() {
    case "CRITICAL", "SEVERE", "严重": localizedUI("严重", language: language)
    case "HIGH", "高危": localizedUI("高危", language: language)
    case "MEDIUM", "MODERATE", "中危": localizedUI("中危", language: language)
    case "LOW", "低危": localizedUI("低危", language: language)
    default: localizedUI("未知", language: language)
    }
}

func statusLabel(_ value: String) -> String {
    switch value.lowercased() {
    case "success", "completed": "完成"
    case "warning": "警告"
    case "failed", "error": "失败"
    case "running": "运行中"
    case "graph-node": "节点"
    default: value
    }
}

func statusLabel(_ value: String, language: AppLanguage) -> String {
    localizedUI(statusLabel(value), language: language)
}

func nodeLabel(_ node: String) -> String {
    let labels = [
        "classify_query": "识别问题意图",
        "component_query.parse_coordinates": "解析组件坐标",
        "component_query.query_vulnerabilities": "查询组件漏洞",
        "component_query.excel_mcp": "生成 Excel 结果",
        "component_query.d3_sankey_mcp": "生成桑基图",
        "component_query.compose_result": "汇总组件查询",
        "component_catalog.validate_request": "校验目录查询范围",
        "component_catalog.query": "查询组件漏洞目录",
        "component_catalog.d3_sankey_mcp": "生成目录桑基图",
        "component_catalog.interrupt_generate_excel": "确认生成 Excel",
        "component_catalog.excel_mcp": "生成目录 Excel",
        "component_catalog.interrupt_download_excel": "确认保存 Excel",
        "component_catalog.compose_result": "汇总组件漏洞目录",
        "component_catalog_subgraph": "组件漏洞目录子图",
        "report_capability_subgraph": "报告中心子图",
        "report.parse_request": "解析报告操作",
        "report.load_catalog": "加载报告清单",
        "report.interrupt_generate": "确认生成报告",
        "report.chart_mcp": "生成报告图表",
        "report.generate": "生成分析报告",
        "report.interrupt_download": "确认下载报告",
        "report.prepare_download": "准备报告下载",
        "report.compose_result": "汇总报告操作",
        "load_memory_context": "加载长期记忆",
        "retrieve_local_knowledge": "检索漏洞知识",
        "fetch_live_vulnerability": "实时补充记录",
        "query_intelligence": "查询漏洞接口",
        "run_static_path_analysis": "静态代码路径分析",
        "enrich_knowledge_graph": "生成知识图谱",
        "query_local_store": "接口查询准备",
        "query_sources": "查询外部接口",
        "persist_intelligence": "接口结果暂存",
        "call_llm": "调用安全模型",
        "translate_vulnerability_card": "整理漏洞卡片",
        "compose_answer": "生成回答",
        "generate_markdown_report": "生成分析报告",
        "persist_memory": "保存长期记忆",
        "validate_config": "准备查询环境",
        "fetch_records": "拉取情报记录",
        "normalize_records": "规范化与去重",
        "persist_records": "跳过本地写入",
        "compose_result": "汇总查询结果",
        "collector.validate_config": "准备查询环境",
        "collector.query_api": "查询漏洞接口",
        "collector.fetch_records": "拉取情报记录",
        "collector.normalize_records": "规范化与去重",
        "collector.persist_records": "跳过本地写入",
        "collector.compose_result": "汇总查询结果",
    ]
    return labels[node] ?? node
}

func nodeLabel(_ node: String, language: AppLanguage) -> String {
    localizedUI(nodeLabel(node), language: language)
}
