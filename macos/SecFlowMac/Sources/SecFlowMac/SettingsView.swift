import AppKit
import SwiftUI
import UniformTypeIdentifiers

private let customModelSelection = "__secflow_custom_model__"
private let maxProfileAvatarBytes = 2 * 1024 * 1024
private let supportedProfileAvatarExtensions: Set<String> = ["jpg", "jpeg", "png", "webp"]
private let defaultSettingsModelProvider = SettingsModelProvider.providers.first { $0.id == "openai" }
    ?? SettingsModelProvider.providers[0]
enum SettingsWindowMetrics {
    static let defaultSize = CGSize(width: 980, height: 760)
    static let minSize = CGSize(width: 940, height: 740)
    static let sidebarWidth: CGFloat = 220
}

private let profileAvatarContentTypes: [UTType] = {
    var types: [UTType] = [.png, .jpeg]
    if let webp = UTType(filenameExtension: "webp") {
        types.append(webp)
    }
    types.append(.image)
    return types
}()

struct SettingsView: View {
    @EnvironmentObject private var model: AppModel

    private let loadsData: Bool

    @State private var selectedSection: SettingsSection = .profile
    @State private var activeDocument: SettingsDocument?

    @State private var profileDisplayName = "李明哲"
    @State private var profileEmail = "limingzhe@example.com"
    @State private var profilePhone = "138 **** 6688"
    @State private var profileDepartment = "网络安全部"
    @State private var profileRole = "安全分析师"
    @State private var profileEmployeeID = "SEC-20240315"
    @State private var profileBio = ""
    @State private var profileAvatarImage: NSImage?
    @State private var isImportingAvatar = false
    @State private var profileNotice: SettingsNotice?
    @State private var didHydrateProfile = false

    @State private var selectedProviderID = defaultSettingsModelProvider.id
    @State private var providerSearchText = ""
    @State private var selectedModel = defaultSettingsModelProvider.defaultModel
    @State private var customModel = ""
    @State private var endpoint = defaultSettingsModelProvider.defaultEndpoint
    @State private var apiKey = ""
    @State private var isApiKeyVisible = false
    @State private var testResult: LLMTestResult?
    @State private var didHydrateLLM = false

    @State private var selectedSubscriptionPlanID = "professional_quarterly"
    @State private var selectedPaymentMethod = "alipay"
    @State private var subscriptionNotice: SettingsNotice?
    @State private var isShowingSubscriptionRecords = false
    @State private var isShowingCancelConfirmation = false

    @State private var selectedLanguage: AppLanguage = .zhHans
    @State private var darkMode = false
    @State private var fontSize = "default"
    @State private var launchAtLogin = false
    @State private var autoCheckUpdates = true
    @State private var preferenceNotice: SettingsNotice?
    @State private var didHydratePreferences = false

    private let providerColumns = [
        GridItem(.flexible(), spacing: 12),
        GridItem(.flexible(), spacing: 12),
        GridItem(.flexible(), spacing: 12),
    ]

    private var isTesting: Bool { model.busyActions.contains("llm-test") }
    private var isSavingLLM: Bool { model.busyActions.contains("llm-save") }
    private var isLoadingModels: Bool { model.busyActions.contains("llm-models") }
    private var isSavingProfile: Bool { model.busyActions.contains("settings-profile-save") }
    private var isUploadingAvatar: Bool { model.busyActions.contains("settings-avatar-upload") }
    private var isDeletingAvatar: Bool { model.busyActions.contains("settings-avatar-delete") }
    private var isSavingPreferences: Bool { model.busyActions.contains("settings-preferences-save") }
    private var isLoadingSubscription: Bool { model.busyActions.contains("subscription-load") }
    private var isCheckingOutSubscription: Bool { model.busyActions.contains("subscription-checkout") }
    private var isCancelingSubscription: Bool { model.busyActions.contains("subscription-cancel") }

    private var selectedProvider: SettingsModelProvider {
        SettingsModelProvider.providers.first { $0.id == selectedProviderID } ?? defaultSettingsModelProvider
    }

    init(initialSection: SettingsSection = .profile, loadsData: Bool = true) {
        self.loadsData = loadsData
        _selectedSection = State(initialValue: initialSection)
    }

    var body: some View {
        HStack(spacing: 0) {
            SettingsSidebar(
                selectedSection: $selectedSection,
                activeDocument: $activeDocument,
                profileName: profileDisplayName,
                role: profileRole,
                avatarImage: profileAvatarImage
            )
            .frame(width: SettingsWindowMetrics.sidebarWidth)

            Divider().overlay(AppPalette.separator.opacity(0.42))

            content
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .frame(
            minWidth: SettingsWindowMetrics.minSize.width,
            minHeight: SettingsWindowMetrics.minSize.height
        )
        .background(AppPalette.page)
        .background {
            SettingsWindowAppearanceConfigurator(darkMode: model.darkModeEnabled)
        }
        .foregroundStyle(AppPalette.text)
        .fileImporter(
            isPresented: $isImportingAvatar,
            allowedContentTypes: profileAvatarContentTypes,
            allowsMultipleSelection: false,
            onCompletion: importProfileAvatar
        )
        .sheet(isPresented: $isShowingSubscriptionRecords) {
            SubscriptionRecordsSheet(
                usage: model.subscriptionUsage,
                orders: model.subscriptionOrders
            )
        }
        .confirmationDialog(
            "确认取消自动续费？",
            isPresented: $isShowingCancelConfirmation,
            titleVisibility: .visible
        ) {
            Button("取消自动续费", role: .destructive) {
                Task { await cancelSubscription() }
            }
            Button("保留自动续费", role: .cancel) {}
        } message: {
            Text("取消后当前权益仍可使用至本周期结束，系统不会立即终止订阅。")
        }
        .onAppear {
            guard !didHydratePreferences else { return }
            darkMode = model.darkModeEnabled
            fontSize = model.interfaceFontSize.rawValue
        }
        .task {
            if loadsData {
                await bootstrap()
            }
        }
        .onChange(of: model.profileSettings) { _, _ in
            hydrateProfile(force: true)
        }
        .onChange(of: model.profileAvatarImageData) { _, _ in
            hydrateAvatarImage()
        }
        .onChange(of: model.preferenceSettings) { _, _ in
            hydratePreferences(force: true)
        }
        .onChange(of: darkMode) { _, value in
            preferenceNotice = nil
            model.previewAppearance(darkMode: value, fontSize: fontSize)
        }
        .onChange(of: fontSize) { _, value in
            preferenceNotice = nil
            model.previewAppearance(darkMode: darkMode, fontSize: value)
        }
        .onChange(of: model.llmConfig) { _, _ in
            hydrateLLM(force: false)
        }
    }

    @ViewBuilder
    private var content: some View {
        if let activeDocument {
            documentPage(activeDocument)
        } else {
            switch selectedSection {
            case .profile:
                profilePage
            case .modelConfig:
                modelConfigPage
            case .subscription:
                subscriptionPage
            case .logs:
                logsPage
            case .general:
                generalSettingsPage
            case .about:
                aboutPage
            }
        }
    }

    private var logsPage: some View {
        VStack(spacing: 0) {
            SettingsTopBar(title: model.uiText("日志管理"))
            RecordsView(showsHeader: false)
        }
    }

    private var profilePage: some View {
        VStack(spacing: 0) {
            SettingsTopBar(title: "用户资料") {
                Button {
                    Task { await saveProfile() }
                } label: {
                    Label(isSavingProfile ? "保存中" : "保存", systemImage: "square.and.arrow.down")
                }
                .buttonStyle(SettingsPrimaryButtonStyle())
                .disabled(isSavingProfile)
            }

            ScrollView {
                VStack(alignment: .leading, spacing: 24) {
                    SettingsPanel {
                        VStack(alignment: .leading, spacing: 26) {
                            SettingsSectionTitle(icon: "face.smiling", title: "基本信息")

                            HStack(alignment: .top, spacing: 36) {
                                VStack(spacing: 12) {
                                    ProfileAvatarView(displayName: profileDisplayName, image: profileAvatarImage)

                                    Button {
                                        profileNotice = nil
                                        isImportingAvatar = true
                                    } label: {
                                        Label(isUploadingAvatar ? "上传中" : "更换头像", systemImage: "camera")
                                    }
                                    .buttonStyle(SettingsSecondaryButtonStyle(height: 36))
                                    .disabled(isUploadingAvatar)

                                    if profileAvatarImage != nil {
                                        Button("移除头像") {
                                            Task { await removeProfileAvatar() }
                                        }
                                        .buttonStyle(.plain)
                                        .font(AppTypography.caption.weight(.semibold))
                                        .foregroundStyle(AppPalette.danger)
                                        .disabled(isDeletingAvatar)
                                    }
                                }
                                .frame(width: 120)

                                VStack(alignment: .leading, spacing: 16) {
                                    SettingsInputField(title: "昵称", text: $profileDisplayName)
                                    SettingsInputField(title: "邮箱账号", text: $profileEmail, isReadOnly: true, trailingText: "不可修改")
                                    SettingsInputField(title: "手机号", text: $profilePhone, trailingText: "更换", trailingColor: AppPalette.primary)

                                    HStack(spacing: 12) {
                                        SettingsInfoPill(title: "部门", value: profileDepartment)
                                        SettingsInfoPill(title: "岗位", value: profileRole)
                                        SettingsInfoPill(title: "工号", value: profileEmployeeID)
                                    }
                                }
                            }

                            if let profileNotice {
                                SettingsNoticeView(notice: profileNotice)
                            }
                        }
                    }

                    SettingsPanel {
                        VStack(alignment: .leading, spacing: 22) {
                            SettingsSectionTitle(icon: "shield", title: "账户安全")
                            SettingsActionRow(
                                icon: "lock.fill",
                                title: "登录密码",
                                subtitle: "上次修改：30天前",
                                trailing: "修改",
                                showChevron: true
                            )
                            SettingsToggleRow(
                                icon: "shield.lefthalf.filled",
                                title: "两步验证",
                                subtitle: "增强账户登录安全性",
                                isOn: .constant(true)
                            )
                            SettingsActionRow(
                                icon: "desktopcomputer",
                                title: "登录设备管理",
                                subtitle: "当前已登录 2 台设备",
                                trailing: "查看",
                                showChevron: true
                            )
                        }
                    }

                    Button {
                        model.signOut()
                    } label: {
                        Label("退出登录", systemImage: "rectangle.portrait.and.arrow.right")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(SettingsDangerButtonStyle())
                }
                .padding(32)
            }
            .background(AppPalette.page)
        }
    }

    private var modelConfigPage: some View {
        VStack(spacing: 0) {
            SettingsTopBar(title: "模型配置") {
                HStack(spacing: 10) {
                    Button {
                        Task { await testConnection() }
                    } label: {
                        Label(isTesting ? "测试中" : "测试连接", systemImage: "wifi")
                    }
                    .buttonStyle(SettingsSecondaryButtonStyle())
                    .disabled(isTesting || isSavingLLM)

                    Button {
                        Task { await saveAndEnable() }
                    } label: {
                        Label(isSavingLLM ? "保存中" : "保存", systemImage: "square.and.arrow.down")
                    }
                    .buttonStyle(SettingsPrimaryButtonStyle())
                    .disabled(isTesting || isSavingLLM || effectiveModel.isEmpty)
                }
            }

            ScrollView {
                VStack(alignment: .leading, spacing: 24) {
                    SettingsPanel {
                        VStack(alignment: .leading, spacing: 20) {
                            SettingsSectionTitle(icon: "puzzlepiece.extension", title: "模型提供商")

                            SettingsSearchField(text: $providerSearchText, placeholder: "搜索模型提供商...")

                            LazyVGrid(columns: providerColumns, spacing: 14) {
                                ForEach(filteredProviders) { provider in
                                    SettingsProviderCard(
                                        provider: provider,
                                        isSelected: provider.id == selectedProviderID
                                    ) {
                                        selectProvider(provider)
                                    }
                                }
                            }
                        }
                    }

                    SettingsPanel {
                        VStack(alignment: .leading, spacing: 20) {
                            HStack {
                                SettingsSectionTitle(icon: "square.stack.3d.up", title: "模型选择")
                                SettingsProviderBadge(provider: selectedProvider)
                                Spacer()
                                Button {
                                    Task { await loadProviderModels() }
                                } label: {
                                    if isLoadingModels {
                                        ProgressView()
                                            .controlSize(.small)
                                            .frame(width: 18, height: 18)
                                    } else {
                                        Image(systemName: "arrow.clockwise")
                                            .frame(width: 18, height: 18)
                                    }
                                }
                                .buttonStyle(SettingsSecondaryButtonStyle(height: 38))
                                .disabled(isLoadingModels)
                                .help("从厂商官方 Models API 同步")

                                Button {
                                    selectedModel = customModelSelection
                                    customModel = ""
                                } label: {
                                    Image(systemName: "plus")
                                        .frame(width: 18, height: 18)
                                }
                                .buttonStyle(SettingsSecondaryButtonStyle(height: 38))
                                .help("填写自定义模型 ID")
                            }

                            VStack(alignment: .leading, spacing: 10) {
                                Text("模型")
                                    .font(AppTypography.caption.weight(.semibold))
                                    .foregroundStyle(AppPalette.textMuted)

                                HStack(spacing: 10) {
                                    Image(systemName: "cpu")
                                        .foregroundStyle(AppPalette.textSubtle)
                                        .frame(width: 18)

                                    Picker("模型", selection: $selectedModel) {
                                        ForEach(visibleModelOptions) { option in
                                            Text("\(option.title) · \(option.model)")
                                                .tag(option.model)
                                        }
                                        Divider()
                                        Text("自定义模型 ID")
                                            .tag(customModelSelection)
                                    }
                                    .labelsHidden()
                                    .pickerStyle(.menu)
                                    .frame(maxWidth: .infinity, alignment: .leading)
                                }
                                .modifier(SettingsFieldChrome())

                                if let option = selectedModelOption {
                                    Text(option.subtitle)
                                        .font(AppTypography.caption)
                                        .foregroundStyle(AppPalette.textSubtle)
                                }

                                if let catalog = model.llmModelCatalog,
                                   catalog.provider == selectedProviderID {
                                    Text(catalog.source == "provider"
                                         ? "已同步 \(catalog.models.count) 个可调用模型"
                                         : "当前显示官网校准的内置模型目录")
                                        .font(AppTypography.caption)
                                        .foregroundStyle(catalog.source == "provider" ? AppPalette.success : AppPalette.textSubtle)
                                }

                            }

                            if selectedModel == customModelSelection {
                                SettingsInputField(
                                    title: "自定义模型 ID",
                                    text: $customModel,
                                    placeholder: "例如：gpt-5.6-terra、qwen3.7-plus、kimi-k3"
                                )
                            }
                        }
                    }

                    SettingsPanel {
                        VStack(alignment: .leading, spacing: 18) {
                            HStack {
                                SettingsSectionTitle(icon: "link", title: "接口配置")
                                Spacer()
                                Link(destination: selectedProvider.docsURL) {
                                    Label("API 文档", systemImage: "book.closed")
                                        .font(AppTypography.caption.weight(.semibold))
                                }
                                Link(destination: selectedProvider.keyURL) {
                                    Text("获取 Key")
                                        .font(AppTypography.caption.weight(.semibold))
                                }
                            }

                            VStack(alignment: .leading, spacing: 10) {
                                Text("API Key")
                                    .font(AppTypography.caption.weight(.semibold))
                                    .foregroundStyle(AppPalette.textMuted)

                                HStack(spacing: 10) {
                                    Image(systemName: "key.fill")
                                        .foregroundStyle(AppPalette.textSubtle)
                                        .frame(width: 18)
                                    Group {
                                        if isApiKeyVisible {
                                            TextField(apiKeyPlaceholder, text: $apiKey)
                                        } else {
                                            SecureField(apiKeyPlaceholder, text: $apiKey)
                                        }
                                    }
                                    .textFieldStyle(.plain)
                                    .font(AppTypography.callout.monospaced())

                                    Button {
                                        isApiKeyVisible.toggle()
                                    } label: {
                                        Image(systemName: isApiKeyVisible ? "eye" : "eye.slash")
                                            .frame(width: 24, height: 24)
                                            .foregroundStyle(AppPalette.textSubtle)
                                    }
                                    .buttonStyle(.plain)
                                }
                                .modifier(SettingsFieldChrome())
                            }

                            SettingsInputField(
                                title: "API 端点地址",
                                text: $endpoint,
                                placeholder: selectedProvider.defaultEndpoint,
                                icon: "globe.asia.australia"
                            )

                            Text("如果使用代理或第三方中转服务，请修改此地址。非原生支持厂商会按 OpenAI 兼容接口写入后端自定义模型配置。")
                                .font(AppTypography.caption)
                                .foregroundStyle(AppPalette.textSubtle)
                        }
                    }

                    SettingsConnectionStatusCard(
                        title: connectionTitle,
                        subtitle: connectionSubtitle,
                        isHealthy: connectionHealthy
                    )
                }
                .padding(32)
            }
            .background(AppPalette.page)
        }
    }

    private var subscriptionPage: some View {
        VStack(spacing: 0) {
            SettingsTopBar(title: "订阅管理") {
                HStack(spacing: 10) {
                    StatusBadge(
                        text: subscriptionStatusText(model.currentSubscription?.status ?? "free"),
                        tone: model.currentSubscription?.isActive == true ? .good : .neutral
                    )
                    Button {
                        isShowingSubscriptionRecords = true
                    } label: {
                        Label("使用记录", systemImage: "clock.arrow.circlepath")
                    }
                    .buttonStyle(SettingsSecondaryButtonStyle(height: 36))
                }
            }

            ScrollView {
                VStack(alignment: .leading, spacing: 24) {
                    if isLoadingSubscription, model.subscriptionCatalog == nil {
                        HStack(spacing: 10) {
                            ProgressView().controlSize(.small)
                            Text("正在加载订阅信息")
                                .font(AppTypography.callout)
                                .foregroundStyle(AppPalette.textMuted)
                        }
                        .frame(maxWidth: .infinity, minHeight: 90)
                    } else if let catalog = model.subscriptionCatalog {
                        SettingsPanel {
                            SubscriptionCurrentPlanView(
                                subscription: model.currentSubscription,
                                plan: catalog.plans.first { $0.id == model.currentSubscription?.planId },
                                isCanceling: isCancelingSubscription,
                                cancelAction: { isShowingCancelConfirmation = true }
                            )
                        }

                        VStack(alignment: .leading, spacing: 14) {
                            HStack(alignment: .center, spacing: 12) {
                                SettingsSectionTitle(icon: "square.stack.3d.up", title: "选择方案")
                                Spacer()
                                Label("所有方案均包含完整专业版权益", systemImage: "checkmark.shield.fill")
                                    .font(AppTypography.caption.weight(.semibold))
                                    .foregroundStyle(AppPalette.textMuted)
                            }
                            LazyVGrid(
                                columns: Array(repeating: GridItem(.flexible(), spacing: 14), count: 3),
                                spacing: 14
                            ) {
                                ForEach(catalog.plans) { plan in
                                    SubscriptionPlanCard(
                                        plan: plan,
                                        isSelected: selectedSubscriptionPlanID == plan.id,
                                        isCurrent: model.currentSubscription?.isActive == true
                                            && model.currentSubscription?.planId == plan.id,
                                        action: {
                                            selectedSubscriptionPlanID = plan.id
                                            subscriptionNotice = nil
                                        }
                                    )
                                }
                            }
                        }

                        SettingsPanel {
                            VStack(alignment: .leading, spacing: 18) {
                                SettingsSectionTitle(icon: "creditcard", title: "支付方式")

                                Picker("支付方式", selection: $selectedPaymentMethod) {
                                    ForEach(catalog.paymentMethods) { method in
                                        Label(method.name, systemImage: subscriptionPaymentIcon(method.id))
                                            .tag(method.id)
                                    }
                                }
                                .pickerStyle(.segmented)
                                .labelsHidden()

                                HStack(spacing: 12) {
                                    SettingsIconBox(icon: "lock.shield.fill")
                                    VStack(alignment: .leading, spacing: 3) {
                                        Text("安全支付保障")
                                            .font(AppTypography.callout.weight(.semibold))
                                        Text("金额由服务端套餐目录确认；支付成功后仅通过签名回调激活订阅。")
                                            .font(AppTypography.caption)
                                            .foregroundStyle(AppPalette.textMuted)
                                    }
                                    Spacer()
                                    Button {
                                        Task { await checkoutSubscription() }
                                    } label: {
                                        Label(
                                            isCheckingOutSubscription ? "创建订单中" : "确认方案并继续支付",
                                            systemImage: "creditcard.fill"
                                        )
                                    }
                                    .buttonStyle(SettingsPrimaryButtonStyle())
                                    .disabled(isCheckingOutSubscription || selectedSubscriptionPlanID.isEmpty)
                                }

                                if let subscriptionNotice {
                                    SettingsNoticeView(notice: subscriptionNotice)
                                }
                            }
                        }
                    } else {
                        ContentUnavailableView(
                            "订阅信息暂不可用",
                            systemImage: "wifi.exclamationmark",
                            description: Text(model.errorMessage ?? "请稍后重新打开订阅管理。")
                        )
                        .frame(maxWidth: .infinity, minHeight: 320)
                    }
                }
                .padding(32)
            }
            .background(AppPalette.page)
        }
    }

    private var generalSettingsPage: some View {
        VStack(spacing: 0) {
            SettingsTopBar(title: "通用设置") {
                Button {
                    Task { await savePreferences() }
                } label: {
                    Label(isSavingPreferences ? "保存中" : "保存", systemImage: "square.and.arrow.down")
                }
                .buttonStyle(SettingsPrimaryButtonStyle())
                .disabled(isSavingPreferences)
            }

            ScrollView {
                VStack(alignment: .leading, spacing: 24) {
                    SettingsPanel {
                        VStack(alignment: .leading, spacing: 22) {
                            SettingsSectionTitle(icon: "paintpalette", title: "外观设置")
                            SettingsToggleRow(
                                icon: "moon.fill",
                                title: "深色模式",
                                subtitle: darkMode ? "已开启深色显示" : "已切换为浅色显示",
                                isOn: $darkMode
                            )
                            SettingsMenuRow(
                                icon: "textformat.size",
                                title: "字体大小",
                                subtitle: "调整界面文字大小",
                                selection: $fontSize,
                                items: [
                                    ("small", "小"),
                                    ("default", "默认"),
                                    ("large", "大"),
                                ]
                            )
                        }
                    }

                    SettingsPanel {
                        VStack(alignment: .leading, spacing: 18) {
                            SettingsSectionTitle(icon: "translate", title: "语言设置")
                            VStack(spacing: 8) {
                                ForEach(SettingsLanguageOption.options) { option in
                                    SettingsLanguageRow(
                                        option: option,
                                        isSelected: option.language == selectedLanguage,
                                        action: {
                                            selectedLanguage = option.language
                                            preferenceNotice = nil
                                        }
                                    )
                                }
                            }
                        }
                    }

                    SettingsPanel {
                        VStack(alignment: .leading, spacing: 22) {
                            SettingsSectionTitle(icon: "arrow.clockwise", title: "启动与更新")
                            SettingsToggleRow(
                                icon: "rocket.fill",
                                title: "开机自启动",
                                subtitle: "系统启动时自动打开安全智脑",
                                isOn: $launchAtLogin
                            )
                            SettingsToggleRow(
                                icon: "icloud.and.arrow.down",
                                title: "自动检查更新",
                                subtitle: "发现新版本时自动提示",
                                isOn: $autoCheckUpdates
                            )
                        }
                    }

                    if let preferenceNotice {
                        SettingsNoticeView(notice: preferenceNotice)
                    }
                }
                .padding(32)
            }
            .background(AppPalette.page)
        }
    }

    private var aboutPage: some View {
        VStack(spacing: 0) {
            SettingsTopBar(title: "关于安全智脑")

            ScrollView {
                VStack(spacing: 26) {
                    VStack(spacing: 12) {
                        AppBrandLogo(size: 82)
                        Text(model.aboutSettings?.name ?? AppBrand.chineseName)
                            .font(AppTypography.title2.weight(.bold))
                        Text(model.aboutSettings?.subtitle ?? AppBrand.subtitle)
                            .font(AppTypography.callout)
                            .foregroundStyle(AppPalette.textMuted)
                        HStack(spacing: 8) {
                            Text("版本 \(aboutVersionLabel)")
                                .font(AppTypography.callout.weight(.semibold))
                                .foregroundStyle(AppPalette.primary)
                            if model.aboutSettings?.latest ?? true {
                                Text("已是最新")
                                    .font(AppTypography.caption2.weight(.semibold))
                                    .foregroundStyle(AppPalette.success)
                                    .padding(.horizontal, 8)
                                    .padding(.vertical, 3)
                                    .background(AppPalette.success.opacity(0.12))
                                    .clipShape(Capsule())
                            }
                        }
                    }
                    .padding(.top, 24)

                    SettingsPanel {
                        VStack(alignment: .leading, spacing: 18) {
                            SettingsSectionTitle(icon: "sparkles", title: "核心功能")
                            ForEach(model.aboutSettings?.features ?? AboutSettingsSnapshot.defaultFeatures, id: \.self) { feature in
                                HStack(alignment: .top, spacing: 10) {
                                    Image(systemName: "checkmark.circle.fill")
                                        .foregroundStyle(AppPalette.success)
                                        .font(AppTypography.system(size: 14, weight: .semibold))
                                        .padding(.top, 2)
                                    Text(feature)
                                        .font(AppTypography.callout)
                                        .foregroundStyle(AppPalette.textMuted)
                                        .fixedSize(horizontal: false, vertical: true)
                                }
                            }
                        }
                    }

                    SettingsPanel {
                        VStack(spacing: 0) {
                            SettingsAboutRow(icon: "arrow.clockwise", title: "检查更新", trailing: model.aboutSettings?.latest == true ? "已是最新版本" : "发现新版本") {
                                model.statusMessage = "已检查更新：当前版本 \(aboutVersionLabel)"
                            }
                            SettingsDivider()
                            SettingsAboutRow(icon: "doc.text", title: "服务协议") {
                                activeDocument = .terms
                                Task { await model.loadLegalDocument(id: SettingsDocument.terms.id) }
                            }
                            SettingsDivider()
                            SettingsAboutRow(icon: "shield", title: "隐私政策") {
                                activeDocument = .privacy
                                Task { await model.loadLegalDocument(id: SettingsDocument.privacy.id) }
                            }
                            SettingsDivider()
                            SettingsAboutRow(icon: "message", title: "意见反馈") {
                                model.statusMessage = "意见反馈入口已准备，可通过 support@security-ai.com 联系我们。"
                            }
                        }
                    }

                    Text(model.aboutSettings?.copyright ?? "© 2024 安全智脑 Security AI. All Rights Reserved.")
                        .font(AppTypography.caption)
                        .foregroundStyle(AppPalette.textSubtle)
                        .multilineTextAlignment(.center)
                        .padding(.bottom, 24)
                }
                .frame(maxWidth: 760)
                .padding(.horizontal, 32)
                .padding(.vertical, 24)
                .frame(maxWidth: .infinity)
            }
            .background(AppPalette.page)
        }
    }

    private func documentPage(_ document: SettingsDocument) -> some View {
        VStack(spacing: 0) {
            SettingsTopBar(title: document.title) {
                HStack(spacing: 12) {
                    Button {
                        activeDocument = nil
                    } label: {
                        Label("返回", systemImage: "chevron.left")
                    }
                    .buttonStyle(SettingsSecondaryButtonStyle(height: 36))
                }
            }

            ScrollView {
                SettingsDocumentCard(
                    document: document,
                    backendDocument: model.legalDocuments[document.id]
                )
                    .frame(maxWidth: 760)
                    .padding(.horizontal, 32)
                    .padding(.vertical, 28)
                    .frame(maxWidth: .infinity)
            }
            .background(AppPalette.page)
        }
    }

    private var filteredProviders: [SettingsModelProvider] {
        let cleanSearch = providerSearchText.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !cleanSearch.isEmpty else { return SettingsModelProvider.providers }
        return SettingsModelProvider.providers.filter {
            $0.title.localizedCaseInsensitiveContains(cleanSearch)
                || $0.subtitle.localizedCaseInsensitiveContains(cleanSearch)
                || $0.vendor.localizedCaseInsensitiveContains(cleanSearch)
        }
    }

    private var aboutVersionLabel: String {
        if let label = model.aboutSettings?.versionLabel?.trimmingCharacters(in: .whitespacesAndNewlines),
           !label.isEmpty {
            return label
        }
        if let version = model.aboutSettings?.version.trimmingCharacters(in: .whitespacesAndNewlines),
           !version.isEmpty {
            let channel = model.aboutSettings?.releaseChannel?.trimmingCharacters(in: .whitespacesAndNewlines)
            let suffix = channel?.isEmpty == false ? " \(channel!)" : " \(AppBrand.releaseChannel)"
            return "v\(version)\(suffix)"
        }
        return AppBrand.versionLabel
    }

    private var visibleModelOptions: [LLMModelOption] {
        var options = selectedProvider.models
        if let catalog = model.llmModelCatalog,
           catalog.provider == selectedProviderID,
           !catalog.models.isEmpty
        {
            let mapped = catalog.models.map {
                LLMModelOption(
                    title: ($0.name?.isEmpty == false ? $0.name! : $0.id),
                    model: $0.id,
                    subtitle: $0.description ?? "厂商接口返回模型"
                )
            }
            options = mapped + options
        }
        var seen = Set<String>()
        return options.filter { seen.insert($0.model).inserted }
    }

    private var selectedModelOption: LLMModelOption? {
        visibleModelOptions.first { $0.model == selectedModel }
    }

    private var effectiveModel: String {
        if selectedModel == customModelSelection {
            return customModel.trimmingCharacters(in: .whitespacesAndNewlines)
        }
        return selectedModel.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private var apiKeyPlaceholder: String {
        if apiKey.isEmpty, model.llmConfig?.hasApiKey == true, let masked = model.llmConfig?.apiKeyMasked {
            return masked
        }
        return selectedProvider.placeholder
    }

    private var connectionHealthy: Bool {
        if let result = testResult {
            return result.configured || result.status.lowercased() == "success"
        }
        return model.llmConfig?.configured == true
    }

    private var connectionTitle: String {
        if let result = testResult {
            return result.configured || result.status.lowercased() == "success" ? "模型连接正常" : "模型连接异常"
        }
        return model.llmConfig?.configured == true ? "模型连接正常" : "等待配置模型"
    }

    private var connectionSubtitle: String {
        if let result = testResult {
            let latency = result.latencyMs.map { " · \($0)ms" } ?? ""
            return "\(model.localizedMessage(result.message) ?? result.message)\(latency)"
        }
        if let updatedAt = model.llmConfig?.updatedAt.flatMap({ settingsDateTime($0, locale: model.appLanguage.locale) }) {
            return "上次检测时间：\(updatedAt)"
        }
        return "填写 API Key 并测试连接后，这里会显示最新连接状态。"
    }

    private func bootstrap() async {
        await model.loadSettings()
        hydrateProfile(force: true)
        hydrateAvatarImage()
        hydratePreferences(force: true)
        await model.loadLLMConfig()
        hydrateLLM(force: true)
        await model.loadSubscriptionData()
        hydrateSubscriptionSelection()
    }

    private func hydrateProfile(force: Bool = false) {
        guard force || !didHydrateProfile else { return }
        guard let profile = model.profileSettings else { return }
        profileDisplayName = profile.displayName
        profileEmail = profile.email
        profilePhone = profile.phone
        profileDepartment = profile.department
        profileRole = profile.role
        profileEmployeeID = profile.employeeId
        profileBio = profile.bio
        didHydrateProfile = true
    }

    private func hydrateAvatarImage() {
        if let data = model.profileAvatarImageData {
            profileAvatarImage = NSImage(data: data)
        } else {
            profileAvatarImage = nil
        }
    }

    private func hydratePreferences(force: Bool = false) {
        guard force || !didHydratePreferences else { return }
        guard let preferences = model.preferenceSettings else { return }
        if let language = AppLanguage(apiCode: preferences.language) {
            selectedLanguage = language
        }
        darkMode = preferences.darkMode
        fontSize = preferences.fontSize
        launchAtLogin = preferences.launchAtLogin
        autoCheckUpdates = preferences.autoCheckUpdates
        didHydratePreferences = true
    }

    private func hydrateLLM(force: Bool = false) {
        guard force || !didHydrateLLM else { return }
        guard let config = model.llmConfig else { return }
        let configEndpoint = config.endpoint ?? ""
        let provider = config.catalogProvider.flatMap { catalogProvider in
            SettingsModelProvider.providers.first { $0.id == catalogProvider }
        } ?? SettingsModelProvider.provider(forBackendProvider: config.provider, endpoint: configEndpoint)
        if let provider {
            selectedProviderID = provider.id
            endpoint = configEndpoint.isEmpty ? provider.defaultEndpoint : configEndpoint
            if provider.models.contains(where: { $0.model == config.model }) {
                selectedModel = config.model
                customModel = ""
            } else {
                selectedModel = customModelSelection
                customModel = config.model
            }
        }
        didHydrateLLM = true
    }

    private func hydrateSubscriptionSelection() {
        if let current = model.currentSubscription, current.isActive {
            selectedSubscriptionPlanID = current.planId
        } else if let recommended = model.subscriptionCatalog?.plans.first(where: \.recommended) {
            selectedSubscriptionPlanID = recommended.id
        }
        if let catalog = model.subscriptionCatalog,
           let firstMethod = catalog.paymentMethods.first,
           !catalog.paymentMethods.contains(where: { $0.id == selectedPaymentMethod }) {
            selectedPaymentMethod = firstMethod.id
        }
    }

    private func checkoutSubscription() async {
        subscriptionNotice = nil
        guard let result = await model.checkoutSubscription(
            planID: selectedSubscriptionPlanID,
            paymentMethod: selectedPaymentMethod
        ) else {
            subscriptionNotice = SettingsNotice(message: model.errorMessage ?? "无法创建支付订单", isSuccess: false)
            return
        }
        subscriptionNotice = SettingsNotice(
            message: result.message,
            isSuccess: result.checkoutStatus == "paid"
        )
    }

    private func cancelSubscription() async {
        subscriptionNotice = nil
        let canceled = await model.cancelCurrentSubscription(reason: "用户在 macOS 客户端取消自动续费")
        subscriptionNotice = SettingsNotice(
            message: canceled ? "已取消自动续费，当前权益保留至本周期结束" : (model.errorMessage ?? "取消自动续费失败"),
            isSuccess: canceled
        )
    }

    private func selectProvider(_ provider: SettingsModelProvider) {
        selectedProviderID = provider.id
        selectedModel = provider.defaultModel
        customModel = ""
        endpoint = provider.defaultEndpoint
        apiKey = ""
        model.llmModelCatalog = nil
        testResult = nil
        Task { await loadProviderModels() }
    }

    private func llmPayload(enabled: Bool = true) -> LLMConfigPayload {
        let cleanEndpoint = endpoint.trimmingCharacters(in: .whitespacesAndNewlines)
        let cleanKey = apiKey.trimmingCharacters(in: .whitespacesAndNewlines)
        let backendProvider = selectedProvider.backendProvider
        return LLMConfigPayload(
            provider: backendProvider.rawValue,
            catalogProvider: selectedProvider.id,
            model: effectiveModel,
            endpoint: cleanEndpoint.isEmpty ? selectedProvider.defaultEndpoint : cleanEndpoint,
            apiKey: cleanKey.isEmpty ? nil : cleanKey,
            enabled: enabled,
            maxTokens: 1800,
            temperature: 0.25,
            topP: 0.9,
            timeoutMs: 60000,
            wireApi: selectedProvider.wireAPI,
            reasoningEffort: selectedProvider.reasoningEffort,
            disableResponseStorage: selectedProvider.disableResponseStorage
        )
    }

    private func modelsPayload() -> LLMModelsPayload {
        LLMModelsPayload(
            provider: selectedProvider.backendProvider.rawValue,
            catalogProvider: selectedProvider.id,
            endpoint: endpoint.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? selectedProvider.defaultEndpoint : endpoint.trimmingCharacters(in: .whitespacesAndNewlines),
            apiKey: apiKey.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? nil : apiKey.trimmingCharacters(in: .whitespacesAndNewlines),
            timeoutMs: 30000
        )
    }

    private func loadProviderModels() async {
        await model.loadLLMModels(modelsPayload())
    }

    private func testConnection() async {
        guard !effectiveModel.isEmpty else {
            testResult = nil
            model.statusMessage = "请先选择或填写模型 ID"
            return
        }
        testResult = await model.testLLMConfig(llmPayload())
    }

    private func saveAndEnable() async {
        guard !effectiveModel.isEmpty else {
            model.statusMessage = "请先选择或填写模型 ID"
            return
        }
        await model.saveLLMConfig(llmPayload())
        apiKey = ""
        await model.loadLLMConfig()
        hydrateLLM(force: true)
    }

    private func saveProfile() async {
        let cleanName = profileDisplayName.trimmingCharacters(in: .whitespacesAndNewlines)
        let cleanEmail = profileEmail.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !cleanName.isEmpty else {
            profileNotice = SettingsNotice(message: "昵称不能为空", isSuccess: false)
            return
        }
        guard !cleanEmail.isEmpty else {
            profileNotice = SettingsNotice(message: "邮箱账号不能为空", isSuccess: false)
            return
        }
        let payload = UserProfileSettingsPayload(
            displayName: cleanName,
            email: cleanEmail,
            phone: profilePhone.trimmingCharacters(in: .whitespacesAndNewlines),
            department: profileDepartment.trimmingCharacters(in: .whitespacesAndNewlines),
            role: profileRole.trimmingCharacters(in: .whitespacesAndNewlines),
            employeeId: profileEmployeeID.trimmingCharacters(in: .whitespacesAndNewlines),
            bio: String(profileBio.prefix(200))
        )
        let saved = await model.saveProfileSettings(payload)
        profileNotice = SettingsNotice(message: saved ? "用户资料已保存" : (model.errorMessage ?? "保存失败"), isSuccess: saved)
    }

    private func importProfileAvatar(_ result: Result<[URL], Error>) {
        do {
            guard let sourceURL = try result.get().first else { return }
            let payload = try avatarPayload(from: sourceURL)
            Task {
                let uploaded = await model.uploadProfileAvatar(payload)
                hydrateAvatarImage()
                profileNotice = SettingsNotice(message: uploaded ? "头像已上传" : (model.errorMessage ?? "头像上传失败"), isSuccess: uploaded)
            }
        } catch {
            profileNotice = SettingsNotice(message: avatarErrorMessage(error), isSuccess: false)
        }
    }

    private func avatarPayload(from sourceURL: URL) throws -> AvatarUploadPayload {
        let scoped = sourceURL.startAccessingSecurityScopedResource()
        defer { if scoped { sourceURL.stopAccessingSecurityScopedResource() } }

        let ext = sourceURL.pathExtension.lowercased()
        guard supportedProfileAvatarExtensions.contains(ext) else {
            throw ProfileAvatarError.unsupportedType
        }
        let values = try sourceURL.resourceValues(forKeys: [.fileSizeKey, .isRegularFileKey])
        guard values.isRegularFile == true else {
            throw ProfileAvatarError.notRegularFile
        }
        if let fileSize = values.fileSize, fileSize > maxProfileAvatarBytes {
            throw ProfileAvatarError.tooLarge
        }
        let data = try Data(contentsOf: sourceURL)
        guard data.count <= maxProfileAvatarBytes else {
            throw ProfileAvatarError.tooLarge
        }
        guard NSImage(data: data) != nil else {
            throw ProfileAvatarError.invalidImage
        }
        return AvatarUploadPayload(
            fileName: sourceURL.lastPathComponent,
            contentBase64: data.base64EncodedString(),
            contentType: avatarContentType(forExtension: ext)
        )
    }

    private func removeProfileAvatar() async {
        let removed = await model.deleteProfileAvatar()
        hydrateAvatarImage()
        profileNotice = SettingsNotice(message: removed ? "头像已移除" : (model.errorMessage ?? "移除失败"), isSuccess: removed)
    }

    private func savePreferences() async {
        let payload = AppPreferenceSettingsPayload(
            language: selectedLanguage.apiCode,
            darkMode: darkMode,
            fontSize: fontSize,
            launchAtLogin: launchAtLogin,
            autoCheckUpdates: autoCheckUpdates
        )
        let saved = await model.savePreferenceSettings(payload)
        preferenceNotice = SettingsNotice(message: saved ? "通用设置已保存" : (model.errorMessage ?? "保存失败"), isSuccess: saved)
    }

    private func avatarContentType(forExtension ext: String) -> String {
        switch ext {
        case "jpg", "jpeg": "image/jpeg"
        case "png": "image/png"
        case "webp": "image/webp"
        default: "application/octet-stream"
        }
    }

    private func avatarErrorMessage(_ error: Error) -> String {
        guard let profileError = error as? ProfileAvatarError else {
            return error.localizedDescription
        }
        switch profileError {
        case .unsupportedType:
            return "仅支持 JPG、PNG 或 WebP 图片"
        case .tooLarge:
            return "头像文件不能超过 2MB"
        case .invalidImage:
            return "无法读取图片内容"
        case .notRegularFile:
            return "请选择一个有效的图片文件"
        }
    }
}

struct SettingsWindowAppearanceConfigurator: NSViewRepresentable {
    let darkMode: Bool

    func makeNSView(context: Context) -> NSView {
        let view = NSView()
        updateWindow(for: view)
        return view
    }

    func updateNSView(_ nsView: NSView, context: Context) {
        updateWindow(for: nsView)
    }

    private func updateWindow(for view: NSView) {
        DispatchQueue.main.async {
            configureSettingsWindowAppearance(view.window, darkMode: darkMode)
        }
    }
}

func configureSettingsWindowAppearance(_ window: NSWindow?, darkMode: Bool) {
    window?.appearance = NSAppearance(
        named: darkMode ? .darkAqua : .aqua
    )
}

enum SettingsSection: CaseIterable, Identifiable {
    case profile
    case modelConfig
    case subscription
    case logs
    case general
    case about

    var id: String { title }

    var title: String {
        switch self {
        case .profile: "用户资料"
        case .modelConfig: "模型配置"
        case .subscription: "订阅管理"
        case .logs: "日志管理"
        case .general: "通用设置"
        case .about: "关于安全智脑"
        }
    }

    var icon: String {
        switch self {
        case .profile: "person"
        case .modelConfig: "brain.head.profile"
        case .subscription: "crown"
        case .logs: "list.bullet.rectangle.portrait"
        case .general: "gearshape"
        case .about: "info.circle"
        }
    }
}

enum SettingsDocument: Identifiable, Hashable {
    case terms
    case privacy

    var id: String {
        switch self {
        case .terms: "terms"
        case .privacy: "privacy"
        }
    }

    var title: String {
        switch self {
        case .terms: "服务协议"
        case .privacy: "隐私政策"
        }
    }

    var heading: String {
        switch self {
        case .terms: "安全智脑服务协议"
        case .privacy: "安全智脑隐私政策"
        }
    }

    var updatedAt: String { "2026年7月20日" }
    var effectiveAt: String { "2026年7月20日" }

    var intro: String {
        switch self {
        case .terms:
            return "欢迎使用安全智脑（以下简称“本软件”）。本协议是您与安全智脑团队之间关于使用本软件服务所订立的协议。请您仔细阅读本协议的全部内容，您一旦安装、复制或以其他方式使用本软件，即表示您已阅读并同意接受本协议各项条款的约束。"
        case .privacy:
            return "安全智脑非常重视用户的隐私保护。本隐私政策将帮助您了解我们如何收集、使用、存储和保护您的个人信息。请您在使用本软件前仔细阅读本政策。"
        }
    }

    var sections: [(String, [String])] {
        switch self {
        case .terms:
            return [
                ("一、协议的接受与修改", [
                    "我们有权根据需要随时修改本协议条款，修改后的协议一经公布即有效代替原来的协议条款。您可随时查阅最新版协议。如您不同意相关修改，请立即停止使用本软件。",
                ]),
                ("二、服务内容", [
                    "安全智脑是一款基于人工智能技术的网络安全辅助工具，主要功能包括但不限于：",
                    "1. 智能问答：提供网络安全领域的知识问答服务；",
                    "2. 情报采集：聚合多源安全情报信息；",
                    "3. 知识图谱：安全领域实体关系可视化展示；",
                    "4. 漏洞库：漏洞信息查询与分析。",
                ]),
                ("三、用户账号", [
                    "您需要注册并登录账号才能使用本软件的完整功能。您应妥善保管账号和密码，对您账号下的所有行为承担责任。如发现账号被盗用，请立即通知我们。",
                ]),
                ("四、用户行为规范", [
                    "您在使用本软件时，应遵守相关法律法规，不得利用本软件从事任何违法违规活动，包括但不限于：",
                    "1. 发布、传播违法或不良信息；",
                    "2. 利用本软件从事未经授权的网络攻击、渗透测试等活动；",
                    "3. 侵犯他人合法权益；",
                    "4. 干扰本软件正常运行。",
                ]),
                ("五、知识产权", [
                    "本软件的一切知识产权，包括但不限于著作权、专利权、商标权等，均归安全智脑团队所有。未经授权，您不得对本软件进行复制、修改、分发、反编译等。",
                ]),
                ("六、免责声明", [
                    "本软件提供的信息仅供参考，不构成任何安全建议或操作指导。您因使用本软件信息而产生的任何直接或间接损失，我们不承担责任。本软件按“现状”提供，我们不保证服务会中断，也不保证服务的绝对准确性。",
                ]),
                ("七、协议终止", [
                    "如您违反本协议，我们有权立即终止您的账号使用权限。您也可以随时注销账号终止本协议。协议终止后，相关条款（如知识产权、免责声明等）仍然有效。",
                ]),
                ("八、联系我们", [
                    "如您对本协议有任何疑问或建议，请通过以下方式联系我们：",
                    "邮箱：support@security-ai.com",
                ]),
            ]
        case .privacy:
            return [
                ("一、我们收集的信息", [
                    "为了向您提供更好的服务，我们可能会收集以下类型的信息：",
                    "账户信息：昵称、邮箱账号、手机号等；",
                    "使用信息：您在本软件中的设置、查询记录和交互信息；",
                    "设备信息：设备型号、操作系统版本、应用版本等；",
                    "日志信息：错误日志、运行状态和服务调用记录。",
                ]),
                ("二、信息的使用", [
                    "我们收集的信息将用于以下目的：",
                    "1. 提供、维护和改进本软件的服务；",
                    "2. 向您发送服务通知和更新信息；",
                    "3. 保障账户安全，防范欺诈等违法行为；",
                    "4. 在获得您同意的前提下，进行产品优化和数据分析。",
                ]),
                ("三、信息的共享与披露", [
                    "我们不会向第三方出售您的个人信息。仅在以下情况下，我们可能会共享您的信息：",
                    "1. 获得您的明确同意；",
                    "2. 法律法规要求或司法机关、行政机关依法定程序要求；",
                    "3. 为保护我们或用户的合法权益所必需。",
                ]),
                ("四、信息的存储与保护", [
                    "我们采用业界标准的安全技术和管理措施来保护您的个人信息，包括加密传输、访问控制、数据脱敏等。但请您理解，由于技术限制和可能的恶意攻击，我们无法保证信息的绝对安全。",
                    "您的个人信息将存储在中华人民共和国境内。如需跨境传输，我们将依法履行相关义务。",
                ]),
                ("五、您的权利", [
                    "您对您的个人信息享有以下权利：",
                    "1. 访问、更正您的个人信息；",
                    "2. 删除您的个人信息；",
                    "3. 撤回您的授权同意；",
                    "4. 注销您的账号。",
                ]),
                ("六、未成年人保护", [
                    "本软件主要面向成年用户。如您是未成年人，请在监护人的指导下使用本软件。我们不会主动收集未成年人的个人信息。",
                ]),
                ("七、政策更新", [
                    "我们可能会适时更新本隐私政策。更新后的政策将在本软件内公布，重大变更将通过显著方式通知您。继续使用本软件即表示您同意更新后的政策。",
                ]),
                ("八、联系我们", [
                    "如您对本隐私政策有任何疑问、意见或建议，或需要行使您的权利，请通过以下方式联系我们：",
                    "邮箱：privacy@security-ai.com",
                ]),
            ]
        }
    }
}

private struct SettingsNotice: Equatable {
    let message: String
    let isSuccess: Bool
}

private enum ProfileAvatarError: LocalizedError {
    case unsupportedType
    case tooLarge
    case invalidImage
    case notRegularFile
}

private struct SettingsSidebar: View {
    @EnvironmentObject private var model: AppModel
    @Binding var selectedSection: SettingsSection
    @Binding var activeDocument: SettingsDocument?
    let profileName: String
    let role: String
    let avatarImage: NSImage?
    @State private var isFooterHovered = false

    var body: some View {
        ZStack {
            SidebarGlassBackground()

            VStack(alignment: .leading, spacing: 26) {
                HStack(spacing: 12) {
                    AppBrandLogo(size: 46, shadow: false)
                    VStack(alignment: .leading, spacing: 3) {
                        Text(AppBrand.chineseName)
                            .font(AppTypography.sidebarBrandTitle)
                            .foregroundStyle(AppPalette.sidebarText)
                        Text(AppBrand.subtitle)
                            .font(AppTypography.sidebarBrandSubtitle)
                            .foregroundStyle(AppPalette.sidebarTextMuted)
                    }
                }
                .padding(.horizontal, 18)
                .padding(.top, 24)

                VStack(spacing: 8) {
                    ForEach(SettingsSection.allCases) { section in
                        SettingsSidebarItemButton(
                            section: section,
                            selected: selectedSection == section
                        ) {
                            selectedSection = section
                            activeDocument = nil
                        }
                    }
                }
                .padding(.horizontal, 10)

                Spacer()

                HStack(spacing: 12) {
                    ZStack {
                        Circle().fill(AppPalette.primary)
                        if let avatarImage {
                            Image(nsImage: avatarImage)
                                .resizable()
                                .scaledToFill()
                                .frame(width: 36, height: 36)
                                .clipShape(Circle())
                        } else {
                            Text(profileInitial)
                                .font(AppTypography.sidebarIdentity)
                                .foregroundStyle(.white)
                        }
                    }
                    .frame(width: 36, height: 36)
                    .overlay(Circle().stroke(AppPalette.sidebarDivider.opacity(0.72), lineWidth: 1))

                    VStack(alignment: .leading, spacing: 2) {
                        Text(profileName.isEmpty ? "小安用户" : profileName)
                            .font(AppTypography.sidebarIdentity)
                            .foregroundStyle(AppPalette.sidebarText)
                            .lineLimit(1)
                        Text(role.isEmpty ? "专业版" : role)
                            .font(AppTypography.sidebarIdentityCaption)
                            .foregroundStyle(AppPalette.sidebarTextMuted)
                            .lineLimit(1)
                    }
                    Spacer()
                    Image(systemName: "ellipsis")
                        .foregroundStyle(AppPalette.sidebarTextMuted)
                        .opacity(isFooterHovered ? 1 : 0.55)
                }
                .padding(.horizontal, 18)
                .frame(minHeight: 58)
                .background(isFooterHovered ? AppPalette.sidebarHover.opacity(0.74) : Color.clear)
                .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
                .padding(.horizontal, 8)
                .padding(.bottom, 18)
                .onHover { hovering in
                    withAnimation(.easeInOut(duration: 0.18)) {
                        isFooterHovered = hovering
                    }
                }
            }
        }
    }

    private var profileInitial: String {
        let clean = profileName.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let first = clean.first else { return "安" }
        return String(first)
    }
}

private struct SettingsSidebarItemButton: View {
    @EnvironmentObject private var model: AppModel
    let section: SettingsSection
    let selected: Bool
    let action: () -> Void
    @State private var hovering = false

    var body: some View {
        Button(action: action) {
            HStack(spacing: 14) {
                Image(systemName: section.icon)
                    .font(AppTypography.system(size: 16, weight: .semibold))
                    .frame(width: 22)
                Text(model.uiText(section.title))
                    .font(AppTypography.sidebarItem)
                Spacer()
            }
            .foregroundStyle(selected ? AppPalette.sidebarText : AppPalette.sidebarTextMuted)
            .padding(.horizontal, 18)
            .frame(height: 48)
            .background(
                selected
                    ? AppPalette.sidebarSelected
                    : (hovering ? AppPalette.sidebarHover.opacity(0.82) : Color.clear)
            )
            .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
            .contentShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
        }
        .buttonStyle(.plain)
        .onHover { value in
            withAnimation(.easeInOut(duration: 0.16)) {
                hovering = value
            }
        }
    }
}

private struct SettingsTopBar<Trailing: View>: View {
    let title: String
    @ViewBuilder let trailing: Trailing

    init(title: String, @ViewBuilder trailing: () -> Trailing) {
        self.title = title
        self.trailing = trailing()
    }

    var body: some View {
        HStack {
            Text(title)
                .font(AppTypography.title3.weight(.bold))
                .foregroundStyle(AppPalette.text)
            Spacer()
            trailing
        }
        .padding(.horizontal, 32)
        .frame(height: 66)
        .background(.ultraThinMaterial)
        .background(AppPalette.page.opacity(0.28))
        .overlay(alignment: .bottom) {
            Rectangle().fill(AppPalette.separator.opacity(0.42)).frame(height: 1)
        }
    }
}

private extension SettingsTopBar where Trailing == EmptyView {
    init(title: String) {
        self.init(title: title) { EmptyView() }
    }
}

private struct SettingsPanel<Content: View>: View {
    @ViewBuilder let content: Content

    init(@ViewBuilder content: () -> Content) {
        self.content = content()
    }

    var body: some View {
        content
            .padding(28)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(
                .regularMaterial,
                in: RoundedRectangle(cornerRadius: 12, style: .continuous)
            )
            .background(
                AppPalette.card.opacity(0.44),
                in: RoundedRectangle(cornerRadius: 12, style: .continuous)
            )
            .overlay {
                RoundedRectangle(cornerRadius: 12, style: .continuous)
                    .stroke(AppPalette.separator.opacity(0.52))
            }
    }
}

private struct SettingsSectionTitle: View {
    let icon: String
    let title: String

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: icon)
                .font(AppTypography.system(size: 17, weight: .semibold))
                .foregroundStyle(AppPalette.primary)
                .frame(width: 22)
            Text(title)
                .font(AppTypography.headline.weight(.bold))
                .foregroundStyle(AppPalette.text)
        }
    }
}

private struct SettingsSearchField: View {
    @Binding var text: String
    let placeholder: String

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: "magnifyingglass")
                .foregroundStyle(AppPalette.textSubtle)
            TextField(placeholder, text: $text)
                .textFieldStyle(.plain)
                .font(AppTypography.callout)
        }
        .modifier(SettingsFieldChrome(height: 48))
    }
}

private struct SettingsInputField: View {
    let title: String
    @Binding var text: String
    var placeholder: String = ""
    var icon: String?
    var isReadOnly = false
    var trailingText: String?
    var trailingColor: Color = AppPalette.textSubtle

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(title)
                .font(AppTypography.caption.weight(.semibold))
                .foregroundStyle(AppPalette.textMuted)
            HStack(spacing: 10) {
                if let icon {
                    Image(systemName: icon)
                        .foregroundStyle(AppPalette.textSubtle)
                        .frame(width: 18)
                }
                TextField(placeholder.isEmpty ? title : placeholder, text: $text)
                    .textFieldStyle(.plain)
                    .font(AppTypography.callout)
                    .foregroundStyle(isReadOnly ? AppPalette.textMuted : AppPalette.text)
                    .disabled(isReadOnly)
                if let trailingText {
                    Text(trailingText)
                        .font(AppTypography.caption.weight(.semibold))
                        .foregroundStyle(trailingColor)
                }
            }
            .modifier(SettingsFieldChrome(background: isReadOnly ? AppPalette.cardMuted.opacity(0.75) : AppPalette.card))
        }
    }
}

private struct SettingsFieldChrome: ViewModifier {
    var height: CGFloat = 44
    var background: Color = AppPalette.card

    func body(content: Content) -> some View {
        content
            .padding(.horizontal, 14)
            .frame(height: height)
            .background(background)
            .clipShape(RoundedRectangle(cornerRadius: 9, style: .continuous))
            .overlay {
                RoundedRectangle(cornerRadius: 9, style: .continuous)
                    .stroke(AppPalette.border.opacity(0.9))
            }
    }
}

private struct ProfileAvatarView: View {
    let displayName: String
    let image: NSImage?

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
            if let image {
                Image(nsImage: image)
                    .resizable()
                    .scaledToFill()
                    .frame(width: 86, height: 86)
                    .clipShape(Circle())
            } else {
                Text(initial)
                    .font(AppTypography.system(size: 34, weight: .bold))
                    .foregroundStyle(.white)
            }
        }
        .frame(width: 86, height: 86)
        .overlay(Circle().stroke(Color.white.opacity(0.82), lineWidth: 3))
        .shadow(color: AppPalette.primary.opacity(0.22), radius: 14, y: 5)
    }

    private var initial: String {
        let cleanName = displayName.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let first = cleanName.first else { return "安" }
        return String(first)
    }
}

private struct SettingsInfoPill: View {
    let title: String
    let value: String

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title)
                .font(AppTypography.caption2.weight(.semibold))
                .foregroundStyle(AppPalette.textSubtle)
            Text(value.isEmpty ? "—" : value)
                .font(AppTypography.caption.weight(.semibold))
                .foregroundStyle(AppPalette.textMuted)
                .lineLimit(1)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 9)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(AppPalette.cardMuted)
        .clipShape(RoundedRectangle(cornerRadius: 9, style: .continuous))
    }
}

private struct SettingsActionRow: View {
    let icon: String
    let title: String
    let subtitle: String
    var trailing: String?
    var showChevron = false

    var body: some View {
        HStack(spacing: 14) {
            SettingsIconBox(icon: icon)
            VStack(alignment: .leading, spacing: 3) {
                Text(title)
                    .font(AppTypography.callout.weight(.semibold))
                    .foregroundStyle(AppPalette.text)
                Text(subtitle)
                    .font(AppTypography.caption)
                    .foregroundStyle(AppPalette.textMuted)
            }
            Spacer()
            if let trailing {
                Text(trailing)
                    .font(AppTypography.caption.weight(.semibold))
                    .foregroundStyle(AppPalette.primary)
            }
            if showChevron {
                Image(systemName: "chevron.right")
                    .font(AppTypography.caption.weight(.bold))
                    .foregroundStyle(AppPalette.textSubtle)
            }
        }
    }
}

private struct SettingsToggleRow: View {
    let icon: String
    let title: String
    let subtitle: String
    @Binding var isOn: Bool

    var body: some View {
        HStack(spacing: 14) {
            SettingsIconBox(icon: icon)
            VStack(alignment: .leading, spacing: 3) {
                Text(title)
                    .font(AppTypography.callout.weight(.semibold))
                    .foregroundStyle(AppPalette.text)
                Text(subtitle)
                    .font(AppTypography.caption)
                    .foregroundStyle(AppPalette.textMuted)
            }
            Spacer()
            Toggle("", isOn: $isOn)
                .labelsHidden()
                .toggleStyle(.switch)
                .tint(AppPalette.success)
        }
    }
}

private struct SettingsMenuRow: View {
    let icon: String
    let title: String
    let subtitle: String
    @Binding var selection: String
    let items: [(String, String)]

    private var selectedTitle: String {
        items.first(where: { $0.0 == selection })?.1 ?? items.first?.1 ?? selection
    }

    var body: some View {
        HStack(spacing: 14) {
            SettingsIconBox(icon: icon)
            VStack(alignment: .leading, spacing: 3) {
                Text(title)
                    .font(AppTypography.callout.weight(.semibold))
                    .foregroundStyle(AppPalette.text)
                Text(subtitle)
                    .font(AppTypography.caption)
                    .foregroundStyle(AppPalette.textMuted)
            }
            Spacer()
            Menu {
                ForEach(items, id: \.0) { item in
                    Button {
                        selection = item.0
                    } label: {
                        if item.0 == selection {
                            Label(item.1, systemImage: "checkmark")
                        } else {
                            Text(item.1)
                        }
                    }
                }
            } label: {
                HStack(spacing: 8) {
                    Text(selectedTitle)
                        .font(AppTypography.caption.weight(.semibold))
                        .foregroundStyle(AppPalette.text)
                        .lineLimit(1)
                    Spacer(minLength: 0)
                    Image(systemName: "chevron.up.chevron.down")
                        .font(AppTypography.system(size: 10, weight: .semibold))
                        .foregroundStyle(AppPalette.textMuted)
                }
                .padding(.horizontal, 11)
                .frame(width: 104, height: 34)
                .background(AppPalette.controlBackground)
                .clipShape(RoundedRectangle(cornerRadius: 7, style: .continuous))
                .overlay {
                    RoundedRectangle(cornerRadius: 7, style: .continuous)
                        .stroke(AppPalette.border, lineWidth: 1)
                }
                .contentShape(RoundedRectangle(cornerRadius: 7, style: .continuous))
            }
            .menuStyle(.borderlessButton)
            .menuIndicator(.hidden)
            .buttonStyle(.plain)
            .accessibilityLabel(title)
            .accessibilityValue(selectedTitle)
        }
    }
}

private struct SettingsIconBox: View {
    let icon: String

    var body: some View {
        Image(systemName: icon)
            .font(AppTypography.system(size: 15, weight: .semibold))
            .foregroundStyle(AppPalette.primary)
            .frame(width: 34, height: 34)
            .background(AppPalette.primary.opacity(0.12))
            .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
    }
}

private struct SettingsNoticeView: View {
    let notice: SettingsNotice

    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: notice.isSuccess ? "checkmark.circle.fill" : "info.circle.fill")
            Text(notice.message)
            Spacer()
        }
        .font(AppTypography.caption.weight(.semibold))
        .foregroundStyle(notice.isSuccess ? AppPalette.success : AppPalette.warning)
        .padding(.horizontal, 14)
        .frame(minHeight: 38)
        .background((notice.isSuccess ? AppPalette.success : AppPalette.warning).opacity(0.10))
        .clipShape(RoundedRectangle(cornerRadius: 9, style: .continuous))
    }
}

private struct SubscriptionCurrentPlanView: View {
    let subscription: SubscriptionSnapshot?
    let plan: SubscriptionPlan?
    let isCanceling: Bool
    let cancelAction: () -> Void

    private var isActive: Bool { subscription?.isActive == true }

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            HStack(alignment: .top, spacing: 14) {
                SettingsIconBox(icon: "crown.fill")
                VStack(alignment: .leading, spacing: 5) {
                    Text("当前订阅")
                        .font(AppTypography.callout.weight(.semibold))
                        .foregroundStyle(AppPalette.textMuted)
                    Text(currentTitle)
                        .font(AppTypography.title2.weight(.bold))
                        .foregroundStyle(AppPalette.text)
                    Text(currentSubtitle)
                        .font(AppTypography.caption)
                        .foregroundStyle(AppPalette.textMuted)
                }
                Spacer()
                VStack(alignment: .trailing, spacing: 8) {
                    StatusBadge(
                        text: subscriptionStatusText(subscription?.status ?? "free"),
                        tone: isActive ? .good : .neutral
                    )
                    if let plan {
                        HStack(alignment: .firstTextBaseline, spacing: 3) {
                            Text(plan.priceText)
                                .font(AppTypography.system(size: 32, weight: .bold, design: .rounded))
                            Text("/\(subscriptionPeriodUnit(plan.billingPeriod))")
                                .font(AppTypography.callout)
                                .foregroundStyle(AppPalette.textMuted)
                        }
                    }
                }
            }

            if isActive, subscription?.autoRenew == true {
                Divider().overlay(AppPalette.border)
                HStack {
                    Label("到期自动续费", systemImage: "arrow.triangle.2.circlepath")
                        .font(AppTypography.caption.weight(.semibold))
                        .foregroundStyle(AppPalette.textMuted)
                    Spacer()
                    Button(action: cancelAction) {
                        Label(isCanceling ? "处理中" : "取消自动续费", systemImage: "xmark.circle")
                    }
                    .buttonStyle(.plain)
                    .font(AppTypography.caption.weight(.semibold))
                    .foregroundStyle(AppPalette.danger)
                    .disabled(isCanceling)
                }
            }
        }
    }

    private var currentTitle: String {
        guard isActive else { return "免费版" }
        let periodName = subscription?.periodName ?? ""
        return [subscription?.planName ?? "专业版", periodName]
            .filter { !$0.isEmpty }
            .joined(separator: " · ")
    }

    private var currentSubtitle: String {
        if subscription?.cancelAtPeriodEnd == true,
           let end = subscription?.currentPeriodEnd,
           let date = settingsDateTime(end, locale: Locale(identifier: "zh_CN")) {
            return "已取消自动续费 · 权益保留至 \(date)"
        }
        if isActive,
           let end = subscription?.currentPeriodEnd,
           let date = settingsDateTime(end, locale: Locale(identifier: "zh_CN")) {
            return "下次续费日期：\(date)"
        }
        return "升级专业版后可使用完整订阅权益"
    }
}

private struct SubscriptionPlanCard: View {
    let plan: SubscriptionPlan
    let isSelected: Bool
    let isCurrent: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            VStack(alignment: .leading, spacing: 14) {
                HStack(alignment: .top, spacing: 10) {
                    Image(systemName: SubscriptionPlanVisuals.symbolName(for: plan))
                        .font(AppTypography.system(size: 18, weight: .semibold))
                        .foregroundStyle(plan.recommended ? Color.white : AppPalette.primary)
                        .frame(width: 38, height: 38)
                        .background(plan.recommended ? AppPalette.primary : AppPalette.primary.opacity(0.12))
                        .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))

                    Spacer(minLength: 4)

                    VStack(alignment: .trailing, spacing: 7) {
                        Text(plan.badge)
                            .font(AppTypography.caption2.weight(.bold))
                            .foregroundStyle(plan.recommended ? Color.white : AppPalette.textMuted)
                            .padding(.horizontal, 8)
                            .padding(.vertical, 4)
                            .background(plan.recommended ? AppPalette.primary : AppPalette.cardMuted)
                            .clipShape(Capsule())
                        Image(systemName: isSelected ? "checkmark.circle.fill" : "circle")
                            .font(AppTypography.system(size: 17, weight: .semibold))
                            .foregroundStyle(isSelected ? AppPalette.primary : AppPalette.textSubtle)
                    }
                }

                VStack(alignment: .leading, spacing: 4) {
                    Text("\(plan.name) · \(plan.periodName)")
                        .font(AppTypography.title3.weight(.bold))
                        .foregroundStyle(AppPalette.text)
                        .lineLimit(1)
                    Text(plan.description)
                        .font(AppTypography.caption)
                        .foregroundStyle(AppPalette.textMuted)
                        .lineLimit(2)
                        .frame(minHeight: 32, alignment: .topLeading)
                }

                VStack(alignment: .leading, spacing: 6) {
                    HStack(alignment: .firstTextBaseline, spacing: 3) {
                        Text(plan.priceText)
                            .font(AppTypography.system(size: 34, weight: .bold, design: .rounded))
                            .foregroundStyle(AppPalette.text)
                        Text("/\(subscriptionPeriodUnit(plan.billingPeriod))")
                            .font(AppTypography.callout)
                            .foregroundStyle(AppPalette.textMuted)
                    }

                    HStack(spacing: 7) {
                        Text(plan.intervalMonths > 1 ? "折合 \(plan.monthlyEquivalentText)/月" : "按月计费")
                            .font(AppTypography.caption)
                            .foregroundStyle(AppPalette.textMuted)
                        if plan.discountPercent > 0 {
                            Text("省 \(plan.discountPercent)%")
                                .font(AppTypography.caption2.weight(.bold))
                                .foregroundStyle(AppPalette.warning)
                                .padding(.horizontal, 6)
                                .padding(.vertical, 2)
                                .background(AppPalette.warning.opacity(0.12))
                                .clipShape(Capsule())
                        }
                    }
                }

                Divider().overlay(AppPalette.border)

                VStack(alignment: .leading, spacing: 9) {
                    ForEach(Array(plan.features.enumerated()), id: \.offset) { _, feature in
                        HStack(alignment: .top, spacing: 8) {
                            Image(systemName: "checkmark.circle.fill")
                                .font(AppTypography.system(size: 13, weight: .semibold))
                                .foregroundStyle(AppPalette.success)
                                .padding(.top, 1)
                            Text(feature)
                                .font(AppTypography.caption)
                                .foregroundStyle(AppPalette.textMuted)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    }
                }
                .frame(maxWidth: .infinity, minHeight: 58, alignment: .topLeading)

                Spacer(minLength: 0)

                HStack(spacing: 7) {
                    Image(systemName: isCurrent ? "checkmark.seal.fill" : (isSelected ? "checkmark" : "arrow.right"))
                    Text(isCurrent ? "当前方案" : (isSelected ? "已选择" : "选择\(plan.periodName)"))
                }
                .font(AppTypography.callout.weight(.semibold))
                .foregroundStyle(isSelected ? Color.white : AppPalette.primary)
                .frame(maxWidth: .infinity, minHeight: 40)
                .background(isSelected ? AppPalette.primary : Color.clear)
                .overlay {
                    RoundedRectangle(cornerRadius: 8, style: .continuous)
                        .stroke(AppPalette.primary, lineWidth: 1)
                }
                .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
            }
            .padding(18)
            .frame(maxWidth: .infinity, minHeight: 390, alignment: .topLeading)
            .background(AppPalette.card)
            .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
            .overlay {
                RoundedRectangle(cornerRadius: 8, style: .continuous)
                    .stroke(cardBorderColor, lineWidth: isSelected ? 2 : (plan.recommended ? 1.5 : 1))
            }
            .shadow(color: Color.black.opacity(isSelected || plan.recommended ? 0.075 : 0.035), radius: 10, y: 4)
        }
        .buttonStyle(.plain)
        .accessibilityLabel("\(plan.name)\(plan.periodName)方案，\(plan.priceText)")
        .accessibilityValue(isCurrent ? "当前方案" : (isSelected ? "已选择" : "未选择"))
    }

    private var cardBorderColor: Color {
        if isSelected { return AppPalette.primary }
        if plan.recommended { return AppPalette.primary.opacity(0.72) }
        return AppPalette.border
    }
}

enum SubscriptionPlanVisuals {
    static func symbolName(for plan: SubscriptionPlan) -> String {
        if plan.recommended { return "sparkles" }
        switch plan.billingPeriod.lowercased() {
        case "month", "monthly":
            return "bolt.fill"
        case "quarter", "quarterly":
            return "calendar.badge.clock"
        case "year", "yearly", "annual":
            return "arrow.down.to.line"
        default:
            return "sparkles"
        }
    }
}

private struct SubscriptionRecordsSheet: View {
    @Environment(\.dismiss) private var dismiss
    @EnvironmentObject private var model: AppModel
    let usage: SubscriptionUsageSnapshot?
    let orders: [SubscriptionOrder]

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                VStack(alignment: .leading, spacing: 3) {
                    Text("使用与订单记录")
                        .font(AppTypography.title3.weight(.bold))
                    Text("本周期资源用量和最近支付订单")
                        .font(AppTypography.caption)
                        .foregroundStyle(AppPalette.textMuted)
                }
                Spacer()
                Button { dismiss() } label: {
                    Image(systemName: "xmark")
                        .frame(width: 28, height: 28)
                }
                .buttonStyle(.plain)
                .help("关闭")
            }
            .padding(22)
            .background(AppPalette.card)

            Divider().overlay(AppPalette.border)

            ScrollView {
                VStack(alignment: .leading, spacing: 24) {
                    VStack(alignment: .leading, spacing: 14) {
                        SettingsSectionTitle(icon: "chart.bar", title: "本周期用量")
                        if let usage {
                            ForEach(usage.metrics) { metric in
                                VStack(alignment: .leading, spacing: 7) {
                                    HStack {
                                        Text(metric.label).font(AppTypography.callout.weight(.semibold))
                                        Spacer()
                                        Text("\(metric.used) / \(metric.limit) \(metric.unit)")
                                            .font(AppTypography.caption.monospacedDigit())
                                            .foregroundStyle(AppPalette.textMuted)
                                    }
                                    ProgressView(value: metric.progress)
                                        .tint(AppPalette.primary)
                                }
                            }
                        } else {
                            Text("暂无使用记录")
                                .font(AppTypography.callout)
                                .foregroundStyle(AppPalette.textMuted)
                        }
                    }

                    Divider().overlay(AppPalette.border)

                    VStack(alignment: .leading, spacing: 12) {
                        SettingsSectionTitle(icon: "list.bullet.rectangle", title: "订单记录")
                        if orders.isEmpty {
                            ContentUnavailableView("暂无订单", systemImage: "creditcard")
                                .frame(maxWidth: .infinity, minHeight: 140)
                        } else {
                            ForEach(orders) { order in
                                HStack(spacing: 14) {
                                    SettingsIconBox(icon: subscriptionPaymentIcon(order.paymentMethod))
                                    VStack(alignment: .leading, spacing: 4) {
                                        Text("\(order.planName) · \(order.periodName)")
                                            .font(AppTypography.callout.weight(.semibold))
                                        Text(order.id)
                                            .font(AppTypography.caption2.monospaced())
                                            .foregroundStyle(AppPalette.textSubtle)
                                            .lineLimit(1)
                                    }
                                    Spacer()
                                    VStack(alignment: .trailing, spacing: 4) {
                                        Text(order.amountText)
                                            .font(AppTypography.callout.weight(.bold).monospacedDigit())
                                        Text(settingsDateTime(order.createdAt, locale: model.appLanguage.locale) ?? order.createdAt)
                                            .font(AppTypography.caption2)
                                            .foregroundStyle(AppPalette.textMuted)
                                    }
                                    StatusBadge(
                                        text: subscriptionOrderStatusText(order.status),
                                        tone: subscriptionOrderStatusTone(order.status)
                                    )
                                }
                                .padding(14)
                                .background(AppPalette.card)
                                .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
                                .overlay {
                                    RoundedRectangle(cornerRadius: 8, style: .continuous)
                                        .stroke(AppPalette.border)
                                }
                            }
                        }
                    }
                }
                .padding(22)
            }
            .background(AppPalette.page)
        }
        .frame(width: 720, height: 580)
    }
}

private func subscriptionPeriodUnit(_ billingPeriod: String) -> String {
    switch billingPeriod {
    case "month": "月"
    case "quarter": "季"
    case "year": "年"
    default: "期"
    }
}

private func subscriptionPaymentIcon(_ method: String) -> String {
    switch method {
    case "alipay": "a.circle.fill"
    case "wechat": "message.fill"
    case "unionpay": "creditcard.fill"
    default: "creditcard"
    }
}

private func subscriptionStatusText(_ status: String) -> String {
    switch status {
    case "active": "订阅中"
    case "canceled": "已取消"
    case "expired": "已到期"
    default: "免费版"
    }
}

private func subscriptionOrderStatusText(_ status: String) -> String {
    switch status {
    case "paid": "已支付"
    case "failed": "支付失败"
    case "refunded": "已退款"
    case "integration_required": "待接入"
    default: "待支付"
    }
}

private func subscriptionOrderStatusTone(_ status: String) -> StatusTone {
    switch status {
    case "paid": .good
    case "failed": .critical
    case "refunded": .warning
    case "integration_required": .info
    default: .neutral
    }
}

private struct SettingsProviderCard: View {
    let provider: SettingsModelProvider
    let isSelected: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 10) {
                ZStack {
                    RoundedRectangle(cornerRadius: 9, style: .continuous)
                        .fill(AppPalette.card)
                    Image(systemName: provider.icon)
                        .font(AppTypography.system(size: 22, weight: .bold))
                        .foregroundStyle(isSelected ? AppPalette.text : AppPalette.textMuted)
                }
                .frame(width: 44, height: 44)

                VStack(alignment: .leading, spacing: 3) {
                    Text(provider.title)
                        .font(AppTypography.callout.weight(.bold))
                        .foregroundStyle(AppPalette.text)
                        .lineLimit(1)
                        .minimumScaleFactor(0.75)
                    Text(provider.vendor)
                        .font(AppTypography.caption)
                        .foregroundStyle(AppPalette.textMuted)
                        .lineLimit(1)
                        .minimumScaleFactor(0.75)
                }
                .layoutPriority(1)
                Spacer(minLength: 4)
                if isSelected {
                    Image(systemName: "checkmark.circle.fill")
                        .foregroundStyle(AppPalette.primary)
                        .font(AppTypography.system(size: 18, weight: .semibold))
                }
            }
            .padding(.horizontal, 12)
            .frame(maxWidth: .infinity, minHeight: 82, alignment: .leading)
            .background(isSelected ? AppPalette.selectedStrong : AppPalette.cardMuted.opacity(0.72))
            .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
            .overlay {
                RoundedRectangle(cornerRadius: 12, style: .continuous)
                    .stroke(isSelected ? AppPalette.primary : AppPalette.border.opacity(0.9), lineWidth: isSelected ? 1.5 : 1)
            }
        }
        .buttonStyle(.plain)
        .help(provider.compatibilityNote)
    }
}

private struct SettingsProviderBadge: View {
    let provider: SettingsModelProvider

    var body: some View {
        HStack(spacing: 5) {
            Image(systemName: provider.icon)
            Text(provider.title)
        }
        .font(AppTypography.caption.weight(.semibold))
        .foregroundStyle(AppPalette.primary)
        .padding(.horizontal, 10)
        .padding(.vertical, 5)
        .background(AppPalette.primary.opacity(0.12))
        .clipShape(RoundedRectangle(cornerRadius: 7, style: .continuous))
    }
}

private struct SettingsModelRow: View {
    let option: LLMModelOption
    let isSelected: Bool
    let isEnabled: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 14) {
                Image(systemName: isSelected ? "checkmark.circle.fill" : "circle")
                    .font(AppTypography.system(size: 19, weight: .semibold))
                    .foregroundStyle(isSelected ? AppPalette.primary : AppPalette.textSubtle.opacity(0.7))

                VStack(alignment: .leading, spacing: 4) {
                    HStack(spacing: 8) {
                        Text(option.title)
                            .font(AppTypography.callout.weight(.bold))
                            .foregroundStyle(AppPalette.text)
                        if isSelected {
                            Text("默认")
                                .font(AppTypography.caption2.weight(.bold))
                                .foregroundStyle(.white)
                                .padding(.horizontal, 6)
                                .padding(.vertical, 2)
                                .background(AppPalette.primary)
                                .clipShape(Capsule())
                        }
                        HStack(spacing: 4) {
                            Circle()
                                .fill(isEnabled ? AppPalette.success : AppPalette.textSubtle)
                                .frame(width: 7, height: 7)
                            Text(isEnabled ? "已启用" : "已禁用")
                                .font(AppTypography.caption.weight(.semibold))
                                .foregroundStyle(isEnabled ? AppPalette.success : AppPalette.textMuted)
                        }
                    }
                    Text("\(option.subtitle) · \(option.model)")
                        .font(AppTypography.caption)
                        .foregroundStyle(AppPalette.textMuted)
                        .lineLimit(1)
                }

                Spacer()
                Image(systemName: "square.and.pencil")
                    .font(AppTypography.callout.weight(.semibold))
                    .foregroundStyle(AppPalette.textSubtle)
                    .frame(width: 34, height: 34)
                    .background(AppPalette.card)
                    .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
                Image(systemName: "ellipsis")
                    .font(AppTypography.callout.weight(.semibold))
                    .foregroundStyle(AppPalette.textSubtle)
                    .frame(width: 34, height: 34)
                    .background(AppPalette.card)
                    .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
            }
            .padding(.horizontal, 16)
            .frame(minHeight: 74)
            .background(isSelected ? AppPalette.selectedStrong : AppPalette.cardMuted.opacity(0.66))
            .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
            .overlay {
                RoundedRectangle(cornerRadius: 10, style: .continuous)
                    .stroke(isSelected ? AppPalette.primary : AppPalette.border.opacity(0.85), lineWidth: isSelected ? 1.4 : 1)
            }
        }
        .buttonStyle(.plain)
    }
}

private struct SettingsConnectionStatusCard: View {
    let title: String
    let subtitle: String
    let isHealthy: Bool

    var body: some View {
        HStack(spacing: 14) {
            Image(systemName: isHealthy ? "checkmark.circle.fill" : "info.circle.fill")
                .font(AppTypography.system(size: 20, weight: .semibold))
                .foregroundStyle(isHealthy ? AppPalette.success : AppPalette.warning)
            VStack(alignment: .leading, spacing: 4) {
                Text(title)
                    .font(AppTypography.callout.weight(.bold))
                    .foregroundStyle(AppPalette.text)
                Text(subtitle)
                    .font(AppTypography.caption)
                    .foregroundStyle(AppPalette.textMuted)
            }
            Spacer()
        }
        .padding(.horizontal, 20)
        .frame(minHeight: 74)
        .background(isHealthy ? AppPalette.success.opacity(0.10) : AppPalette.warning.opacity(0.10))
        .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: 12, style: .continuous)
                .stroke((isHealthy ? AppPalette.success : AppPalette.warning).opacity(0.28))
        }
    }
}

private struct SettingsLanguageOption: Identifiable {
    let id: String
    let flag: String
    let title: String
    let subtitle: String
    let language: AppLanguage

    static let options: [SettingsLanguageOption] = [
        SettingsLanguageOption(id: "zh-Hans", flag: "🇨🇳", title: "简体中文", subtitle: "Chinese (Simplified)", language: .zhHans),
        SettingsLanguageOption(id: "zh-Hant", flag: "🇭🇰", title: "繁體中文", subtitle: "Chinese (Traditional)", language: .zhHant),
        SettingsLanguageOption(id: "en", flag: "🇺🇸", title: "English", subtitle: "English", language: .en),
        SettingsLanguageOption(id: "ko", flag: "🇰🇷", title: "한국어", subtitle: "Korean", language: .ko),
        SettingsLanguageOption(id: "ja", flag: "🇯🇵", title: "日本語", subtitle: "Japanese", language: .ja),
        SettingsLanguageOption(id: "es", flag: "🇪🇸", title: "Español", subtitle: "Spanish", language: .es),
        SettingsLanguageOption(id: "fr", flag: "🇫🇷", title: "Français", subtitle: "French", language: .fr),
        SettingsLanguageOption(id: "de", flag: "🇩🇪", title: "Deutsch", subtitle: "German", language: .de),
        SettingsLanguageOption(id: "it", flag: "🇮🇹", title: "Italiano", subtitle: "Italian", language: .it),
        SettingsLanguageOption(id: "ru", flag: "🇷🇺", title: "Русский", subtitle: "Russian", language: .ru),
    ]
}

private struct SettingsLanguageRow: View {
    let option: SettingsLanguageOption
    let isSelected: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 14) {
                Text(option.flag).font(AppTypography.title3)
                VStack(alignment: .leading, spacing: 2) {
                    Text(option.title)
                        .font(AppTypography.callout.weight(.bold))
                        .foregroundStyle(AppPalette.text)
                    Text(option.subtitle)
                        .font(AppTypography.caption)
                        .foregroundStyle(AppPalette.textMuted)
                }
                Spacer()
                if isSelected {
                    Image(systemName: "checkmark.circle.fill")
                        .foregroundStyle(AppPalette.primary)
                }
            }
            .padding(.horizontal, 16)
            .frame(minHeight: 58)
            .background(isSelected ? AppPalette.selectedStrong : AppPalette.cardMuted.opacity(0.72))
            .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
            .overlay {
                RoundedRectangle(cornerRadius: 10, style: .continuous)
                    .stroke(isSelected ? AppPalette.primary : AppPalette.border.opacity(0.88))
            }
        }
        .buttonStyle(.plain)
    }
}

private struct SettingsAboutRow: View {
    let icon: String
    let title: String
    var trailing: String?
    let action: () -> Void

    init(icon: String, title: String, trailing: String? = nil, action: @escaping () -> Void) {
        self.icon = icon
        self.title = title
        self.trailing = trailing
        self.action = action
    }

    var body: some View {
        Button(action: action) {
            HStack(spacing: 14) {
                SettingsIconBox(icon: icon)
                Text(title)
                    .font(AppTypography.callout.weight(.semibold))
                    .foregroundStyle(AppPalette.text)
                Spacer()
                if let trailing {
                    Text(trailing)
                        .font(AppTypography.caption.weight(.semibold))
                        .foregroundStyle(AppPalette.success)
                }
                Image(systemName: "chevron.right")
                    .font(AppTypography.caption.weight(.bold))
                    .foregroundStyle(AppPalette.textSubtle)
            }
            .padding(.vertical, 12)
        }
        .buttonStyle(.plain)
    }
}

private struct SettingsDivider: View {
    var body: some View {
        Rectangle()
            .fill(AppPalette.border.opacity(0.68))
            .frame(height: 1)
            .padding(.leading, 48)
    }
}

private struct SettingsDocumentCard: View {
    let document: SettingsDocument
    let backendDocument: LegalDocumentSnapshot?

    var body: some View {
        VStack(alignment: .leading, spacing: 24) {
            VStack(spacing: 7) {
                Text(backendDocument?.heading ?? document.heading)
                    .font(AppTypography.title2.weight(.bold))
                    .foregroundStyle(AppPalette.text)
                Text("最后更新日期：\(backendDocument?.updatedAt ?? document.updatedAt)")
                    .font(AppTypography.caption)
                    .foregroundStyle(AppPalette.textSubtle)
                Text("生效日期：\(backendDocument?.effectiveAt ?? document.effectiveAt)")
                    .font(AppTypography.caption)
                    .foregroundStyle(AppPalette.textSubtle)
            }
            .frame(maxWidth: .infinity)
            .padding(.top, 16)
            .padding(.bottom, 24)

            Text(backendDocument?.intro ?? document.intro)
                .font(AppTypography.callout)
                .foregroundStyle(AppPalette.textMuted)
                .lineSpacing(4)
                .padding(18)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(AppPalette.cardMuted.opacity(0.85))
                .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))

            ForEach(Array(documentSections.enumerated()), id: \.offset) { _, section in
                VStack(alignment: .leading, spacing: 12) {
                    Text(section.heading)
                        .font(AppTypography.headline.weight(.bold))
                        .foregroundStyle(AppPalette.text)
                    ForEach(section.paragraphs, id: \.self) { line in
                        Text(line)
                            .font(AppTypography.callout)
                            .foregroundStyle(line.hasPrefix("邮箱：") ? AppPalette.primary : AppPalette.textMuted)
                            .lineSpacing(4)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
            }
        }
        .padding(42)
        .background(AppPalette.card)
        .clipShape(RoundedRectangle(cornerRadius: 14, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: 14, style: .continuous)
                .stroke(AppPalette.border.opacity(0.9))
        }
    }

    private var documentSections: [LegalDocumentSectionSnapshot] {
        if let sections = backendDocument?.sections, !sections.isEmpty {
            return sections
        }
        return document.sections.map {
            LegalDocumentSectionSnapshot(heading: $0.0, paragraphs: $0.1)
        }
    }
}

private struct SettingsPrimaryButtonStyle: ButtonStyle {
    var height: CGFloat = 42

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(AppTypography.callout.weight(.semibold))
            .foregroundStyle(.white)
            .padding(.horizontal, 20)
            .frame(height: height)
            .background(configuration.isPressed ? AppPalette.primaryStrong : AppPalette.primary)
            .clipShape(RoundedRectangle(cornerRadius: 9, style: .continuous))
    }
}

private struct SettingsSecondaryButtonStyle: ButtonStyle {
    var height: CGFloat = 42

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(AppTypography.callout.weight(.semibold))
            .foregroundStyle(AppPalette.textMuted)
            .padding(.horizontal, 18)
            .frame(height: height)
            .background(configuration.isPressed ? AppPalette.cardMuted.opacity(0.78) : AppPalette.cardMuted)
            .clipShape(RoundedRectangle(cornerRadius: 9, style: .continuous))
            .overlay {
                RoundedRectangle(cornerRadius: 9, style: .continuous)
                    .stroke(AppPalette.border.opacity(0.9))
            }
    }
}

private struct SettingsDangerButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(AppTypography.callout.weight(.semibold))
            .foregroundStyle(AppPalette.danger)
            .padding(.horizontal, 18)
            .frame(height: 48)
            .background(configuration.isPressed ? AppPalette.danger.opacity(0.10) : AppPalette.card)
            .clipShape(RoundedRectangle(cornerRadius: 9, style: .continuous))
            .overlay {
                RoundedRectangle(cornerRadius: 9, style: .continuous)
                    .stroke(AppPalette.danger.opacity(0.9))
            }
    }
}

private struct SettingsModelProvider: Identifiable, Equatable {
    let id: String
    let title: String
    let vendor: String
    let subtitle: String
    let icon: String
    let backendProvider: LLMProvider
    let defaultEndpoint: String
    let placeholder: String
    let models: [LLMModelOption]
    let docsURL: URL
    let keyURL: URL

    var defaultModel: String { models.first?.model ?? "" }

    var wireAPI: String? { backendProvider == .custom ? (id == "sub2api" ? "responses" : "chat") : nil }
    var reasoningEffort: String? { id == "sub2api" ? "xhigh" : (backendProvider == .custom ? "none" : nil) }
    var disableResponseStorage: Bool? { backendProvider == .custom ? id == "sub2api" : nil }

    var compatibilityNote: String {
        backendProvider == .custom ? "该厂商按 OpenAI 兼容接口保存到后端自定义模型配置。" : "该厂商由后端原生模型链路支持。"
    }

    static let providers: [SettingsModelProvider] = [
        SettingsModelProvider(
            id: "sub2api",
            title: "Sub2API",
            vendor: "自定义网关",
            subtitle: "GPT-5.6 Sol · Responses API",
            icon: "bolt.horizontal.circle",
            backendProvider: .custom,
            defaultEndpoint: "https://carpool.composiastack.com",
            placeholder: "sk-••••••••••••••••••••",
            models: [
                LLMModelOption(title: "GPT-5.6 Sol", model: "gpt-5.6-sol", subtitle: "极高推理 · 不存储响应"),
            ],
            docsURL: URL(string: "https://carpool.composiastack.com")!,
            keyURL: URL(string: "https://carpool.composiastack.com")!
        ),
        SettingsModelProvider(
            id: "openai",
            title: "OpenAI",
            vendor: "美国",
            subtitle: "OpenAI 官方接口",
            icon: "sparkles",
            backendProvider: .openai,
            defaultEndpoint: "https://api.openai.com/v1",
            placeholder: "sk-proj-••••••••••••••••••••••",
            models: [
                LLMModelOption(title: "GPT-5.6", model: "gpt-5.6", subtitle: "Sol 官方别名 · 推荐"),
                LLMModelOption(title: "GPT-5.6 Sol", model: "gpt-5.6-sol", subtitle: "旗舰能力 · 复杂生产工作流"),
                LLMModelOption(title: "GPT-5.6 Terra", model: "gpt-5.6-terra", subtitle: "能力、成本与速度平衡"),
                LLMModelOption(title: "GPT-5.6 Luna", model: "gpt-5.6-luna", subtitle: "高吞吐 · 低延迟"),
                LLMModelOption(title: "GPT-5.4", model: "gpt-5.4", subtitle: "兼容既有 GPT-5 工作流"),
            ],
            docsURL: URL(string: "https://developers.openai.com/api/docs/models")!,
            keyURL: URL(string: "https://platform.openai.com/api-keys")!
        ),
        SettingsModelProvider(
            id: "anthropic",
            title: "Anthropic",
            vendor: "美国",
            subtitle: "Claude Messages API",
            icon: "atom",
            backendProvider: .claude,
            defaultEndpoint: "https://api.anthropic.com/v1",
            placeholder: "sk-ant-••••••••••••••••••••",
            models: [
                LLMModelOption(title: "Claude Sonnet 5", model: "claude-sonnet-5", subtitle: "速度与能力平衡"),
                LLMModelOption(title: "Claude Fable 5", model: "claude-fable-5", subtitle: "最高能力模型"),
                LLMModelOption(title: "Claude Opus 4.8", model: "claude-opus-4-8", subtitle: "复杂智能体与企业工作"),
                LLMModelOption(title: "Claude Haiku 4.5", model: "claude-haiku-4-5", subtitle: "低延迟 · 轻量任务"),
            ],
            docsURL: URL(string: "https://platform.claude.com/docs/en/about-claude/models/overview")!,
            keyURL: URL(string: "https://console.anthropic.com/settings/keys")!
        ),
        SettingsModelProvider(
            id: "google",
            title: "Google",
            vendor: "美国",
            subtitle: "Gemini OpenAI 兼容",
            icon: "g.circle.fill",
            backendProvider: .custom,
            defaultEndpoint: "https://generativelanguage.googleapis.com/v1beta/openai",
            placeholder: "AIza••••••••••••••••••••",
            models: [
                LLMModelOption(title: "Gemini 3.5 Flash", model: "gemini-3.5-flash", subtitle: "稳定版 · 智能体与编码"),
                LLMModelOption(title: "Gemini 3.1 Pro", model: "gemini-3.1-pro-preview", subtitle: "高级推理 · 预览版"),
                LLMModelOption(title: "Gemini 3 Flash", model: "gemini-3-flash-preview", subtitle: "高性价比 · 预览版"),
                LLMModelOption(title: "Gemini 3.1 Flash-Lite", model: "gemini-3.1-flash-lite", subtitle: "稳定版 · 低成本"),
                LLMModelOption(title: "Gemini 2.5 Pro", model: "gemini-2.5-pro", subtitle: "复杂推理与编码"),
                LLMModelOption(title: "Gemini 2.5 Flash", model: "gemini-2.5-flash", subtitle: "低延迟 · 高吞吐"),
                LLMModelOption(title: "Gemini 2.5 Flash-Lite", model: "gemini-2.5-flash-lite", subtitle: "经济型多模态模型"),
            ],
            docsURL: URL(string: "https://ai.google.dev/gemini-api/docs/models")!,
            keyURL: URL(string: "https://aistudio.google.com/app/apikey")!
        ),
        SettingsModelProvider(
            id: "meta",
            title: "Meta",
            vendor: "美国",
            subtitle: "Llama 兼容接口",
            icon: "infinity",
            backendProvider: .custom,
            defaultEndpoint: "https://api.llama.com/compat/v1",
            placeholder: "llama-••••••••••••••••",
            models: [
                LLMModelOption(title: "llama-3.1-405b", model: "llama-3.1-405b-instruct", subtitle: "开源生态 · 高能力"),
                LLMModelOption(title: "llama-3.1-70b", model: "llama-3.1-70b-instruct", subtitle: "开源生态 · 平衡模型"),
            ],
            docsURL: URL(string: "https://llama.developer.meta.com/docs/models")!,
            keyURL: URL(string: "https://llama.developer.meta.com")!
        ),
        SettingsModelProvider(
            id: "deepseek",
            title: "DeepSeek",
            vendor: "中国",
            subtitle: "DeepSeek 官方接口",
            icon: "lightbulb",
            backendProvider: .deepseek,
            defaultEndpoint: "https://api.deepseek.com/v1",
            placeholder: "sk-••••••••••••••••••••••",
            models: [
                LLMModelOption(title: "DeepSeek V4 Flash", model: "deepseek-v4-flash", subtitle: "低延迟 · 默认思考模式"),
                LLMModelOption(title: "DeepSeek V4 Pro", model: "deepseek-v4-pro", subtitle: "高能力 · 复杂任务"),
            ],
            docsURL: URL(string: "https://api-docs.deepseek.com/quick_start/pricing")!,
            keyURL: URL(string: "https://platform.deepseek.com/api_keys")!
        ),
        SettingsModelProvider(
            id: "qwen",
            title: "通义千问",
            vendor: "阿里",
            subtitle: "DashScope OpenAI 兼容",
            icon: "sparkle.magnifyingglass",
            backendProvider: .custom,
            defaultEndpoint: "https://dashscope.aliyuncs.com/compatible-mode/v1",
            placeholder: "sk-••••••••••••••••••••••",
            models: [
                LLMModelOption(title: "Qwen 3.8 Max Preview", model: "qwen3.8-max-preview", subtitle: "最新预览文本模型"),
                LLMModelOption(title: "Qwen 3.7 Max", model: "qwen3.7-max", subtitle: "高能力 · 复杂推理"),
                LLMModelOption(title: "Qwen 3.7 Plus", model: "qwen3.7-plus", subtitle: "通用任务 · 视觉理解"),
                LLMModelOption(title: "Qwen 3.7 Flash", model: "qwen3.7-flash", subtitle: "低延迟 · 高吞吐"),
            ],
            docsURL: URL(string: "https://help.aliyun.com/zh/model-studio/models")!,
            keyURL: URL(string: "https://bailian.console.aliyun.com")!
        ),
        SettingsModelProvider(
            id: "ernie",
            title: "文心一言",
            vendor: "百度",
            subtitle: "千帆兼容接口",
            icon: "cloud",
            backendProvider: .custom,
            defaultEndpoint: "https://qianfan.baidubce.com/v2",
            placeholder: "bce-v3/••••••••••••••",
            models: [
                LLMModelOption(title: "ernie-4.0", model: "ernie-4.0-turbo-8k", subtitle: "中文理解 · 企业场景"),
                LLMModelOption(title: "ernie-speed", model: "ernie-speed-128k", subtitle: "快速响应 · 长上下文"),
            ],
            docsURL: URL(string: "https://cloud.baidu.com/doc/qianfan/index.html")!,
            keyURL: URL(string: "https://console.bce.baidu.com/qianfan/ais/console/applicationConsole/application")!
        ),
        SettingsModelProvider(
            id: "zhipu",
            title: "智谱 AI",
            vendor: "中国",
            subtitle: "GLM OpenAI 兼容",
            icon: "bolt",
            backendProvider: .custom,
            defaultEndpoint: "https://open.bigmodel.cn/api/paas/v4",
            placeholder: "••••••••.••••••••",
            models: [
                LLMModelOption(title: "GLM-5", model: "glm-5", subtitle: "旗舰文本模型"),
                LLMModelOption(title: "GLM-5 Turbo", model: "glm-5-turbo", subtitle: "高吞吐文本模型"),
                LLMModelOption(title: "GLM-5.2", model: "glm-5.2", subtitle: "新一代通用模型"),
                LLMModelOption(title: "GLM-5.1", model: "glm-5.1", subtitle: "通用推理模型"),
                LLMModelOption(title: "GLM-4.7", model: "glm-4.7", subtitle: "稳定通用模型"),
                LLMModelOption(title: "GLM-4.7 Flash", model: "glm-4.7-flash", subtitle: "低延迟通用模型"),
            ],
            docsURL: URL(string: "https://docs.bigmodel.cn/cn/guide/models/text/glm-4.5")!,
            keyURL: URL(string: "https://open.bigmodel.cn/usercenter/apikeys")!
        ),
        SettingsModelProvider(
            id: "spark",
            title: "讯飞星火",
            vendor: "科大讯飞",
            subtitle: "星火兼容接口",
            icon: "flame",
            backendProvider: .custom,
            defaultEndpoint: "https://spark-api-open.xf-yun.com/v1",
            placeholder: "spark-••••••••••••••",
            models: [
                LLMModelOption(title: "spark-max", model: "generalv3.5", subtitle: "中文任务 · 通用模型"),
                LLMModelOption(title: "spark-pro", model: "generalv3", subtitle: "平衡能力 · 低成本"),
            ],
            docsURL: URL(string: "https://www.xfyun.cn/doc/spark/Web.html")!,
            keyURL: URL(string: "https://console.xfyun.cn/services/bm35")!
        ),
        SettingsModelProvider(
            id: "moonshot",
            title: "月之暗面",
            vendor: "Kimi",
            subtitle: "Moonshot OpenAI 兼容",
            icon: "moon",
            backendProvider: .custom,
            defaultEndpoint: "https://api.moonshot.cn/v1",
            placeholder: "sk-••••••••••••••••••••",
            models: [
                LLMModelOption(title: "Kimi K3", model: "kimi-k3", subtitle: "旗舰编程、知识工作与深度推理"),
                LLMModelOption(title: "Kimi K2.7 Code", model: "kimi-k2.7-code", subtitle: "编程与代码智能体"),
                LLMModelOption(title: "Kimi K2.7 Code Highspeed", model: "kimi-k2.7-code-highspeed", subtitle: "高速编程模型"),
                LLMModelOption(title: "Kimi K2.6", model: "kimi-k2.6", subtitle: "通用对话、智能体与复杂推理"),
                LLMModelOption(title: "Kimi K2.5", model: "kimi-k2.5", subtitle: "兼容既有 Kimi 工作流"),
            ],
            docsURL: URL(string: "https://platform.kimi.com/docs/models")!,
            keyURL: URL(string: "https://platform.kimi.com/console/api-keys")!
        ),
        SettingsModelProvider(
            id: "stepfun",
            title: "阶跃星辰",
            vendor: "StepFun",
            subtitle: "Step OpenAI 兼容",
            icon: "star",
            backendProvider: .custom,
            defaultEndpoint: "https://api.stepfun.com/v1",
            placeholder: "sk-••••••••••••••••••••",
            models: [
                LLMModelOption(title: "step-2", model: "step-2-16k", subtitle: "中文推理 · 复杂任务"),
                LLMModelOption(title: "step-1", model: "step-1-32k", subtitle: "通用任务 · 长上下文"),
            ],
            docsURL: URL(string: "https://platform.stepfun.com/docs/llm/text")!,
            keyURL: URL(string: "https://platform.stepfun.com/interface-key")!
        ),
        SettingsModelProvider(
            id: "custom",
            title: "自定义",
            vendor: "OpenAI 兼容",
            subtitle: "自定义模型网关",
            icon: "plus",
            backendProvider: .custom,
            defaultEndpoint: "https://api.example.com/v1",
            placeholder: "sk-••••••••••••••••••••",
            models: [
                LLMModelOption(title: "自定义模型", model: "gpt-5.6-sol", subtitle: "OpenAI 兼容 · 自定义端点"),
            ],
            docsURL: URL(string: "https://platform.openai.com/docs/api-reference")!,
            keyURL: URL(string: "https://platform.openai.com/api-keys")!
        ),
    ]

    static func provider(forBackendProvider backendProvider: String, endpoint: String) -> SettingsModelProvider? {
        if backendProvider == LLMProvider.openai.rawValue {
            return providers.first { $0.id == "openai" }
        }
        if backendProvider == LLMProvider.claude.rawValue {
            return providers.first { $0.id == "anthropic" }
        }
        if backendProvider == LLMProvider.deepseek.rawValue {
            return providers.first { $0.id == "deepseek" }
        }
        if backendProvider == LLMProvider.custom.rawValue {
            let endpointHost = URL(string: endpoint)?.host
            return providers.first {
                $0.backendProvider == .custom
                    && endpointHost != nil
                    && URL(string: $0.defaultEndpoint)?.host == endpointHost
            } ?? providers.first { $0.id == "custom" }
        }
        return providers.first { $0.id == "openai" }
    }
}

private extension AboutSettingsSnapshot {
    static let defaultFeatures = [
        "智能问答：基于大语言模型的网络安全知识问答，支持漏洞分析、渗透测试建议等",
        "情报采集：多源安全情报聚合与分析，实时追踪最新安全动态",
        "知识图谱：安全领域实体关系可视化，快速定位关联信息",
        "漏洞库：全面的漏洞数据库，支持 CVE 编号查询与修复建议",
    ]
}

struct LLMModelOption: Identifiable, Equatable {
    let title: String
    let model: String
    let subtitle: String

    var id: String { model }
}

enum LLMProvider: String, CaseIterable, Identifiable {
    case openai
    case claude
    case deepseek
    case custom

    var id: String { rawValue }

    var title: String {
        switch self {
        case .openai: "OpenAI"
        case .claude: "Anthropic"
        case .deepseek: "DeepSeek"
        case .custom: "Sub2API"
        }
    }

    var subtitle: String {
        switch self {
        case .openai: "OpenAI Responses / Models API"
        case .claude: "Claude Messages / Models API"
        case .deepseek: "DeepSeek Chat Completions"
        case .custom: "Responses API 自定义网关"
        }
    }

    var icon: String {
        switch self {
        case .openai: "sparkles"
        case .claude: "atom"
        case .deepseek: "lightbulb"
        case .custom: "network"
        }
    }

    var defaultModel: String {
        switch self {
        case .openai: modelOptions[0].model
        case .claude: modelOptions[0].model
        case .deepseek: modelOptions[0].model
        case .custom: modelOptions[0].model
        }
    }

    var defaultEndpoint: String {
        switch self {
        case .openai: "https://api.openai.com/v1"
        case .claude: "https://api.anthropic.com/v1"
        case .deepseek: "https://api.deepseek.com/v1"
        case .custom: "https://carpool.composiastack.com"
        }
    }

    var placeholder: String {
        switch self {
        case .openai: "sk-proj-••••••••••••••••••••••"
        case .claude: "sk-ant-••••••••••••••••••••"
        case .deepseek: "sk-••••••••••••••••••••••"
        case .custom: "sk-••••••••••••••••••••••"
        }
    }

    var modelOptions: [LLMModelOption] {
        switch self {
        case .openai:
            [
                LLMModelOption(title: "GPT-5.6", model: "gpt-5.6", subtitle: "Sol 官方别名 · 推荐"),
                LLMModelOption(title: "GPT-5.6 Sol", model: "gpt-5.6-sol", subtitle: "旗舰能力"),
                LLMModelOption(title: "GPT-5.6 Terra", model: "gpt-5.6-terra", subtitle: "能力与成本平衡"),
                LLMModelOption(title: "GPT-5.6 Luna", model: "gpt-5.6-luna", subtitle: "高吞吐低延迟"),
                LLMModelOption(title: "GPT-5.4", model: "gpt-5.4", subtitle: "兼容既有 GPT-5 工作流"),
            ]
        case .claude:
            [
                LLMModelOption(title: "Claude Sonnet 5", model: "claude-sonnet-5", subtitle: "速度与能力平衡"),
                LLMModelOption(title: "Claude Fable 5", model: "claude-fable-5", subtitle: "最高能力模型"),
                LLMModelOption(title: "Claude Opus 4.8", model: "claude-opus-4-8", subtitle: "复杂智能体与企业工作"),
                LLMModelOption(title: "Claude Haiku 4.5", model: "claude-haiku-4-5", subtitle: "低延迟轻量模型"),
            ]
        case .deepseek:
            [
                LLMModelOption(title: "DeepSeek V4 Flash", model: "deepseek-v4-flash", subtitle: "低延迟 · 默认思考模式"),
                LLMModelOption(title: "DeepSeek V4 Pro", model: "deepseek-v4-pro", subtitle: "高能力复杂任务"),
            ]
        case .custom:
            [
                LLMModelOption(title: "GPT-5.6 Sol", model: "gpt-5.6-sol", subtitle: "极高推理 · Responses API"),
            ]
        }
    }

    var keyURL: URL {
        switch self {
        case .openai: URL(string: "https://platform.openai.com/api-keys")!
        case .claude: URL(string: "https://console.anthropic.com/settings/keys")!
        case .deepseek: URL(string: "https://platform.deepseek.com/api_keys")!
        case .custom: URL(string: "https://platform.openai.com/api-keys")!
        }
    }
}

private func settingsDateTime(_ value: String, locale: Locale) -> String? {
    let iso = ISO8601DateFormatter()
    iso.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    let date = iso.date(from: value) ?? {
        let fallback = ISO8601DateFormatter()
        fallback.formatOptions = [.withInternetDateTime]
        return fallback.date(from: value)
    }()
    guard let date else { return nil }
    let formatter = DateFormatter()
    formatter.calendar = Calendar(identifier: .gregorian)
    formatter.locale = locale
    formatter.dateFormat = "yyyy-MM-dd HH:mm"
    return formatter.string(from: date)
}
