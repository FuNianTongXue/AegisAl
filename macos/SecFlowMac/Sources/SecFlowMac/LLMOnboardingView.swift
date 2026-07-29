import SwiftUI

private let onboardingCustomModel = "__secflow_onboarding_custom_model__"

enum PostLoginSetupRules {
    static func isProfileComplete(_ profile: UserProfileSettingsSnapshot?, userID: String) -> Bool {
        guard let profile else { return false }
        let cleanUserID = normalized(userID)
        return !cleanUserID.isEmpty
            && normalized(profile.email) == cleanUserID
            && !normalized(profile.displayName).isEmpty
            && !normalized(profile.department).isEmpty
            && !normalized(profile.role).isEmpty
            && !normalized(profile.updatedAt).isEmpty
    }

    static func isModelComplete(_ config: LLMConfigSnapshot?) -> Bool {
        config?.configured == true && config?.hasApiKey == true
    }

    static func firstIncompleteStep(
        profile: UserProfileSettingsSnapshot?,
        userID: String,
        llmConfig: LLMConfigSnapshot?
    ) -> Int? {
        if !isProfileComplete(profile, userID: userID) { return 1 }
        if !isModelComplete(llmConfig) { return 3 }
        return nil
    }

    private static func normalized(_ value: String) -> String {
        value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    }
}

private struct PostLoginRoleOption: Identifiable {
    let id: String
    let icon: String
    let description: String
}

struct PostLoginSetupView: View {
    @EnvironmentObject private var model: AppModel

    @State private var step = 1
    @State private var displayName = ""
    @State private var phone = ""
    @State private var department = ""
    @State private var employeeID = ""
    @State private var bio = ""
    @State private var role = ""
    @State private var profileError: String?
    @State private var provider: LLMProvider = .openai
    @State private var selectedModel = LLMProvider.openai.defaultModel
    @State private var customModel = ""
    @State private var endpoint = LLMProvider.openai.defaultEndpoint
    @State private var apiKey = ""
    @State private var isKeyVisible = false
    @State private var testResult: LLMTestResult?
    @State private var didBootstrap = false
    @State private var didHydrateConfiguration = false

    private let totalSteps = 6
    private let roles = [
        PostLoginRoleOption(id: "安全分析师", icon: "shield.lefthalf.filled", description: "漏洞研判、告警分析与安全运营"),
        PostLoginRoleOption(id: "安全工程师", icon: "wrench.and.screwdriver.fill", description: "安全研发、规则维护与扫描治理"),
        PostLoginRoleOption(id: "安全管理员", icon: "person.badge.key.fill", description: "团队管理、策略配置与风险审计"),
        PostLoginRoleOption(id: "开发工程师", icon: "chevron.left.forwardslash.chevron.right", description: "代码修复、依赖治理与研发协作"),
        PostLoginRoleOption(id: "项目负责人", icon: "person.2.fill", description: "项目统筹、风险跟踪与交付决策"),
        PostLoginRoleOption(id: "其他", icon: "ellipsis.circle.fill", description: "使用通用的安全分析工作区"),
    ]

    private var isTesting: Bool { model.busyActions.contains("llm-test") }
    private var isSavingModel: Bool { model.busyActions.contains("llm-save") }
    private var isSavingProfile: Bool { model.busyActions.contains("settings-profile-save") }

    var body: some View {
        HStack(spacing: 0) {
            stepRail
                .frame(width: 286)
            Divider()
            VStack(alignment: .leading, spacing: 0) {
                header
                Divider()
                ScrollView {
                    stepContent
                        .padding(36)
                        .frame(maxWidth: 760, alignment: .leading)
                        .frame(maxWidth: .infinity, alignment: .topLeading)
                }
                navigation
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(AppPalette.page)
        .foregroundStyle(AppPalette.text)
        .task { await bootstrap() }
        .onChange(of: model.llmConfig) { _, _ in
            hydrateConfiguration()
        }
    }

    private var stepRail: some View {
        VStack(alignment: .leading, spacing: 26) {
            HStack(spacing: 12) {
                AppBrandLogo(size: 40, shadow: false)
                VStack(alignment: .leading, spacing: 2) {
                    Text(model.text(.appName))
                        .font(AppTypography.headline)
                        .foregroundStyle(AppPalette.onBrand)
                    Text(model.uiText("登录后设置"))
                        .font(AppTypography.caption)
                        .foregroundStyle(AppPalette.onBrandMuted)
                }
            }

            VStack(alignment: .leading, spacing: 14) {
                ForEach(1...totalSteps, id: \.self) { item in
                    onboardingStepRow(item)
                }
            }

            Spacer()
            LanguagePickerMenu(variant: .sidebar)
            Label(model.uiText("资料保存在本机，密钥加密存储"), systemImage: "lock.fill")
                .font(AppTypography.caption)
                .foregroundStyle(AppPalette.onBrandMuted)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(30)
        .frame(maxHeight: .infinity, alignment: .topLeading)
        .background { SidebarGlassBackground() }
    }

    private func onboardingStepRow(_ item: Int) -> some View {
        let titles = ["用户资料", "选择角色", "选择模型厂商", "选择模型", "填写连接信息", "验证并完成"].map { model.uiText($0) }
        let isCurrent = step == item
        let isCompleted = step > item
        return HStack(spacing: 12) {
            ZStack {
                Circle()
                    .fill(isCurrent || isCompleted ? AppPalette.primary : Color.white.opacity(0.10))
                    .frame(width: 30, height: 30)
                if isCompleted {
                    Image(systemName: "checkmark")
                        .font(AppTypography.caption.weight(.bold))
                        .foregroundStyle(.white)
                } else {
                    Text("\(item)")
                        .font(AppTypography.caption.weight(.bold))
                        .foregroundStyle(isCurrent ? .white : AppPalette.onBrandMuted)
                }
            }
            Text(titles[item - 1])
                .font(AppTypography.callout.weight(isCurrent ? .semibold : .regular))
                .foregroundStyle(isCurrent ? AppPalette.onBrand : AppPalette.onBrandMuted)
        }
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                VStack(alignment: .leading, spacing: 4) {
                    Text(model.uiText("完成账户设置"))
                        .font(AppTypography.title2.weight(.semibold))
                    Text(headerSubtitle)
                        .font(AppTypography.callout)
                        .foregroundStyle(AppPalette.textMuted)
                }
                Spacer()
                Text(model.uiText("第 %d / %d 步", step, totalSteps))
                    .font(AppTypography.caption.weight(.semibold))
                    .foregroundStyle(AppPalette.primaryStrong)
            }
            ProgressView(value: Double(step), total: Double(totalSteps))
                .tint(AppPalette.primary)
        }
        .padding(.horizontal, 36)
        .padding(.vertical, 24)
        .background(AppPalette.card)
    }

    private var headerSubtitle: String {
        if step <= 2 {
            return model.uiText("先设置用户资料和工作角色，再配置使用的 AI 模型")
        }
        return model.uiText("模型验证成功后即可使用智能问答和报告分析")
    }

    @ViewBuilder
    private var stepContent: some View {
        switch step {
        case 1: profileStep
        case 2: roleStep
        case 3: providerStep
        case 4: modelStep
        case 5: connectionStep
        default: verificationStep
        }
    }

    private var profileStep: some View {
        VStack(alignment: .leading, spacing: 22) {
            stepHeading(model.uiText("设置用户资料"), subtitle: model.uiText("这些信息用于任务归属、报告署名和团队协作"))
            VStack(alignment: .leading, spacing: 18) {
                setupField(model.uiText("昵称"), required: true) {
                    TextField(model.uiText("请输入昵称"), text: $displayName)
                        .textFieldStyle(LightFieldStyle())
                }
                setupField(model.uiText("登录账号")) {
                    HStack {
                        Image(systemName: "envelope")
                            .foregroundStyle(AppPalette.textMuted)
                        Text(model.userID)
                            .font(AppTypography.callout)
                            .foregroundStyle(AppPalette.text)
                        Spacer()
                        Text(model.uiText("不可修改"))
                            .font(AppTypography.caption)
                            .foregroundStyle(AppPalette.textSubtle)
                    }
                    .padding(.horizontal, 11)
                    .frame(height: 38)
                    .background(AppPalette.page)
                    .clipShape(RoundedRectangle(cornerRadius: 7, style: .continuous))
                    .overlay { RoundedRectangle(cornerRadius: 7).stroke(AppPalette.border) }
                }
                HStack(alignment: .top, spacing: 14) {
                    setupField(model.uiText("部门"), required: true) {
                        TextField(model.uiText("例如：安全研发部"), text: $department)
                            .textFieldStyle(LightFieldStyle())
                    }
                    setupField(model.uiText("手机号")) {
                        TextField(model.uiText("选填"), text: $phone)
                            .textFieldStyle(LightFieldStyle())
                    }
                }
                setupField(model.uiText("工号")) {
                    TextField(model.uiText("选填"), text: $employeeID)
                        .textFieldStyle(LightFieldStyle())
                }
                setupField(model.uiText("个人简介")) {
                    TextField(model.uiText("选填，最多 200 字"), text: $bio, axis: .vertical)
                        .lineLimit(3...5)
                        .textFieldStyle(LightFieldStyle())
                }
            }
            .padding(22)
            .frame(maxWidth: 640)
            .background(AppPalette.card)
            .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
            .overlay { RoundedRectangle(cornerRadius: 8).stroke(AppPalette.border) }

            if let profileError {
                Label(profileError, systemImage: "exclamationmark.circle.fill")
                    .font(AppTypography.callout)
                    .foregroundStyle(AppPalette.danger)
            }
        }
    }

    private var roleStep: some View {
        VStack(alignment: .leading, spacing: 22) {
            stepHeading(model.uiText("选择工作角色"), subtitle: model.uiText("角色用于调整智能体的回答侧重点和报告表达"))
            LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], spacing: 14) {
                ForEach(roles) { item in
                    Button {
                        role = item.id
                        profileError = nil
                    } label: {
                        HStack(alignment: .top, spacing: 14) {
                            Image(systemName: item.icon)
                                .font(AppTypography.title3.weight(.semibold))
                                .foregroundStyle(role == item.id ? .white : AppPalette.primaryStrong)
                                .frame(width: 28)
                            VStack(alignment: .leading, spacing: 5) {
                                Text(model.uiText(item.id))
                                    .font(AppTypography.headline)
                                    .foregroundStyle(role == item.id ? .white : AppPalette.text)
                                Text(model.uiText(item.description))
                                    .font(AppTypography.caption)
                                    .foregroundStyle(role == item.id ? Color.white.opacity(0.76) : AppPalette.textMuted)
                                    .fixedSize(horizontal: false, vertical: true)
                            }
                            Spacer(minLength: 0)
                            Image(systemName: role == item.id ? "checkmark.circle.fill" : "circle")
                                .foregroundStyle(role == item.id ? .white : AppPalette.textSubtle)
                        }
                        .padding(17)
                        .frame(maxWidth: .infinity, minHeight: 92, alignment: .leading)
                        .background(role == item.id ? AppPalette.primary : AppPalette.card)
                        .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
                        .overlay {
                            RoundedRectangle(cornerRadius: 8, style: .continuous)
                                .stroke(role == item.id ? AppPalette.primaryStrong.opacity(0.28) : AppPalette.border)
                        }
                    }
                    .buttonStyle(.plain)
                }
            }
            if let profileError {
                Label(profileError, systemImage: "exclamationmark.circle.fill")
                    .font(AppTypography.callout)
                    .foregroundStyle(AppPalette.danger)
            }
        }
    }

    private var providerStep: some View {
        VStack(alignment: .leading, spacing: 22) {
            stepHeading(model.uiText("选择模型厂商"), subtitle: model.uiText("请选择你已经开通 API 服务的厂商"))
            LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible()), GridItem(.flexible())], spacing: 14) {
                ForEach(LLMProvider.allCases) { item in
                    Button {
                        provider = item
                        selectedModel = item.defaultModel
                        customModel = ""
                        endpoint = item.defaultEndpoint
                        apiKey = ""
                        testResult = nil
                    } label: {
                        VStack(alignment: .leading, spacing: 16) {
                            HStack {
                                Image(systemName: item.icon)
                                    .font(AppTypography.title3.weight(.semibold))
                                    .foregroundStyle(provider == item ? .white : AppPalette.primaryStrong)
                                Spacer()
                                Image(systemName: provider == item ? "checkmark.circle.fill" : "circle")
                                    .foregroundStyle(provider == item ? .white : AppPalette.textSubtle)
                            }
                            Text(item.title)
                                .font(AppTypography.headline)
                                .foregroundStyle(provider == item ? .white : AppPalette.text)
                            Text(item.subtitle)
                                .font(AppTypography.caption)
                                .foregroundStyle(provider == item ? Color.white.opacity(0.74) : AppPalette.textMuted)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                        .padding(18)
                        .frame(maxWidth: .infinity, minHeight: 142, alignment: .leading)
                        .background(provider == item ? AppPalette.primary : AppPalette.card)
                        .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
                        .overlay {
                            RoundedRectangle(cornerRadius: 8, style: .continuous)
                                .stroke(provider == item ? AppPalette.primaryStrong.opacity(0.28) : AppPalette.border)
                        }
                    }
                    .buttonStyle(.plain)
                }
            }
        }
    }

    private var modelStep: some View {
        VStack(alignment: .leading, spacing: 22) {
            stepHeading(model.uiText("选择具体模型"), subtitle: model.uiText("模型列表遵循 %@ 的接口规范", provider.title))
            VStack(alignment: .leading, spacing: 10) {
                onboardingFieldLabel(model.uiText("模型"))
                Picker(model.uiText("模型"), selection: $selectedModel) {
                    ForEach(provider.modelOptions) { option in
                        Text("\(option.title) · \(option.model)").tag(option.model)
                    }
                    Text(model.uiText("自定义模型 ID…")).tag(onboardingCustomModel)
                }
                .pickerStyle(.menu)
                .labelsHidden()
                .frame(maxWidth: 520, alignment: .leading)

                if selectedModel == onboardingCustomModel {
                    TextField(model.uiText("输入厂商模型 ID"), text: $customModel)
                        .textFieldStyle(LightFieldStyle())
                        .frame(maxWidth: 520)
                }
            }
            .padding(20)
            .background(AppPalette.card)
            .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
            .overlay { RoundedRectangle(cornerRadius: 8).stroke(AppPalette.border) }
        }
    }

    private var connectionStep: some View {
        VStack(alignment: .leading, spacing: 22) {
            stepHeading(model.uiText("填写连接信息"), subtitle: model.uiText("API Key 初始为空，需要使用者自行填写"))
            VStack(alignment: .leading, spacing: 18) {
                onboardingFieldLabel(model.uiText("API 地址"))
                TextField(provider.defaultEndpoint, text: $endpoint)
                    .textFieldStyle(LightFieldStyle())
                    .font(AppTypography.callout.monospaced())

                onboardingFieldLabel(model.uiText("API Key"))
                HStack {
                    Group {
                        if isKeyVisible {
                            TextField(provider.placeholder, text: $apiKey)
                        } else {
                            SecureField(provider.placeholder, text: $apiKey)
                        }
                    }
                    .textFieldStyle(.plain)
                    .font(AppTypography.callout.monospaced())
                    Button {
                        isKeyVisible.toggle()
                    } label: {
                        Image(systemName: isKeyVisible ? "eye" : "eye.slash")
                    }
                    .buttonStyle(.plain)
                    .help(isKeyVisible ? model.text(.hideApiKey) : model.text(.showApiKey))
                }
                .padding(.horizontal, 11)
                .frame(height: 38)
                .background(AppPalette.card)
                .clipShape(RoundedRectangle(cornerRadius: 7, style: .continuous))
                .overlay { RoundedRectangle(cornerRadius: 7).stroke(AppPalette.border) }

                Link(destination: provider.keyURL) {
                    Label(model.uiText("前往 %@ 获取 API Key", provider.title), systemImage: "arrow.up.right.square")
                        .font(AppTypography.caption)
                }
            }
            .padding(22)
            .frame(maxWidth: 620)
            .background(AppPalette.card)
            .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
            .overlay { RoundedRectangle(cornerRadius: 8).stroke(AppPalette.border) }
        }
        .onChange(of: endpoint) { _, _ in testResult = nil }
        .onChange(of: apiKey) { _, _ in testResult = nil }
    }

    private var verificationStep: some View {
        VStack(alignment: .leading, spacing: 22) {
            stepHeading(model.uiText("验证连接"), subtitle: model.uiText("测试成功后才会把配置写入本机加密存储"))
            VStack(alignment: .leading, spacing: 14) {
                reviewRow(model.uiText("用户"), displayName)
                reviewRow(model.uiText("角色"), model.uiText(role))
                reviewRow(model.uiText("厂商"), provider.title)
                reviewRow(model.uiText("模型"), effectiveModel)
                reviewRow(model.uiText("API 地址"), endpoint)
                reviewRow("API Key", model.uiText("已填写，不显示明文"))
            }
            .padding(20)
            .frame(maxWidth: 620)
            .background(AppPalette.card)
            .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
            .overlay { RoundedRectangle(cornerRadius: 8).stroke(AppPalette.border) }

            if let testResult {
                Label(model.localizedMessage(testResult.message) ?? testResult.message, systemImage: testResult.configured ? "checkmark.circle.fill" : "xmark.circle.fill")
                    .font(AppTypography.callout)
                    .foregroundStyle(testResult.configured ? AppPalette.success : AppPalette.danger)
                    .padding(14)
                    .frame(maxWidth: 620, alignment: .leading)
                    .background((testResult.configured ? AppPalette.success : AppPalette.danger).opacity(0.08))
                    .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
            }

            Button {
                Task { await testConnection() }
            } label: {
                HStack(spacing: 8) {
                    if isTesting { ProgressView().controlSize(.small) } else { Image(systemName: "powerplug") }
                    Text(isTesting ? model.uiText("正在测试") : model.text(.testConnection))
                }
            }
            .buttonStyle(SecondaryActionButtonStyle())
            .disabled(isTesting || isSavingModel)
        }
    }

    private var navigation: some View {
        HStack {
            if step > 1 {
                Button {
                    step -= 1
                    testResult = nil
                    profileError = nil
                } label: {
                    Label(model.uiText("上一步"), systemImage: "chevron.left")
                }
                .buttonStyle(SecondaryActionButtonStyle())
                .disabled(isSavingProfile || isSavingModel || isTesting)
            }
            Spacer()
            if step < totalSteps {
                Button {
                    Task { await advance() }
                } label: {
                    HStack(spacing: 8) {
                        if isSavingProfile { ProgressView().controlSize(.small) }
                        Text(isSavingProfile ? model.uiText("正在保存") : model.uiText("下一步"))
                        if !isSavingProfile { Image(systemName: "chevron.right") }
                    }
                }
                .buttonStyle(PrimaryActionButtonStyle())
                .disabled(!canContinue || isSavingProfile || isSavingModel || isTesting)
            } else {
                Button {
                    Task { await saveAndEnter() }
                } label: {
                    HStack(spacing: 8) {
                        if isSavingModel { ProgressView().controlSize(.small) } else { Image(systemName: "checkmark") }
                        Text(isSavingModel ? model.uiText("正在保存") : model.uiText("保存并进入"))
                    }
                }
                .buttonStyle(PrimaryActionButtonStyle())
                .disabled(isSavingModel || isTesting || testResult?.configured != true)
            }
        }
        .padding(.horizontal, 36)
        .frame(height: 76)
        .background(AppPalette.card)
    }

    private func setupField<Content: View>(
        _ title: String,
        required: Bool = false,
        @ViewBuilder content: () -> Content
    ) -> some View {
        VStack(alignment: .leading, spacing: 7) {
            HStack(spacing: 3) {
                onboardingFieldLabel(title)
                if required {
                    Text("*")
                        .font(AppTypography.caption.weight(.bold))
                        .foregroundStyle(AppPalette.danger)
                }
            }
            content()
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func stepHeading(_ title: String, subtitle: String) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title).font(AppTypography.title3.weight(.semibold))
            Text(subtitle).font(AppTypography.callout).foregroundStyle(AppPalette.textMuted)
        }
    }

    private func onboardingFieldLabel(_ title: String) -> some View {
        Text(title).font(AppTypography.caption.weight(.semibold)).foregroundStyle(AppPalette.textMuted)
    }

    private func reviewRow(_ title: String, _ value: String) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 16) {
            Text(title)
                .font(AppTypography.caption.weight(.semibold))
                .foregroundStyle(AppPalette.textMuted)
                .frame(width: 76, alignment: .leading)
            Text(value)
                .font(AppTypography.callout)
                .foregroundStyle(AppPalette.text)
                .textSelection(.enabled)
        }
    }

    private var effectiveModel: String {
        selectedModel == onboardingCustomModel
            ? customModel.trimmingCharacters(in: .whitespacesAndNewlines)
            : selectedModel
    }

    private var cleanDisplayName: String {
        displayName.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private var cleanDepartment: String {
        department.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private var canContinue: Bool {
        switch step {
        case 1:
            return !cleanDisplayName.isEmpty && !cleanDepartment.isEmpty && !model.userID.isEmpty
        case 2:
            return !role.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        case 3:
            return true
        case 4:
            return !effectiveModel.isEmpty
        case 5:
            let cleanEndpoint = endpoint.trimmingCharacters(in: .whitespacesAndNewlines)
            let validEndpoint = cleanEndpoint.hasPrefix("http://") || cleanEndpoint.hasPrefix("https://")
            return validEndpoint && !apiKey.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        default:
            return testResult?.configured == true
        }
    }

    private var llmPayload: LLMConfigPayload {
        LLMConfigPayload(
            provider: provider.rawValue,
            catalogProvider: provider == .custom ? "sub2api" : provider.rawValue,
            model: effectiveModel,
            endpoint: endpoint.trimmingCharacters(in: .whitespacesAndNewlines),
            apiKey: apiKey.trimmingCharacters(in: .whitespacesAndNewlines),
            enabled: true,
            maxTokens: 1800,
            temperature: 0.25,
            topP: 0.9,
            timeoutMs: 60000,
            wireApi: provider == .custom ? "responses" : nil,
            reasoningEffort: provider == .custom ? "xhigh" : nil,
            disableResponseStorage: provider == .custom ? true : nil
        )
    }

    private func bootstrap() async {
        guard !didBootstrap else { return }
        if model.profileSettings == nil {
            await model.loadSettings()
        }
        if model.llmConfig == nil {
            await model.loadLLMConfig()
        }
        hydrateProfile()
        hydrateConfiguration()
        step = PostLoginSetupRules.firstIncompleteStep(
            profile: model.profileSettings,
            userID: model.userID,
            llmConfig: model.llmConfig
        ) ?? 1
        didBootstrap = true
    }

    private func hydrateProfile() {
        let profile = model.profileSettings
        let profileBelongsToUser = profile?.email.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            == model.userID.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard profileBelongsToUser, let profile else {
            displayName = model.userID.split(separator: "@").first.map(String.init) ?? ""
            phone = ""
            department = ""
            employeeID = ""
            bio = ""
            role = ""
            return
        }
        displayName = profile.displayName
        phone = profile.phone
        department = profile.department
        employeeID = profile.employeeId
        bio = profile.bio
        role = profile.role
    }

    private func hydrateConfiguration() {
        guard !didHydrateConfiguration, let config = model.llmConfig else { return }
        provider = LLMProvider(rawValue: config.provider) ?? .openai
        selectedModel = provider.modelOptions.contains(where: { $0.model == config.model }) ? config.model : onboardingCustomModel
        customModel = selectedModel == onboardingCustomModel ? config.model : ""
        endpoint = config.endpoint?.isEmpty == false ? config.endpoint ?? provider.defaultEndpoint : provider.defaultEndpoint
        apiKey = ""
        didHydrateConfiguration = true
    }

    private func advance() async {
        guard canContinue else { return }
        if step == 2 {
            await saveProfileAndContinue()
        } else {
            step += 1
            testResult = nil
            profileError = nil
        }
    }

    private func saveProfileAndContinue() async {
        guard !cleanDisplayName.isEmpty, !cleanDepartment.isEmpty, !role.isEmpty else {
            profileError = model.uiText("请完整填写昵称、部门并选择角色")
            return
        }
        let payload = UserProfileSettingsPayload(
            displayName: cleanDisplayName,
            email: model.userID.trimmingCharacters(in: .whitespacesAndNewlines).lowercased(),
            phone: phone.trimmingCharacters(in: .whitespacesAndNewlines),
            department: cleanDepartment,
            role: role.trimmingCharacters(in: .whitespacesAndNewlines),
            employeeId: employeeID.trimmingCharacters(in: .whitespacesAndNewlines),
            bio: String(bio.trimmingCharacters(in: .whitespacesAndNewlines).prefix(200))
        )
        let saved = await model.saveProfileSettings(payload)
        if saved {
            profileError = nil
            step = 3
        } else {
            profileError = model.errorMessage ?? model.uiText("用户资料保存失败，请重试")
        }
    }

    private func testConnection() async {
        testResult = await model.testLLMConfig(llmPayload)
    }

    private func saveAndEnter() async {
        guard testResult?.configured == true,
              PostLoginSetupRules.isProfileComplete(model.profileSettings, userID: model.userID)
        else { return }
        await model.saveLLMConfig(llmPayload)
    }
}

@available(*, deprecated, renamed: "PostLoginSetupView")
struct LLMOnboardingView: View {
    var body: some View {
        PostLoginSetupView()
    }
}
