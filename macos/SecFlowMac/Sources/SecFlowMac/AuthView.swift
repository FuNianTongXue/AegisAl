import AppKit
import SwiftUI

struct AuthView: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        ZStack {
            AppPalette.brandNavyDeep.ignoresSafeArea()
            HStack(spacing: 0) {
                authBrand
                    .frame(width: 420)
                if model.authScreen == .login {
                    LoginForm()
                } else {
                    RegistrationForm()
                }
            }
            .frame(width: 960, height: model.authScreen == .login ? 640 : 700)
            .background(AppPalette.card)
            .clipShape(RoundedRectangle(cornerRadius: 14, style: .continuous))
            .shadow(color: AppPalette.brandNavy.opacity(0.32), radius: 24, y: 10)
        }
        .frame(minWidth: 960, minHeight: 620)
    }

    private var authBrand: some View {
        VStack(alignment: .leading, spacing: 28) {
            Spacer()
            HStack(spacing: 14) {
                AppBrandLogo(size: 50, shadow: false)
                VStack(alignment: .leading, spacing: 2) {
                    Text(model.text(.appName)).font(AppTypography.title2.bold()).foregroundStyle(.white)
                    Text("Security Knowledge Agent").font(AppTypography.caption).foregroundStyle(.white.opacity(0.65))
                }
            }
            Text(model.authScreen == .login ? model.uiText("AI 驱动的安全知识库智能体\n漏洞分析 · 威胁情报 · 知识图谱") : model.uiText("创建您的安全智脑账户\n开启智能安全分析之旅"))
                .font(AppTypography.title3).foregroundStyle(.white.opacity(0.78)).lineSpacing(7)
            if model.authScreen == .login {
                VStack(alignment: .leading, spacing: 18) {
                    AuthFeature(icon: "brain.head.profile", text: model.uiText("智能问答，秒级响应安全咨询"))
                    AuthFeature(icon: "antenna.radiowaves.left.and.right", text: model.uiText("实时漏洞查询，多源接口关联"))
                    AuthFeature(icon: "point.3.connected.trianglepath.dotted", text: model.uiText("知识图谱关联漏洞与组件"))
                }
            } else {
                VStack(alignment: .leading, spacing: 20) {
                    AuthStep(number: "1", text: model.uiText("填写基本信息"), active: true)
                    AuthStep(number: "2", text: model.uiText("验证邮箱地址"), active: false)
                    AuthStep(number: "3", text: model.uiText("设置安全偏好"), active: false)
                }
            }
            Spacer()
        }
        .padding(54)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .leading)
        .background(
            LinearGradient(
                colors: [
                    AppPalette.brandNavy,
                    AppPalette.brandNavyDeep
                ],
                startPoint: .topLeading,
                endPoint: .bottomTrailing
            )
        )
    }
}

private struct LoginForm: View {
    @EnvironmentObject private var model: AppModel
    @State private var email = ""
    @State private var password = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 22) {
            Spacer()
            Text(model.uiText("欢迎回来")).font(AppTypography.largeTitle.bold()).foregroundStyle(AppPalette.text)
            Text(model.uiText("登录您的安全智脑账户")).foregroundStyle(AppPalette.textMuted)
            AuthField(label: model.uiText("邮箱地址"), icon: "envelope", placeholder: model.uiText("请输入邮箱地址"), text: $email)
            AuthField(label: model.uiText("密码"), icon: "lock", placeholder: model.uiText("请输入密码"), text: $password, secure: true)
            Button {
                model.enterWorkspace(email: email)
            } label: {
                Text(model.uiText("登 录")).frame(maxWidth: .infinity)
            }
            .buttonStyle(PrimaryActionButtonStyle()).controlSize(.large)
            .disabled(email.isEmpty || password.isEmpty)
            HStack { Rectangle().frame(height: 1); Text(model.uiText("或")); Rectangle().frame(height: 1) }
                .foregroundStyle(AppPalette.textSubtle).font(AppTypography.caption)
            Button {
                model.enterWorkspace(email: email.isEmpty ? NSFullUserName() : email)
            } label: {
                Label(model.uiText("使用本机账户进入"), systemImage: "person.crop.circle").frame(maxWidth: .infinity)
            }
            .buttonStyle(.bordered).controlSize(.large)
            HStack {
                Spacer()
                Text(model.uiText("还没有账户？")).foregroundStyle(AppPalette.textMuted)
                Button(model.uiText("立即注册")) { model.authScreen = .register }.buttonStyle(.plain).foregroundStyle(AppPalette.primary)
                Spacer()
            }
            .font(AppTypography.callout)
            Spacer()
        }
        .padding(.horizontal, 56)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

private struct RegistrationForm: View {
    @EnvironmentObject private var model: AppModel
    @State private var familyName = ""
    @State private var givenName = ""
    @State private var email = ""
    @State private var password = ""
    @State private var confirmPassword = ""
    @State private var organization = ""
    @State private var role = "安全分析师"
    @State private var accepted = false
    @State private var termsRead = false
    @State private var privacyRead = false
    @State private var activeLegalDocument: SettingsDocument?

    private var allDocumentsRead: Bool { termsRead && privacyRead }
    private var canRegister: Bool {
        RegistrationRules.canRegister(
            email: email,
            password: password,
            confirmPassword: confirmPassword,
            termsRead: termsRead,
            privacyRead: privacyRead,
            accepted: accepted
        )
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                HStack {
                    Button { model.authScreen = .login } label: { Image(systemName: "chevron.left") }
                        .buttonStyle(.plain)
                    VStack(alignment: .leading) {
                        Text(model.uiText("创建账户")).font(AppTypography.title.bold())
                        Text(model.uiText("加入安全智脑，提升安全分析效率")).foregroundStyle(AppPalette.textMuted)
                    }
                }
                HStack {
                    AuthField(label: model.uiText("姓"), icon: nil, placeholder: model.uiText("请输入"), text: $familyName)
                    AuthField(label: model.uiText("名"), icon: nil, placeholder: model.uiText("请输入"), text: $givenName)
                }
                AuthField(label: model.uiText("工作邮箱"), icon: "envelope", placeholder: "name@company.com", text: $email)
                AuthField(label: model.uiText("设置密码"), icon: "lock", placeholder: model.uiText("至少8位，包含字母和数字"), text: $password, secure: true)
                AuthField(label: model.uiText("确认密码"), icon: "lock", placeholder: model.uiText("请再次输入密码"), text: $confirmPassword, secure: true)
                AuthField(label: model.uiText("所属组织（选填）"), icon: "building.2", placeholder: model.uiText("公司或团队名称"), text: $organization)
                Text(model.uiText("角色")).font(AppTypography.caption.weight(.semibold)).foregroundStyle(AppPalette.text)
                Picker(model.uiText("角色"), selection: $role) {
                    ForEach(["安全分析师", "安全工程师", "安全管理员", "其他"], id: \.self) { Text(model.uiText($0)) }
                }
                .pickerStyle(.segmented).labelsHidden()
                legalConsentSection
                Button {
                    model.enterWorkspace(email: email)
                } label: {
                    Text(model.uiText("创建账户")).frame(maxWidth: .infinity)
                }
                .buttonStyle(PrimaryActionButtonStyle()).controlSize(.large)
                .disabled(!canRegister)
            }
            .padding(42)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .task {
            if model.legalDocuments[SettingsDocument.terms.id] == nil
                || model.legalDocuments[SettingsDocument.privacy.id] == nil {
                await model.loadLegalDocuments()
            }
        }
        .sheet(item: $activeLegalDocument) { document in
            RegistrationLegalDocumentSheet(
                document: document,
                backendDocument: model.legalDocuments[document.id],
                alreadyRead: document == .terms ? termsRead : privacyRead
            ) {
                if document == .terms {
                    termsRead = true
                } else {
                    privacyRead = true
                }
            }
            .environmentObject(model)
        }
    }

    private var legalConsentSection: some View {
        VStack(alignment: .leading, spacing: 9) {
            HStack(spacing: 8) {
                Text(model.uiText("请先分别阅读"))
                    .foregroundStyle(AppPalette.textMuted)
                legalDocumentButton(.terms, isRead: termsRead)
                Text(model.uiText("和"))
                    .foregroundStyle(AppPalette.textMuted)
                legalDocumentButton(.privacy, isRead: privacyRead)
                if model.isBusy("settings-legal-load") {
                    ProgressView().controlSize(.small)
                }
            }
            .font(AppTypography.caption)

            Toggle(model.uiText("我已阅读并同意服务条款和隐私政策"), isOn: $accepted)
                .font(AppTypography.caption)
                .disabled(!allDocumentsRead)

            if !allDocumentsRead {
                Label(model.uiText("需分别打开文档并下拉至底部"), systemImage: "arrow.down.circle")
                    .font(AppTypography.caption2)
                    .foregroundStyle(AppPalette.textSubtle)
            }
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(AppPalette.cardMuted.opacity(0.72))
        .clipShape(RoundedRectangle(cornerRadius: 6, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: 6, style: .continuous)
                .stroke(AppPalette.border.opacity(0.8))
        }
    }

    private func legalDocumentButton(_ document: SettingsDocument, isRead: Bool) -> some View {
        Button {
            activeLegalDocument = document
        } label: {
            Label(
                model.uiText(document == .terms ? "服务条款" : "隐私政策"),
                systemImage: isRead ? "checkmark.circle.fill" : "doc.text"
            )
            .foregroundStyle(isRead ? AppPalette.success : AppPalette.primary)
        }
        .buttonStyle(.plain)
        .help(model.uiText(document == .terms ? "查看服务条款" : "查看隐私政策"))
    }
}

struct RegistrationLegalDocumentSheet: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss

    let document: SettingsDocument
    let backendDocument: LegalDocumentSnapshot?
    let onReachedBottom: (() -> Void)?
    let onRead: () -> Void

    @State private var hasReachedBottom: Bool
    @State private var viewportHeight: CGFloat = 0
    @State private var documentBottomPosition: CGFloat = .greatestFiniteMagnitude

    init(
        document: SettingsDocument,
        backendDocument: LegalDocumentSnapshot?,
        alreadyRead: Bool,
        onReachedBottom: (() -> Void)? = nil,
        onRead: @escaping () -> Void
    ) {
        self.document = document
        self.backendDocument = backendDocument
        self.onReachedBottom = onReachedBottom
        self.onRead = onRead
        _hasReachedBottom = State(initialValue: alreadyRead)
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 12) {
                Image(systemName: document == .terms ? "doc.text.fill" : "hand.raised.fill")
                    .font(AppTypography.title3)
                    .foregroundStyle(AppPalette.primary)
                VStack(alignment: .leading, spacing: 2) {
                    Text(backendDocument?.heading ?? document.heading)
                        .font(AppTypography.headline.weight(.bold))
                    Text(
                        model.uiText(
                            "最后更新：%@ · 生效：%@",
                            backendDocument?.updatedAt ?? document.updatedAt,
                            backendDocument?.effectiveAt ?? document.effectiveAt
                        )
                    )
                    .font(AppTypography.caption)
                    .foregroundStyle(AppPalette.textSubtle)
                }
                Spacer()
                Button {
                    dismiss()
                } label: {
                    Image(systemName: "xmark")
                        .frame(width: 28, height: 28)
                }
                .buttonStyle(.plain)
                .help(model.uiText("关闭"))
            }
            .padding(.horizontal, 24)
            .frame(height: 68)

            Divider()

            ScrollView {
                VStack(alignment: .leading, spacing: 22) {
                    Text(backendDocument?.intro ?? document.intro)
                        .font(AppTypography.callout)
                        .foregroundStyle(AppPalette.textMuted)
                        .lineSpacing(4)
                        .padding(16)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(AppPalette.cardMuted.opacity(0.8))
                        .clipShape(RoundedRectangle(cornerRadius: 6, style: .continuous))

                    ForEach(Array(sections.enumerated()), id: \.offset) { _, section in
                        VStack(alignment: .leading, spacing: 10) {
                            Text(section.heading)
                                .font(AppTypography.headline.weight(.semibold))
                            ForEach(section.paragraphs, id: \.self) { paragraph in
                                Text(paragraph)
                                    .font(AppTypography.callout)
                                    .foregroundStyle(AppPalette.textMuted)
                                    .lineSpacing(4)
                                    .fixedSize(horizontal: false, vertical: true)
                            }
                        }
                    }

                    Color.clear
                        .frame(height: 1)
                        .background {
                            GeometryReader { proxy in
                                Color.clear.preference(
                                    key: LegalDocumentBottomPreferenceKey.self,
                                    value: proxy.frame(in: .named("registration-legal-scroll")).maxY
                                )
                            }
                        }
                }
                .padding(28)
            }
            .coordinateSpace(name: "registration-legal-scroll")
            .background {
                GeometryReader { proxy in
                    Color.clear
                        .onAppear {
                            viewportHeight = proxy.size.height
                            updateReachedBottom(
                                bottomPosition: documentBottomPosition,
                                viewportHeight: proxy.size.height
                            )
                        }
                        .onChange(of: proxy.size.height) { _, height in
                            viewportHeight = height
                            updateReachedBottom(
                                bottomPosition: documentBottomPosition,
                                viewportHeight: height
                            )
                        }
                }
            }
            .onPreferenceChange(LegalDocumentBottomPreferenceKey.self) { bottomPosition in
                documentBottomPosition = bottomPosition
                updateReachedBottom(
                    bottomPosition: bottomPosition,
                    viewportHeight: viewportHeight
                )
            }

            Divider()

            HStack(spacing: 12) {
                Label(
                    model.uiText(hasReachedBottom ? "文档已阅读" : "请下拉至文档底部后确认"),
                    systemImage: hasReachedBottom ? "checkmark.circle.fill" : "arrow.down.circle"
                )
                .font(AppTypography.caption)
                .foregroundStyle(hasReachedBottom ? AppPalette.success : AppPalette.textMuted)
                Spacer()
                Button {
                    onRead()
                    dismiss()
                } label: {
                    Label(model.uiText("已阅读并返回"), systemImage: "checkmark")
                }
                .buttonStyle(PrimaryActionButtonStyle())
                .disabled(!hasReachedBottom)
            }
            .padding(.horizontal, 24)
            .frame(height: 70)
        }
        .frame(minWidth: 660, idealWidth: 720, minHeight: 560, idealHeight: 680)
        .background(AppPalette.card)
        .foregroundStyle(AppPalette.text)
    }

    private func updateReachedBottom(bottomPosition: CGFloat, viewportHeight: CGFloat) {
        guard !hasReachedBottom,
              RegistrationRules.hasReachedDocumentEnd(
                  bottomPosition: bottomPosition,
                  viewportHeight: viewportHeight
              ) else { return }
        hasReachedBottom = true
        onReachedBottom?()
    }

    private var sections: [LegalDocumentSectionSnapshot] {
        if let backendSections = backendDocument?.sections, !backendSections.isEmpty {
            return backendSections
        }
        return document.sections.map {
            LegalDocumentSectionSnapshot(heading: $0.0, paragraphs: $0.1)
        }
    }
}

private struct LegalDocumentBottomPreferenceKey: PreferenceKey {
    static var defaultValue: CGFloat = .greatestFiniteMagnitude

    static func reduce(value: inout CGFloat, nextValue: () -> CGFloat) {
        value = min(value, nextValue())
    }
}

enum RegistrationRules {
    static func canRegister(
        email: String,
        password: String,
        confirmPassword: String,
        termsRead: Bool,
        privacyRead: Bool,
        accepted: Bool
    ) -> Bool {
        !email.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            && password.count >= 8
            && password == confirmPassword
            && termsRead
            && privacyRead
            && accepted
    }

    static func hasReachedDocumentEnd(
        bottomPosition: CGFloat,
        viewportHeight: CGFloat,
        tolerance: CGFloat = 20
    ) -> Bool {
        viewportHeight > 0 && bottomPosition <= viewportHeight + tolerance
    }
}

private struct AuthField: View {
    let label: String
    let icon: String?
    let placeholder: String
    @Binding var text: String
    var secure = false

    var body: some View {
        VStack(alignment: .leading, spacing: 7) {
            Text(label).font(AppTypography.caption.weight(.semibold)).foregroundStyle(AppPalette.text)
            HStack {
                if let icon { Image(systemName: icon).foregroundStyle(AppPalette.textMuted) }
                if secure { SecureField(placeholder, text: $text) } else { TextField(placeholder, text: $text) }
            }
            .textFieldStyle(.plain)
            .foregroundStyle(AppPalette.text)
            .padding(11)
            .background(AppPalette.card)
            .clipShape(RoundedRectangle(cornerRadius: 6))
            .overlay { RoundedRectangle(cornerRadius: 6).stroke(AppPalette.border) }
        }
        .frame(maxWidth: .infinity)
    }
}

private struct AuthFeature: View {
    let icon: String
    let text: String
    var body: some View {
        Label(text, systemImage: icon).foregroundStyle(.white.opacity(0.76)).font(AppTypography.callout)
    }
}

private struct AuthStep: View {
    let number: String
    let text: String
    let active: Bool
    var body: some View {
        HStack(spacing: 12) {
            Text(number).frame(width: 28, height: 28).background(active ? AppPalette.primary : Color.white.opacity(0.14)).clipShape(Circle())
            Text(text).foregroundStyle(.white.opacity(active ? 0.9 : 0.45))
        }
    }
}
