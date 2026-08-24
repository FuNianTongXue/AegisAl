import {
  Activity,
  ArrowLeft,
  ArrowRight,
  BarChart3,
  Bell,
  Bot,
  Boxes,
  Camera,
  Check,
  CircleHelp,
  Database,
  Flame,
  Eye,
  EyeOff,
  Gauge,
  Library,
  Lightbulb,
  KeyRound,
  LoaderCircle,
  Lock,
  LockOpen,
  MessageSquare,
  MessagesSquare,
  Moon,
  Palette,
  RefreshCcw,
  Save,
  Search,
  Server,
  Settings,
  Sparkles,
  Sun,
  TestTube2,
  Trash2,
  TrendingUp,
  Type,
  UserRound,
} from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";

import { CLIENT_LANGUAGES, clientLocaleTag, type ClientLocale, translate, useI18n } from "../i18n";
import { api } from "../lib/api";
import { configForProvider, normalizedReasoningEffort, providerPresets, selectedProviderId } from "../lib/modelControls";
import { handleWindowDrag } from "../lib/windowDrag";
import { useAppStore } from "../store/appStore";
import { BRAND_NAME_ZH, brandDisplayText } from "../branding";
import type { ClientCapabilityCatalog, InformationSnapshot, InformationSource, LlmConfig, ModelUsageSnapshot, UserProfile } from "../types";
import { ModelProviderPicker } from "./ModelProviderPicker";
import { ModelSelectControl } from "./ModelSelectControl";
import { ProfileAvatar } from "./ProfileAvatar";
import { WizardProgress } from "./WizardProgress";

type SettingsTab =
  | "general"
  | "appearance"
  | "model"
  | "browser"
  | "index"
  | "usage"
  | "agents"
  | "skills"
  | "mcp"
  | "guide";

interface SettingsNavItem {
  id: SettingsTab;
  label: string;
  ariaLabel?: string;
  icon: React.ReactNode;
}

const settingsGroups: Array<{ label: string; items: SettingsNavItem[] }> = [
  {
    label: "基础设置",
    items: [
      { id: "general", label: "用户资料", icon: <UserRound /> },
      { id: "appearance", label: "外观", icon: <Palette /> },
      { id: "model", label: "模型设置", icon: <Server /> },
      { id: "browser", label: "咨询订阅", icon: <Bell /> },
    ],
  },
  {
    label: "数据与统计",
    items: [
      { id: "index", label: "索引库", icon: <Library /> },
      { id: "usage", label: "使用统计", icon: <BarChart3 /> },
    ],
  },
  {
    label: "客户端能力",
    items: [
      { id: "agents", label: "Agent", icon: <Bot /> },
      { id: "skills", label: "Skills", icon: <Sparkles /> },
      { id: "mcp", label: "MCP", icon: <Boxes /> },
    ],
  },
];

export function SettingsView({ onBack }: { onBack?: () => void }) {
  const state = useAppStore();
  const { t } = useI18n();
  const [tab, setTab] = useState<SettingsTab>("model");
  const [hasUnsavedChanges, setHasUnsavedChanges] = useState(false);
  const back = onBack || (() => state.set({ view: "assistant" }));
  const confirmDiscard = () => (
    !hasUnsavedChanges
    || window.confirm(t("当前设置尚未保存，确定要放弃修改吗？"))
  );
  const selectTab = (nextTab: SettingsTab) => {
    if (nextTab === tab || !confirmDiscard()) return;
    setHasUnsavedChanges(false);
    setTab(nextTab);
  };
  const leaveSettings = () => {
    if (!confirmDiscard()) return;
    setHasUnsavedChanges(false);
    back();
  };

  useEffect(() => {
    if (!hasUnsavedChanges) return;
    const warnBeforeUnload = (event: BeforeUnloadEvent) => {
      event.preventDefault();
      event.returnValue = "";
    };
    window.addEventListener("beforeunload", warnBeforeUnload);
    return () => window.removeEventListener("beforeunload", warnBeforeUnload);
  }, [hasUnsavedChanges]);

  return (
    <div className="settings-layout zcode-settings">
      <div className="settings-window-drag" data-tauri-drag-region onMouseDown={handleWindowDrag} />
      <aside className="settings-navigation" aria-label={t("设置导航")}>
        <button className="settings-back" aria-label={t("返回工作区")} onClick={leaveSettings}><ArrowLeft size={16} /><span>{t("返回工作区")}</span></button>
        <div className="settings-nav-scroll">
          {settingsGroups.map((group) => (
            <section className="settings-nav-group" key={group.label}>
              <h2>{t(group.label)}</h2>
              {group.items.map((item) => (
                <button
                  key={item.id}
                  aria-label={t(item.ariaLabel || item.label)}
                  aria-current={tab === item.id ? "page" : undefined}
                  className={tab === item.id ? "active" : ""}
                  onClick={() => selectTab(item.id)}
                >
                  {item.icon}<span>{t(item.label)}</span>
                </button>
              ))}
            </section>
          ))}
          <button className={`settings-guide ${tab === "guide" ? "active" : ""}`} aria-label={t("引导")} onClick={() => selectTab("guide")}>
            <Sparkles size={16} /><span>{t("引导")}</span>
          </button>
        </div>
        <div className="settings-account-row">
          <button className="settings-account" aria-label={t("打开用户资料设置")} onClick={() => selectTab("general")}>
            <ProfileAvatar profile={state.settings?.profile} userId={state.userId} className="settings-account-avatar" />
            <span><strong>{state.settings?.profile.display_name || t("本机用户")}</strong><small>{state.llm?.model || t("连接使用")}</small></span>
          </button>
          <button className="settings-account-action" aria-label={t("打开用户资料设置")} title={t("用户资料设置")} onClick={() => selectTab("general")}><Settings size={16} /></button>
        </div>
      </aside>
      <main className="settings-stage">
        <button className="settings-help" aria-label={t("打开设置引导")} title={t("设置引导")} onClick={() => selectTab("guide")}><CircleHelp size={17} /></button>
        <div className="settings-content">
          <div className="settings-panel" key={tab} data-settings-tab={tab}>
            {tab === "general" ? <ProfileSettings onDirtyChange={setHasUnsavedChanges} /> : null}
            {tab === "appearance" ? <AppearanceSettings /> : null}
            {tab === "model" ? <ModelSettings onDirtyChange={setHasUnsavedChanges} /> : null}
            {tab === "browser" ? <InformationSubscriptionSettings /> : null}
            {tab === "index" ? <IntelligenceSourceSettings /> : null}
            {tab === "usage" ? <UsageSettings /> : null}
            {tab === "agents" ? <CapabilitySettings category="agents" /> : null}
            {tab === "skills" ? <CapabilitySettings category="skills" /> : null}
            {tab === "mcp" ? <CapabilitySettings category="mcp" /> : null}
            {tab === "guide" ? <GuideSettings /> : null}
          </div>
        </div>
      </main>
    </div>
  );
}

function SettingsHeader({ title, description, action }: { title: string; description: string; action?: React.ReactNode }) {
  const { t } = useI18n();
  return <header className="settings-header"><div><h1>{t(title)}</h1>{action}</div><p>{t(description)}</p></header>;
}

function ProfileSettings({ onDirtyChange }: { onDirtyChange: (dirty: boolean) => void }) {
  const state = useAppStore();
  const { locale, t } = useI18n();
  const [profile, setProfile] = useState<UserProfile>(state.settings?.profile || { display_name: "", email: "", department: "", role: "" });
  const [status, setStatus] = useState("");
  const [busy, setBusy] = useState(false);
  const [locked, setLocked] = useState(Boolean(state.settings?.profile.updated_at));
  const [avatarBusy, setAvatarBusy] = useState(false);
  const [avatarPreview, setAvatarPreview] = useState("");
  const avatarInput = useRef<HTMLInputElement>(null);
  useEffect(() => {
    if (!state.settings?.profile) return;
    setProfile(state.settings.profile);
    setLocked(Boolean(state.settings.profile.updated_at));
    onDirtyChange(false);
  }, [onDirtyChange, state.settings?.profile]);
  const field = (key: keyof UserProfile, value: string) => {
    setProfile((current) => ({ ...current, [key]: value }));
    onDirtyChange(true);
  };
  const applyProfile = (result: UserProfile) => {
    setProfile(result);
    const latest = useAppStore.getState().settings;
    if (latest) state.set({ settings: { ...latest, profile: result } });
  };
  const save = async () => {
    setBusy(true);
    setStatus(t("正在保存"));
    try {
      const result = await api.saveProfile(state.userId, profile);
      applyProfile(result);
      setLocked(true);
      onDirtyChange(false);
      setStatus(t("已保存"));
    } catch (error) {
      setStatus(error instanceof Error ? error.message : String(error));
    } finally {
      setBusy(false);
    }
  };
  const changeLanguage = async (nextLocale: ClientLocale) => {
    if (!state.settings) return;
    const previous = state.settings.preferences;
    const optimistic = { ...previous, language: nextLocale };
    state.set({ settings: { ...state.settings, preferences: optimistic } });
    setStatus(translate(nextLocale, "语言设置已更新"));
    try {
      const preferences = await api.savePreferences(optimistic);
      const latest = useAppStore.getState().settings;
      if (latest) state.set({ settings: { ...latest, preferences } });
    } catch (error) {
      const latest = useAppStore.getState().settings;
      if (latest) state.set({ settings: { ...latest, preferences: previous } });
      setStatus(error instanceof Error ? error.message : String(error));
    }
  };
  const uploadAvatar = async (file?: File) => {
    if (!file) return;
    const extension = file.name.split(".").pop()?.toLowerCase();
    if (!extension || !["jpg", "jpeg", "png", "webp"].includes(extension)) {
      setStatus(t("请选择 JPG、PNG 或 WebP 图片"));
      return;
    }
    if (file.size > 2 * 1024 * 1024) {
      setStatus(t("头像文件不能超过 2MB"));
      return;
    }
    setAvatarBusy(true);
    setStatus(t("正在上传头像"));
    try {
      const dataUrl = await readFileAsDataUrl(file);
      setAvatarPreview(dataUrl);
      const contentBase64 = dataUrl.slice(dataUrl.indexOf(",") + 1);
      const result = await api.uploadProfileAvatar(state.userId, file.name, contentBase64, file.type);
      applyProfile(result);
      setAvatarPreview("");
      setStatus(t("头像已更新"));
    } catch (error) {
      setAvatarPreview("");
      setStatus(error instanceof Error ? error.message : String(error));
    } finally {
      setAvatarBusy(false);
      if (avatarInput.current) avatarInput.current.value = "";
    }
  };
  const removeAvatar = async () => {
    setAvatarBusy(true);
    try {
      const result = await api.removeProfileAvatar(state.userId);
      applyProfile(result);
      setAvatarPreview("");
      setStatus(t("头像已移除"));
    } catch (error) {
      setStatus(error instanceof Error ? error.message : String(error));
    } finally {
      setAvatarBusy(false);
    }
  };
  const roles = ["安全分析师", "安全工程师", "研发工程师", "安全负责人", "审计人员"];
  const handleProfileLock = () => {
    if (locked) {
      setLocked(false);
      setStatus("");
      return;
    }
    if (state.settings?.profile) setProfile(state.settings.profile);
    setLocked(true);
    onDirtyChange(false);
    setStatus(t("已取消未保存的修改"));
  };
  return (
    <section>
      <SettingsHeader
        title="用户资料"
        description="管理本机用户资料与安全工作区身份。保存后自动锁定，解锁后才能再次编辑。"
        action={<button className={`settings-icon-button ${locked ? "locked" : "unlocked"}`} type="button" aria-label={locked ? t("解锁个人信息") : t("取消编辑并锁定个人信息")} title={locked ? t("解锁后编辑个人信息") : t("取消未保存修改并锁定")} onClick={handleProfileLock}>{locked ? <Lock /> : <LockOpen />}</button>}
      />
      <fieldset className={`profile-lock-scope ${locked ? "locked" : ""}`} disabled={locked || busy || avatarBusy}>
      <div className="profile-identity">
        <button type="button" className="profile-avatar-button" aria-label={t("更换头像")} title={t("更换头像")} onClick={() => avatarInput.current?.click()} disabled={avatarBusy}>
          <ProfileAvatar profile={profile} userId={state.userId} previewUrl={avatarPreview} />
          <span className="profile-avatar-edit">{avatarBusy ? <LoaderCircle className="spin" /> : <Camera />}</span>
        </button>
        <input ref={avatarInput} className="profile-avatar-input" type="file" name="profile_avatar" accept="image/jpeg,image/png,image/webp" onChange={(event) => void uploadAvatar(event.target.files?.[0])} />
        <div className="profile-identity-copy"><strong>{profile.display_name || t("本机用户")}</strong><small>{profile.role ? t(profile.role) : t("尚未选择角色")}</small></div>
        {profile.avatar_available ? <button type="button" className="profile-avatar-remove" aria-label={t("移除头像")} title={t("移除头像")} onClick={() => void removeAvatar()} disabled={avatarBusy}><Trash2 /></button> : null}
      </div>
      <form onSubmit={(event) => { event.preventDefault(); void save(); }}>
        <div className="settings-form-grid">
          <label>{t("显示名称")}<input required maxLength={80} name="display_name" autoComplete="name" value={profile.display_name} onChange={(event) => field("display_name", event.target.value)} /></label>
          <label>{t("邮箱")}<input required maxLength={160} name="email" type="email" autoComplete="email" spellCheck={false} value={profile.email} onChange={(event) => field("email", event.target.value)} /></label>
          <label>{t("部门")}<input maxLength={120} name="department" autoComplete="organization" value={profile.department} onChange={(event) => field("department", event.target.value)} /></label>
          <label>{t("角色")}<select name="role" autoComplete="off" value={profile.role} onChange={(event) => field("role", event.target.value)}><option value="">{t("请选择角色")}</option>{!roles.includes(profile.role) && profile.role ? <option>{profile.role}</option> : null}{roles.map((role) => <option value={role} key={role}>{t(role)}</option>)}</select></label>
          <label>{t("手机号")}<input maxLength={80} name="phone" type="tel" inputMode="tel" autoComplete="tel" value={profile.phone || ""} onChange={(event) => field("phone", event.target.value)} /></label>
          <label>{t("员工编号")}<input maxLength={80} name="employee_id" autoComplete="off" spellCheck={false} value={profile.employee_id || ""} onChange={(event) => field("employee_id", event.target.value)} /></label>
          <label>{t("客户端语言")}<select aria-label={t("客户端语言")} name="language" autoComplete="off" value={locale} onChange={(event) => void changeLanguage(event.target.value as ClientLocale)}>{CLIENT_LANGUAGES.map((language) => <option value={language.value} key={language.value}>{language.label}</option>)}</select></label>
          <label className="wide">{t("个人简介")}<textarea maxLength={200} rows={3} name="bio" autoComplete="off" value={profile.bio || ""} onChange={(event) => field("bio", event.target.value)} /></label>
        </div>
        <div className="settings-actions"><span aria-live="polite">{brandDisplayText(status)}</span><button className="primary" type="submit" disabled={locked || busy || avatarBusy}>{busy ? <LoaderCircle className="spin" /> : status === t("已保存") ? <Check size={14} /> : <Save size={14} />}{busy ? t("正在保存") : t("保存资料并锁定")}</button></div>
      </form>
      </fieldset>
    </section>
  );
}

function readFileAsDataUrl(file: File) {
  return new Promise<string>((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result || ""));
    reader.onerror = () => reject(reader.error || new Error("Unable to read image"));
    reader.readAsDataURL(file);
  });
}

function ModelSettings({ onDirtyChange }: { onDirtyChange: (dirty: boolean) => void }) {
  const state = useAppStore();
  const { t } = useI18n();
  const [config, setConfig] = useState<LlmConfig>(state.llm || { provider: "openai", endpoint: "", model: "", max_tokens: 1800, timeout_ms: 60000, enabled: true });
  const [models, setModels] = useState<Array<{ id: string; name?: string }>>([]);
  const [status, setStatus] = useState("");
  const [busy, setBusy] = useState(false);
  const [locked, setLocked] = useState(true);
  const [dirty, setDirty] = useState(false);
  const [showKey, setShowKey] = useState(false);
  const [activePanel, setActivePanel] = useState<"provider" | "model" | "credential" | "advanced">("provider");
  useEffect(() => {
    if (!state.llm) return;
    setConfig(state.llm);
    setDirty(false);
    onDirtyChange(false);
  }, [onDirtyChange, state.llm]);
  const update = (key: keyof LlmConfig, value: string | number | boolean) => {
    setConfig((current) => ({ ...current, [key]: value, ...(key === "api_key" ? { clear_api_key: false } : {}) }));
    setDirty(true);
    onDirtyChange(true);
    if (key === "model" || key === "endpoint" || key === "api_key") setStatus("");
  };
  const loadModels = async () => { setBusy(true); setStatus("正在从模型厂商接口读取模型"); try { const result = await api.modelCatalog(state.userId, config); setModels(result.models || []); setStatus(`已读取 ${result.models?.length || 0} 个模型`); } catch (error) { setStatus(String(error)); } finally { setBusy(false); } };
  const test = async (targetConfig = config) => { setBusy(true); try { const result = await api.testLlmConfig(state.userId, targetConfig); if (result.status !== "success" || result.configured === false) throw new Error(result.message || "模型连接测试失败"); setStatus(result.latency_ms ? `模型连接正常 · ${result.latency_ms}ms` : "模型连接正常"); } catch (error) { setStatus(error instanceof Error ? error.message : String(error)); } finally { setBusy(false); } };
  const save = async () => {
    setBusy(true);
    setStatus("正在保存模型配置");
    try {
      const nextConfig = {
        ...config,
        enabled: config.enabled !== false,
        reasoning_effort: normalizedReasoningEffort(config, config.reasoning_effort),
      };
      const result = await api.saveLlmConfig(state.userId, nextConfig);
      state.set({ llm: result });
      setConfig(result);
      setDirty(false);
      setLocked(true);
      setShowKey(false);
      onDirtyChange(false);
      setStatus(result.enabled ? "模型配置已保存并启用" : "模型配置已保存并停用");
    } catch (error) {
      setStatus(error instanceof Error ? error.message : String(error));
    } finally {
      setBusy(false);
    }
  };
  const handleLockAction = () => {
    if (locked) {
      setLocked(false);
      setStatus("");
      return;
    }
    if (!dirty) {
      setLocked(true);
      setShowKey(false);
      setStatus("");
      onDirtyChange(false);
      return;
    }
    void save();
  };
  const chooseProvider = (provider: string) => {
    setConfig((current) => configForProvider(current, provider));
    setDirty(true);
    onDirtyChange(true);
    setModels([]);
    setStatus("");
  };
  const clearApiKey = () => {
    setConfig((current) => ({ ...current, api_key: "", api_key_configured: false, clear_api_key: true }));
    setDirty(true);
    onDirtyChange(true);
    setShowKey(false);
    setStatus("保存后将清除已配置的 API Key");
  };
  const selectedProvider = selectedProviderId(config);
  const preset = providerPresets.find((item) => item.id === selectedProvider);
  const panels = [
    { id: "provider" as const, label: "选择厂商", description: preset?.label || "选择接入来源", icon: <Server />, complete: Boolean(selectedProvider) },
    { id: "model" as const, label: "选择模型", description: config.model || "指定模型 ID", icon: <Sparkles />, complete: Boolean(config.model) },
    { id: "credential" as const, label: "接入凭证", description: config.api_key_configured || config.api_key ? "凭证已就绪" : "填写地址与密钥", icon: <KeyRound />, complete: Boolean(config.api_key_configured || config.api_key) },
    { id: "advanced" as const, label: "高级选项", description: config.enabled !== false ? "模型已启用" : "模型已停用", icon: <Gauge />, complete: true },
  ];
  const panelIndex = panels.findIndex((panel) => panel.id === activePanel);
  const movePanel = (direction: -1 | 1) => {
    const next = panels[Math.max(0, Math.min(panels.length - 1, panelIndex + direction))];
    if (next) setActivePanel(next.id);
  };

  return (
    <section className="model-settings-page">
      <SettingsHeader
        title="模型设置"
        description={t("推理模型仅用于安全分析与内容生成；漏洞翻译由本机离线能力完成，不依赖模型配置，也不计入 Token 用量。")}
        action={<div className="model-settings-header-actions"><button type="button" className={`settings-icon-button ${locked ? "locked" : "unlocked"}`} aria-label={locked ? "解锁模型配置" : dirty ? "保存并锁定模型配置" : "锁定模型配置"} title={locked ? "解锁后编辑模型配置" : dirty ? config.enabled !== false ? "保存并启用，然后锁定" : "保存并停用，然后锁定" : "锁定模型配置"} onClick={handleLockAction} disabled={busy}>{busy ? <LoaderCircle className="spin" /> : locked ? <Lock /> : <LockOpen />}</button><button type="button" className="settings-icon-button" aria-label="刷新模型列表" title="刷新模型列表" onClick={() => void loadModels()} disabled={locked || busy}><RefreshCcw /></button></div>}
      />
      <div className={`model-settings-card model-transition-card ${locked ? "locked" : ""}`} aria-readonly={locked}>
        <nav className="model-settings-tabs" aria-label="模型配置步骤">
          {panels.map((panel, index) => (
            <button type="button" key={panel.id} className={`${activePanel === panel.id ? "active" : ""} ${panel.complete ? "complete" : ""}`} aria-label={panel.label} aria-current={activePanel === panel.id ? "step" : undefined} onClick={() => setActivePanel(panel.id)}>
              <span className="model-tab-icon">{panel.complete && activePanel !== panel.id ? <Check /> : panel.icon}</span>
              <span><strong>{panel.label}</strong><small>{panel.description}</small></span>
              <i>{index + 1}</i>
            </button>
          ))}
        </nav>
        <fieldset className={`model-settings-lock-scope ${locked ? "locked" : ""}`} disabled={locked || busy}>
          <div className="model-transition-panel" key={activePanel}>
            {activePanel === "provider" ? (
              <div className="model-panel-section">
                <div className="model-panel-heading"><div><Server /><span><strong>选择模型厂商</strong><small>厂商模板会自动填充官方地址和推荐模型。</small></span></div></div>
                <ModelProviderPicker value={selectedProvider} onChange={chooseProvider} disabled={busy} />
              </div>
            ) : null}
            {activePanel === "model" ? (
              <div className="model-panel-section compact">
                <div className="model-panel-heading"><div><Sparkles /><span><strong>选择可用模型</strong><small>读取厂商模型，或手动加入兼容的模型 ID。</small></span></div></div>
                <ModelSelectControl config={config} models={models} busy={busy} onModelChange={(model) => update("model", model)} onLoadModels={() => void loadModels()} />
              </div>
            ) : null}
            {activePanel === "credential" ? (
              <div className="model-panel-section compact">
                <div className="model-panel-heading"><div><KeyRound /><span><strong>验证接入凭证</strong><small>密钥仅保存在本机安全存储，不会显示完整内容。</small></span></div><button type="button" className="credential-test-button" onClick={() => void test()} disabled={busy}><TestTube2 size={14} />测试连接</button></div>
                <div className="provider-fields-grid">
                  <label className="provider-field" htmlFor="model-endpoint">Base URL<input id="model-endpoint" name="model_endpoint" type="url" inputMode="url" autoComplete="off" spellCheck={false} value={config.endpoint || ""} placeholder="例如 https://api.example.com/v1…" onChange={(event) => update("endpoint", event.target.value)} /></label>
                  <div className="provider-field provider-key-field"><label htmlFor="model-api-key">API Key</label><div><input id="model-api-key" name="model_api_key" type={showKey ? "text" : "password"} maxLength={8192} autoComplete="off" spellCheck={false} value={config.api_key || ""} placeholder={config.clear_api_key ? "保存后移除当前密钥…" : config.api_key_configured ? "已配置，留空保持不变…" : "输入模型厂商 API Key…"} onChange={(event) => update("api_key", event.target.value)} />{config.api_key_configured && !config.clear_api_key ? <button type="button" aria-label="清除已保存的 API Key" title="清除已保存的 API Key" onClick={clearApiKey}><Trash2 size={15} /></button> : null}<button type="button" aria-label={showKey ? "隐藏 API Key" : "显示 API Key"} title={showKey ? "隐藏 API Key" : "显示 API Key"} onClick={() => setShowKey((value) => !value)}>{showKey ? <EyeOff size={15} /> : <Eye size={15} />}</button></div></div>
                </div>
              </div>
            ) : null}
            {activePanel === "advanced" ? (
              <div className="model-panel-section compact">
                <div className="model-panel-heading"><div><Gauge /><span><strong>调整运行参数</strong><small>使用紧凑的快速设置行控制模型状态和请求边界。</small></span></div></div>
                <div className="model-quick-settings">
                  <label className="quick-setting-row model-enabled-toggle"><span className="quick-setting-copy"><Sparkles /><span><strong>启用模型</strong><small>在安全任务和咨询中允许选择此模型</small></span></span><span className="quick-setting-control"><span className="model-switch"><input aria-label="启用模型" type="checkbox" checked={config.enabled !== false} onChange={(event) => update("enabled", event.target.checked)} /><span className="model-switch-track" aria-hidden="true"><span className="model-switch-thumb" /></span></span></span></label>
                  <label className="quick-setting-row"><span className="quick-setting-copy"><Gauge /><span><strong>最大输出 Token</strong><small>限制单次回复的最大生成长度</small></span></span><span className="quick-setting-control"><input aria-label="最大输出 Token" type="number" value={config.max_tokens} onChange={(event) => update("max_tokens", Number(event.target.value))} /></span></label>
                  <label className="quick-setting-row"><span className="quick-setting-copy"><Activity /><span><strong>请求超时</strong><small>超过设定毫秒数后终止等待</small></span></span><span className="quick-setting-control"><input aria-label="超时毫秒" type="number" value={config.timeout_ms} onChange={(event) => update("timeout_ms", Number(event.target.value))} /></span></label>
                </div>
              </div>
            ) : null}
          </div>
        </fieldset>
        <footer className="model-transition-footer">
          <button type="button" className="ghost" onClick={() => movePanel(-1)} disabled={panelIndex === 0}><ArrowLeft />上一步</button>
          <span aria-live="polite">{brandDisplayText(status) || (locked ? "配置已锁定，点击右上角锁形按钮后编辑" : "修改完成后点击右上角开锁按钮保存")}</span>
          <button type="button" className="secondary" onClick={() => movePanel(1)} disabled={panelIndex === panels.length - 1}>下一步<ArrowRight /></button>
        </footer>
      </div>
    </section>
  );
}

function AppearanceSettings() {
  const state = useAppStore();
  const { t } = useI18n();
  const emojiSaveVersion = useRef(0);
  const emojiMode = state.settings?.preferences.emoji_mode || "moderate";
  const persistEmojiMode = (value: "off" | "moderate" | "active") => {
    if (!state.settings) return;
    const requestVersion = ++emojiSaveVersion.current;
    const preferences = { ...state.settings.preferences, emoji_mode: value };
    state.set({ settings: { ...state.settings, preferences } });
    void api.savePreferences(preferences).then((savedPreferences) => {
      if (requestVersion !== emojiSaveVersion.current) return;
      const latest = useAppStore.getState().settings;
      if (latest) state.set({ settings: { ...latest, preferences: savedPreferences } });
    }).catch(() => {
      // Keep the optimistic selection visible when an older bundled backend does not know this field yet.
    });
  };
  const persistAppearance = (theme: "light" | "dark" | "system", fontScale: number) => {
    state.set({ theme, fontScale });
    if (!state.settings) return;
    const darkMode = theme === "dark" || (theme === "system" && window.matchMedia("(prefers-color-scheme: dark)").matches);
    const fontSize = fontScale < 1 ? "small" : fontScale > 1 ? "large" : "default";
    void api.savePreferences({ ...state.settings.preferences, dark_mode: darkMode, font_size: fontSize }).then((preferences) => {
      if (state.settings) state.set({ settings: { ...state.settings, preferences } });
    });
  };
  const themes = [
    { id: "light" as const, label: "浅色模式", icon: <Sun size={18} />, iconClass: "" },
    { id: "dark" as const, label: "深色模式", icon: <Moon size={18} />, iconClass: "dark" },
    { id: "system" as const, label: "跟随系统", icon: <Settings size={18} />, iconClass: "" },
  ];
  return (
    <section>
      <SettingsHeader title="外观" description={`调整${BRAND_NAME_ZH}的主题与界面密度。`} />
      {themes.map((theme) => (
        <label className={`appearance-setting ${state.theme === theme.id ? "selected" : ""}`} key={theme.id}>
          <span className={`setting-icon ${theme.iconClass}`}>{theme.icon}</span>
          <strong>{t(theme.label)}</strong>
          <input aria-label={t(theme.label)} type="radio" name="theme" checked={state.theme === theme.id} onChange={() => persistAppearance(theme.id, state.fontScale)} />
        </label>
      ))}
      <div className="font-scale-setting"><div><Type size={18} /><strong>字体大小</strong></div><div className="font-segments" role="group" aria-label="字体大小">{[[0.9,"小"],[1,"标准"],[1.12,"大"]].map(([value,label]) => <button key={String(value)} aria-pressed={state.fontScale === value} className={state.fontScale === value ? "active" : ""} onClick={() => persistAppearance(state.theme, Number(value))}>{label}</button>)}</div></div>
      <div className="font-scale-setting"><div><Sparkles size={18} /><strong>表情符号</strong></div><div className="font-segments" role="group" aria-label="表情符号"><button aria-pressed={emojiMode === "off"} className={emojiMode === "off" ? "active" : ""} onClick={() => persistEmojiMode("off")}>关闭</button><button aria-pressed={emojiMode === "moderate"} className={emojiMode === "moderate" ? "active" : ""} onClick={() => persistEmojiMode("moderate")}>适度</button><button aria-pressed={emojiMode === "active"} className={emojiMode === "active" ? "active" : ""} onClick={() => persistEmojiMode("active")}>活泼</button></div></div>
    </section>
  );
}

function IntelligenceSourceSettings() {
  const { locale, t } = useI18n();
  const [storedCount, setStoredCount] = useState<number>();
  const [error, setError] = useState("");
  useEffect(() => {
    let disposed = false;
    let retryTimer = 0;
    const load = async (attempt: number) => {
      try {
        const result = await api.dashboard();
        if (!disposed) { setStoredCount(result.catalog_count ?? result.stats.total ?? 0); setError(""); }
      } catch (reason) {
        if (disposed) return;
        if (attempt < 3) retryTimer = window.setTimeout(() => void load(attempt + 1), 900);
        else setError(String(reason));
      }
    };
    void load(0);
    return () => { disposed = true; window.clearTimeout(retryTimer); };
  }, []);
  return (
    <section className="index-storage-page">
      <SettingsHeader title="索引库" description="查看本机情报库当前已存储的数据量。" />
      <div className="index-storage-card" aria-busy={storedCount === undefined && !error}>
        <span><Database /></span>
        <strong>{storedCount === undefined ? "--" : new Intl.NumberFormat(clientLocaleTag(locale)).format(storedCount)}</strong>
        <b>{t("条已存储数据")}</b>
      </div>
      {error ? <p className="capability-error">{brandDisplayText(error)}</p> : null}
    </section>
  );
}

function InformationSubscriptionSettings() {
  const [snapshot, setSnapshot] = useState<InformationSnapshot>();
  const [query, setQuery] = useState("");
  const [group, setGroup] = useState("全部分组");
  const [enabledOnly, setEnabledOnly] = useState(false);
  const [visibleCount, setVisibleCount] = useState(40);
  const [busySource, setBusySource] = useState("");
  const [message, setMessage] = useState("");
  useEffect(() => {
    let disposed = false;
    let retryTimer = 0;
    const load = async (attempt: number) => {
      try {
        const result = await api.information();
        if (!disposed) { setSnapshot(result); setMessage(""); }
      } catch (reason) {
        if (disposed) return;
        if (attempt < 3) retryTimer = window.setTimeout(() => void load(attempt + 1), 900);
        else setMessage(String(reason));
      }
    };
    void load(0);
    return () => { disposed = true; window.clearTimeout(retryTimer); };
  }, []);
  const sources = snapshot?.sources || [];
  const groups = useMemo(() => ["全部分组", ...Array.from(new Set(sources.map((source) => source.group || "其他"))).sort()], [sources]);
  const filtered = useMemo(() => { const keyword = query.trim().toLocaleLowerCase(); return sources.filter((source) => { if (enabledOnly && !source.enabled) return false; if (group !== "全部分组" && (source.group || "其他") !== group) return false; return !keyword || `${source.name} ${source.group || ""} ${source.region || ""}`.toLocaleLowerCase().includes(keyword); }); }, [enabledOnly, group, query, sources]);
  const replaceSource = (next: InformationSource) => setSnapshot((current) => current ? { ...current, sources: (current.sources || []).map((source) => source.id === next.id ? next : source), source_summary: current.source_summary ? { ...current.source_summary, enabled: (current.sources || []).reduce((count, source) => count + ((source.id === next.id ? next : source).enabled ? 1 : 0), 0), opml_enabled: (current.sources || []).reduce((count, source) => { const value = source.id === next.id ? next : source; return count + (value.catalog === "chinese-security-rss" && value.enabled ? 1 : 0); }, 0) } : undefined } : current);
  const toggle = async (source: InformationSource) => { setBusySource(source.id); setMessage(""); try { replaceSource(await api.updateInformationSource(source.id, !source.enabled)); } catch (reason) { setMessage(String(reason)); } finally { setBusySource(""); } };
  const test = async (source: InformationSource) => { const sourceName = brandDisplayText(source.name); setBusySource(source.id); setMessage(`正在测试 ${sourceName}`); try { const result = await api.testInformationSource(source.id); replaceSource(result); setMessage(brandDisplayText(result.message) || `${sourceName} 测试完成`); } catch (reason) { setMessage(String(reason)); } finally { setBusySource(""); } };
  const summary = snapshot?.source_summary;
  return (
    <section>
      <SettingsHeader title="咨询订阅" description="管理信息咨询使用的新闻、研究与安全社区订阅。" />
      <div className="source-summary">
        <span><small>全部来源</small><strong>{summary?.total ?? sources.length}</strong></span>
        <span><small>已启用</small><strong>{summary?.enabled ?? sources.filter((source) => source.enabled).length}</strong></span>
      </div>
      <div className="source-toolbar">
        <label>
          <Search size={14} aria-hidden="true" />
          <input aria-label="搜索咨询来源" name="information_source_query" autoComplete="off" value={query} placeholder="例如 FreeBuf 或安全媒体…" onChange={(event) => { setQuery(event.target.value); setVisibleCount(40); }} />
        </label>
        <select aria-label="咨询来源分组" name="information_source_group" autoComplete="off" value={group} onChange={(event) => { setGroup(event.target.value); setVisibleCount(40); }}>
          {groups.map((item) => <option key={item} value={item}>{brandDisplayText(item)}</option>)}
        </select>
        <label className="enabled-filter"><input type="checkbox" name="information_source_enabled" checked={enabledOnly} onChange={(event) => setEnabledOnly(event.target.checked)} />只看已启用</label>
      </div>
      <p className="source-message" role="status" aria-live="polite">{brandDisplayText(message)}</p>
      <div className="source-list information-source-list">
        {filtered.slice(0, visibleCount).map((source) => {
          const sourceName = brandDisplayText(source.name);
          return <div key={source.id}>
            <InformationSourceAvatar source={source} />
            <span><strong>{sourceName}</strong><small>{brandDisplayText(source.group) || "其他"} · {source.item_count} 条 · {brandDisplayText(source.message) || "等待更新"}</small></span>
            <b className={`source-status ${source.status}`}>{sourceStatusLabel(source)}</b>
            <button className="source-test" aria-label={`测试 ${sourceName} 连接`} title={`测试 ${sourceName} 连接`} onClick={() => void test(source)} disabled={Boolean(busySource)}>{busySource === source.id ? <LoaderCircle className="spin" /> : <TestTube2 />}</button>
            <input aria-label={`${sourceName}订阅`} type="checkbox" checked={source.enabled} onChange={() => void toggle(source)} disabled={Boolean(busySource)} />
          </div>;
        })}
        {!filtered.length ? <p className="settings-empty"><Bell size={18} />{sources.length ? "没有匹配的咨询来源" : brandDisplayText(message) || "正在读取咨询订阅…"}</p> : null}
      </div>
      {filtered.length > visibleCount ? <button className="source-more secondary" onClick={() => setVisibleCount((value) => value + 40)}>再显示 40 个来源</button> : null}
    </section>
  );
}

function InformationSourceAvatar({ source }: { source: InformationSource }) {
  const [failed, setFailed] = useState(false);
  if (failed) return <span className="source-avatar fallback" aria-hidden="true">{brandDisplayText(source.name).slice(0, 1)}</span>;
  return (
    <span className="source-avatar" aria-hidden="true">
      <img
        src={api.informationSourceImageUrl(source.id, source.source_image_version)}
        alt=""
        width={33}
        height={33}
        loading="lazy"
        decoding="async"
        onError={() => setFailed(true)}
      />
    </span>
  );
}

function sourceStatusLabel(source: InformationSource) {
  if (!source.enabled) return "已暂停";
  if (source.status === "error") return `失败 ${source.failure_count || 1} 次`;
  if (source.status === "success") return "连接正常";
  if (source.status === "refreshing") return "正在刷新";
  return "等待刷新";
}

function UsageSettings() {
  const userId = useAppStore((state) => state.userId);
  const { locale, t } = useI18n();
  const [days, setDays] = useState<7 | 30>(30);
  const [usage, setUsage] = useState<ModelUsageSnapshot | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    let active = true;
    setLoading(true);
    setError("");
    api.modelUsage(userId, days)
      .then((value) => { if (active) setUsage(value); })
      .catch((reason) => { if (active) setError(reason instanceof Error ? reason.message : t("使用统计加载失败")); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [days, t, userId]);

  const totalTokens = usage?.totals.total_tokens || 0;
  const maximumDailyTokens = Math.max(1, ...(usage?.daily.map((item) => item.total_tokens) || [0]));
  const metrics = [
    {
      key: "tokens",
      label: t("Tokens 用量"),
      value: formatUsageNumber(totalTokens, locale),
      detail: t("输入 {input} · 输出 {output}", { input: formatUsageNumber(usage?.totals.input_tokens || 0, locale), output: formatUsageNumber(usage?.totals.output_tokens || 0, locale) }),
      icon: <Flame />,
      featured: true,
    },
    { key: "conversations", label: t("会话数量"), value: formatUsageNumber(usage?.conversation_count || 0, locale), detail: t("模型调用 {count} 次", { count: formatUsageNumber(usage?.totals.call_count || 0, locale) }), icon: <MessagesSquare /> },
    { key: "messages", label: t("消息数量"), value: formatUsageNumber(usage?.message_count || 0, locale), detail: t("用户与智能体消息"), icon: <MessageSquare /> },
    { key: "active", label: t("活跃天数"), value: formatUsageNumber(usage?.active_days || 0, locale), detail: t("最近 {days} 天", { days }), icon: <Activity /> },
    { key: "streak", label: t("当前连续天数"), value: formatUsageNumber(usage?.current_streak || 0, locale), detail: usage?.current_streak ? t("保持使用中") : t("今天尚未产生调用"), icon: <TrendingUp /> },
    {
      key: "model",
      label: t("最常用模型"),
      value: usage?.most_used_model.model || t("暂无调用"),
      detail: usage?.most_used_model.model ? t("{provider} · 占比 {share}%", { provider: usage.most_used_model.provider, share: usage.most_used_model.share }) : t("完成一次模型问答后显示"),
      icon: <Gauge />,
    },
  ];

  return (
    <section className="model-usage-page">
      <SettingsHeader
        title="使用统计"
        description="基于模型服务商返回的实际 Token 用量统计。"
        action={(
          <div className="usage-range" aria-label={t("统计时间范围")}>
            <button className={days === 7 ? "active" : ""} aria-pressed={days === 7} onClick={() => setDays(7)}>{t("最近 7 天")}</button>
            <button className={days === 30 ? "active" : ""} aria-pressed={days === 30} onClick={() => setDays(30)}>{t("最近 30 天")}</button>
          </div>
        )}
      />

      {error ? <div className="usage-error" role="alert"><BarChart3 /><span>{brandDisplayText(error)}</span></div> : null}
      <div className={`usage-metrics ${loading ? "loading" : ""}`} aria-busy={loading}>
        {metrics.map((metric) => (
          <article className={`usage-metric ${metric.featured ? "featured" : ""}`} key={metric.key} title={metric.key === "tokens" ? `${totalTokens} Tokens` : undefined}>
            <header>{metric.icon}<span>{metric.label}</span></header>
            <strong className={metric.key === "model" ? "model-name" : ""}>{loading ? "--" : metric.value}</strong>
            <small>{loading ? t("正在读取实际用量") : metric.detail}</small>
            {metric.key === "model" && usage?.most_used_model.model ? (
              <i className="usage-share" aria-label={t("模型用量占比 {share}%", { share: usage.most_used_model.share })}>
                <b style={{ width: `${Math.min(100, usage.most_used_model.share)}%` }} />
              </i>
            ) : null}
          </article>
        ))}
      </div>

      <div className="usage-section usage-activity">
        <header><h2>{t("活跃热力图")}</h2><span><small>{t("较少")}</small>{[0, 1, 2, 3, 4].map((level) => <i className={`level-${level}`} key={level} />)}<small>{t("较多")}</small></span></header>
        <div className="usage-heatmap" role="img" aria-label={t("最近 {days} 天活跃热力图", { days })} style={{ gridTemplateRows: `repeat(${Math.min(7, days)}, 14px)` }}>
          {(usage?.heatmap || []).map((item) => (
            <i className={`level-${item.level}`} key={item.date} title={`${formatUsageDate(item.date, locale)}：${item.count}`} />
          ))}
        </div>
        <table className="sr-only"><caption>{t("最近 {days} 天活跃热力图", { days })}</caption><thead><tr><th>{t("日期")}</th><th>{t("调用次数")}</th></tr></thead><tbody>{(usage?.heatmap || []).map((item) => <tr key={item.date}><td>{formatUsageDate(item.date, locale)}</td><td>{formatUsageNumber(item.count, locale)}</td></tr>)}</tbody></table>
        {!loading && !usage?.active_days ? <p className="usage-empty">{t("所选时间范围内还没有模型调用，完成问答后会在这里形成活动记录。")}</p> : null}
      </div>

      <div className="usage-section usage-trend">
        <header><h2>{t("按天 Token 趋势")}</h2><span>{t("最高 {count}", { count: formatUsageNumber(maximumDailyTokens === 1 && !totalTokens ? 0 : maximumDailyTokens, locale) })}</span></header>
        <div className="usage-trend-chart" role="img" aria-label={t("最近 {days} 天 Token 趋势", { days })}>
          {(usage?.daily || []).map((item) => (
            <i key={item.date} title={`${formatUsageDate(item.date, locale)}：${formatUsageNumber(item.total_tokens, locale)} Tokens`}>
              <b style={{ height: `${item.total_tokens ? Math.max(5, item.total_tokens / maximumDailyTokens * 100) : 0}%` }} />
            </i>
          ))}
        </div>
        <table className="sr-only"><caption>{t("最近 {days} 天 Token 趋势", { days })}</caption><thead><tr><th>{t("日期")}</th><th>Tokens</th></tr></thead><tbody>{(usage?.daily || []).map((item) => <tr key={item.date}><td>{formatUsageDate(item.date, locale)}</td><td>{formatUsageNumber(item.total_tokens, locale)}</td></tr>)}</tbody></table>
        <div className="usage-trend-axis"><span>{formatUsageDate(usage?.daily[0]?.date || "", locale)}</span><span>{formatUsageDate(usage?.daily.at(-1)?.date || "", locale)}</span></div>
      </div>

      <div className="usage-tip"><span><Lightbulb /></span><p><strong>{t("统计说明")}</strong><small>{t("Token 仅记录模型服务商明确返回的 usage，不使用字符数估算；测试连接不会计入业务用量。")}</small></p></div>
    </section>
  );
}

function formatUsageNumber(value: number, locale: ClientLocale) {
  return new Intl.NumberFormat(clientLocaleTag(locale)).format(Math.max(0, Number(value || 0)));
}

function formatUsageDate(value: string, locale: ClientLocale) {
  if (!value) return "";
  const parsed = new Date(`${value}T00:00:00Z`);
  if (Number.isNaN(parsed.getTime())) return value;
  return new Intl.DateTimeFormat(clientLocaleTag(locale), { month: "short", day: "numeric", timeZone: "UTC" }).format(parsed);
}

function CapabilitySettings({ category }: { category: "agents" | "skills" | "mcp" }) {
  const [catalog, setCatalog] = useState<ClientCapabilityCatalog>();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  useEffect(() => {
    let active = true;
    api.capabilities()
      .then((value) => { if (active) setCatalog(value); })
      .catch((reason) => { if (active) setError(reason instanceof Error ? reason.message : String(reason)); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, []);
  const summary = catalog?.summary;
  const titles = {
    agents: { title: "Agent", description: "查看客户端内置并由 Supervisor 编排的专业 Agent。" },
    skills: { title: "Skills", description: "查看与客户端一起打包的本地工作流规则。" },
    mcp: { title: "MCP", description: "查看客户端实际注册并可调用的 MCP 服务器与工具。" },
  }[category];
  return (
    <section className="capability-settings-page">
      <SettingsHeader title={titles.title} description={titles.description} />
      <div className={`capability-summary ${category === "mcp" ? "double" : "single"}`} aria-busy={loading}>
        {category === "agents" ? <article><Bot /><span><b>Agent</b><strong>{summary?.agent_count ?? "--"}</strong></span></article> : null}
        {category === "skills" ? <article><Sparkles /><span><b>Skills</b><strong>{summary?.skill_count ?? "--"}</strong></span></article> : null}
        {category === "mcp" ? <><article><Server /><span><b>MCP 服务器</b><strong>{summary?.mcp_server_count ?? "--"}</strong></span></article><article><TestTube2 /><span><b>MCP Tools</b><strong>{summary?.mcp_tool_count ?? "--"}</strong></span></article></> : null}
      </div>
      {error ? <p className="capability-error">{brandDisplayText(error)}</p> : null}
      {category === "agents" ? <div className="capability-section">
        <header><Bot /><span><strong>Agent 能力</strong></span></header>
        <div className="capability-grid">{(catalog?.agents || []).map((agent) => <article key={agent.agent_id}><strong>{brandDisplayText(agent.label)}</strong><small>{brandDisplayText(agent.description || agent.agent_id)}</small><div>{(agent.capabilities || []).map((item) => <span key={item}>{brandDisplayText(item)}</span>)}</div></article>)}</div>
      </div> : null}
      {category === "mcp" ? <div className="capability-section">
        <header><Server /><span><strong>MCP 服务器</strong></span></header>
        <div className="capability-grid mcp">{(catalog?.mcp_servers || []).map((server) => <article key={server.id}><strong>{brandDisplayText(server.name)}<i>{server.tool_count}</i></strong><small>{server.transport}</small><div>{server.tools.map((tool) => <span title={brandDisplayText(tool.description)} key={tool.name}>{brandDisplayText(tool.name)}</span>)}</div></article>)}</div>
      </div> : null}
      {category === "skills" ? <div className="capability-section">
        <header><Sparkles /><span><strong>Skills</strong></span></header>
        <div className="capability-grid skills">{(catalog?.skills || []).map((skill) => <article key={skill.id}><strong>{brandDisplayText(skill.name)}</strong><small>{brandDisplayText(skill.description)}</small><div><span>{brandDisplayText(skill.source)}</span></div></article>)}</div>
      </div> : null}
      {!loading && catalog ? <p className="capability-platform"><Database />Platform Adapter：{catalog.platform.adapter} · {catalog.platform.architecture}</p> : null}
    </section>
  );
}

function GuideSettings() {
  const [activeStep, setActiveStep] = useState(0);
  const steps = [
    { id: "model", label: "配置模型", description: "接入推理服务" },
    { id: "services", label: "检查服务", description: "确认本机能力" },
    { id: "workspace", label: "开始分析", description: "进入安全工作区" },
  ];
  const content = [
    { icon: <Server />, title: "连接你的模型", description: "进入模型设置，选择厂商和模型，填写本机保存的 API Key，并完成一次连接测试。", hint: "连接成功后锁定配置，安全任务将使用当前启用的模型。" },
    { icon: <Activity />, title: "确认安全服务就绪", description: "查看运行状态，确认 FastAPI、任务 Worker、代码扫描、SBOM 和报告能力均已连接。", hint: "服务异常时先刷新运行状态，再检查本机端口和安全软件拦截。" },
    { icon: <Sparkles />, title: "创建第一个安全任务", description: `返回工作区选择项目，描述扫描、漏洞查询或报告目标，${BRAND_NAME_ZH}会选择对应 Agent。`, hint: "执行过程会显示在主对话的思考过程中，右侧仅保留运行状态。" },
  ];
  const current = content[activeStep];
  return (
    <section className="guide-wizard-page">
      <SettingsHeader title="引导" description={`按推荐顺序完成${BRAND_NAME_ZH}的本机配置。`} />
      <div className="guide-wizard-card">
        <WizardProgress steps={steps} activeIndex={activeStep} onSelect={setActiveStep} ariaLabel={`${BRAND_NAME_ZH}使用引导`} />
        <div className="guide-transition-panel" key={steps[activeStep].id}>
          <div className="guide-panel-icon">{current.icon}</div>
          <div><span className="guide-step-kicker">步骤 {activeStep + 1} / {steps.length}</span><h2>{current.title}</h2><p>{current.description}</p><small>{current.hint}</small></div>
        </div>
        <footer className="guide-wizard-footer">
          <button type="button" className="ghost" onClick={() => setActiveStep((value) => Math.max(0, value - 1))} disabled={activeStep === 0}><ArrowLeft />上一步</button>
          <span>{steps[activeStep].description}</span>
          <button type="button" className="primary" onClick={() => setActiveStep((value) => value === steps.length - 1 ? 0 : value + 1)}>{activeStep === steps.length - 1 ? "重新查看" : "下一步"}<ArrowRight /></button>
        </footer>
      </div>
    </section>
  );
}
