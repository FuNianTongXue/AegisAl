import { ArrowLeft, ArrowRight, Check, KeyRound, LoaderCircle, Lock, UserRound } from "lucide-react";
import { useState } from "react";

import { api } from "../lib/api";
import { configForProvider, selectedProviderId } from "../lib/modelControls";
import { useAppStore } from "../store/appStore";
import type { LlmConfig, UserProfile } from "../types";
import { BrandMark } from "./BrandMark";
import { BRAND_NAME_ZH, BRAND_SECURITY_AGENT, brandDisplayText } from "../branding";
import { ModelProviderPicker } from "./ModelProviderPicker";
import { ModelSelectControl } from "./ModelSelectControl";
import { WizardProgress } from "./WizardProgress";

const roles = ["安全分析师", "安全工程师", "研发工程师", "安全负责人", "审计人员"];
const setupSteps = [
  { id: "profile", label: "个人信息", description: "建立本机身份" },
  { id: "model", label: "设置模型", description: "验证推理服务" },
];

export function InitialSetupView() {
  const state = useAppStore();
  const [step, setStep] = useState<1 | 2>(1);
  const [profile, setProfile] = useState<UserProfile>(state.settings?.profile || {
    display_name: "",
    email: "",
    department: "",
    role: "",
  });
  const [config, setConfig] = useState<LlmConfig>(state.llm || {
    provider: "deepseek",
    endpoint: "https://api.deepseek.com",
    model: "deepseek-chat",
    max_tokens: 1800,
    timeout_ms: 60000,
    enabled: true,
  });
  const [busy, setBusy] = useState(false);
  const [verified, setVerified] = useState(false);
  const [status, setStatus] = useState("");
  const [models, setModels] = useState<Array<{ id: string; name?: string }>>([]);
  const selectedProvider = selectedProviderId(config);

  const updateProfile = (key: keyof UserProfile, value: string) => {
    setProfile((current) => ({ ...current, [key]: value }));
  };
  const updateConfig = (patch: Partial<LlmConfig>) => {
    setConfig((current) => ({ ...current, ...patch }));
    setVerified(false);
    setStatus("");
  };
  const chooseProvider = (provider: string) => {
    setConfig((current) => configForProvider(current, provider));
    setModels([]);
    setVerified(false);
    setStatus("");
  };

  const loadModels = async () => {
    setBusy(true);
    setStatus("正在从模型厂商接口读取模型…");
    try {
      const result = await api.modelCatalog(state.userId, config);
      setModels(result.models || []);
      setStatus(`已读取 ${result.models?.length || 0} 个模型`);
    } catch (error) {
      setStatus(error instanceof Error ? error.message : String(error));
    } finally {
      setBusy(false);
    }
  };

  const saveProfile = async () => {
    setBusy(true);
    setStatus("正在保存个人信息…");
    try {
      const result = await api.saveProfile(state.userId, profile);
      const settings = useAppStore.getState().settings;
      if (settings) state.set({ settings: { ...settings, profile: result } });
      setProfile(result);
      setStatus("");
      setStep(2);
    } catch (error) {
      setStatus(error instanceof Error ? error.message : String(error));
    } finally {
      setBusy(false);
    }
  };

  const testConnection = async () => {
    setBusy(true);
    setStatus("正在验证模型连接…");
    try {
      const result = await api.testLlmConfig(state.userId, config);
      setVerified(true);
      setStatus(result.latency_ms ? `连接成功 · ${result.latency_ms}ms` : "连接成功");
    } catch (error) {
      setVerified(false);
      setStatus(error instanceof Error ? error.message : String(error));
    } finally {
      setBusy(false);
    }
  };

  const finish = async () => {
    setBusy(true);
    setStatus("正在保存模型配置…");
    try {
      const result = await api.saveLlmConfig(state.userId, { ...config, enabled: true });
      state.set({ llm: result, initialSetupRequired: false });
    } catch (error) {
      setStatus(error instanceof Error ? error.message : String(error));
    } finally {
      setBusy(false);
    }
  };

  return (
    <main className="initial-setup">
      <section className="initial-setup-card" aria-label={`${BRAND_NAME_ZH} 初始引导`}>
        <aside className="initial-setup-aside">
          <div className="initial-setup-brand"><BrandMark size={46} /><span><strong>{BRAND_NAME_ZH}</strong><small>{BRAND_SECURITY_AGENT}</small></span></div>
          <div className="initial-setup-intro"><span className="setup-kicker">首次配置</span><h1>欢迎使用{BRAND_NAME_ZH}</h1><p>两步完成本机身份与推理模型接入，随后即可开始漏洞分析、项目扫描和报告生成。</p></div>
          <ul>
            <li><Check /><span><strong>信息仅存本机</strong><small>个人资料和密钥不会公开展示</small></span></li>
            <li><Check /><span><strong>连接测试独立</strong><small>临时网络异常不会阻止保存配置</small></span></li>
          </ul>
        </aside>
        <div className="initial-setup-workflow">
          <header><span>设置向导</span><strong>第 {step} 步，共 {setupSteps.length} 步</strong></header>
          <WizardProgress steps={setupSteps} activeIndex={step - 1} ariaLabel="配置步骤" />
          <div className="initial-setup-transition" key={step}>
            {step === 1 ? (
              <form onSubmit={(event) => { event.preventDefault(); void saveProfile(); }}>
                <div className="initial-setup-heading"><UserRound /><div><h2>配置个人信息</h2><p>用于头像、任务记录和安全工作区身份显示。</p></div></div>
                <div className="settings-form-grid">
                  <label>显示名称<input required maxLength={80} name="display_name" autoComplete="name" value={profile.display_name} onChange={(event) => updateProfile("display_name", event.target.value)} /></label>
                  <label>邮箱<input required maxLength={160} name="email" type="email" autoComplete="email" spellCheck={false} value={profile.email} onChange={(event) => updateProfile("email", event.target.value)} /></label>
                  <label>部门<input maxLength={120} name="department" autoComplete="organization" value={profile.department} onChange={(event) => updateProfile("department", event.target.value)} /></label>
                  <label>角色<select name="role" autoComplete="off" value={profile.role} onChange={(event) => updateProfile("role", event.target.value)}><option value="">请选择角色</option>{roles.map((role) => <option value={role} key={role}>{role}</option>)}</select></label>
                </div>
                <footer><span aria-live="polite">{brandDisplayText(status)}</span><button className="primary" type="submit" disabled={busy}>{busy ? <LoaderCircle className="spin" /> : <ArrowRight />}保存并继续</button></footer>
              </form>
            ) : (
              <form onSubmit={(event) => { event.preventDefault(); void finish(); }}>
                <div className="initial-setup-heading"><KeyRound /><div><h2>接入模型</h2><p>选择厂商并填写凭证；连接测试可独立执行，不影响本机保存。</p></div></div>
                <div className="initial-model-stack">
                  <section className="initial-model-section">
                    <div className="initial-model-section-heading"><strong>选择模型厂商</strong><small>与设置页使用同一份厂商目录和映射规则。</small></div>
                    <ModelProviderPicker value={selectedProvider} onChange={chooseProvider} disabled={busy} className="initial-provider-cards" />
                  </section>
                  <section className="initial-model-section">
                    <div className="initial-model-section-heading"><strong>选择可用模型</strong><small>可读取厂商目录，也可添加兼容的模型 ID。</small></div>
                    <ModelSelectControl key={selectedProvider} config={config} models={models} busy={busy} onModelChange={(model) => updateConfig({ model })} onLoadModels={() => void loadModels()} />
                  </section>
                </div>
                <div className="settings-form-grid initial-credential-grid">
                  <label>Base URL<input required name="model_endpoint" type="url" inputMode="url" autoComplete="off" spellCheck={false} value={config.endpoint} placeholder="例如 https://api.example.com/v1…" onChange={(event) => updateConfig({ endpoint: event.target.value })} /></label>
                  <label>API Key<input required={selectedProvider !== "ollama" && !config.api_key_configured} maxLength={8192} name="model_api_key" type="password" autoComplete="off" spellCheck={false} value={config.api_key || ""} placeholder={selectedProvider === "ollama" ? "本地 Ollama 无需密钥…" : config.api_key_configured ? "已配置，留空保持不变…" : "输入模型厂商 API Key…"} onChange={(event) => updateConfig({ api_key: event.target.value })} /></label>
                </div>
                <footer>
                  <button className="ghost" type="button" onClick={() => { setStep(1); setStatus(""); }} disabled={busy}><ArrowLeft />返回</button>
                  <span className={verified ? "success" : ""} aria-live="polite">{brandDisplayText(status)}</span>
                  <button className="secondary" type="button" onClick={() => void testConnection()} disabled={busy}>{busy ? <LoaderCircle className="spin" /> : <KeyRound />}测试连接</button>
                  <button className="primary" type="submit" disabled={busy}><Lock />保存并进入工作区</button>
                </footer>
              </form>
            )}
          </div>
        </div>
      </section>
    </main>
  );
}
