import { Check } from "lucide-react";
import type { CSSProperties } from "react";

import { providerPresets } from "../lib/modelControls";

export interface ModelProviderPickerProps {
  value: string;
  onChange: (id: string) => void;
  disabled?: boolean;
  className?: string;
}

export function ModelProviderPicker({
  value,
  onChange,
  disabled = false,
  className = "",
}: ModelProviderPickerProps) {
  return (
    <div
      className={["provider-cards", className].filter(Boolean).join(" ")}
      role="group"
      aria-label="选择模型厂商"
      aria-disabled={disabled || undefined}
    >
      {providerPresets.map((provider, index) => {
        const selected = value === provider.id;
        return (
          <button
            type="button"
            key={provider.id}
            className={`provider-card ${selected ? "active" : ""}`}
            aria-label={provider.label}
            aria-pressed={selected}
            disabled={disabled}
            style={{ "--provider-index": index } as CSSProperties}
            onClick={() => onChange(provider.id)}
          >
            <span className="provider-card-name">
              {provider.label}
              {provider.badge || selected ? (
                <span className="provider-card-flags" aria-hidden="true">
                  {provider.badge ? (
                    <span
                      className={`badge ${provider.badge === "推荐" ? "badge-amber" : "badge-navy"}`}
                    >
                      {provider.badge}
                    </span>
                  ) : null}
                  {selected ? <Check strokeWidth={3} /> : null}
                </span>
              ) : null}
            </span>
            <span className="provider-card-host" aria-hidden="true">
              {provider.consoleHost || "自定义接入地址"}
            </span>
          </button>
        );
      })}
    </div>
  );
}
