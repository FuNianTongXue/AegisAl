import { LoaderCircle, Plus, RefreshCcw } from "lucide-react";
import { useState } from "react";

import { modelOptionsFor } from "../lib/modelControls";
import type { LlmConfig } from "../types";

export interface ModelSelectControlProps {
  config: LlmConfig;
  models: Array<{ id: string; name?: string }>;
  busy?: boolean;
  onModelChange: (id: string) => void;
  onLoadModels: () => void;
  disabled?: boolean;
}

export function ModelSelectControl({
  config,
  models,
  busy = false,
  onModelChange,
  onLoadModels,
  disabled = false,
}: ModelSelectControlProps) {
  const [addingModel, setAddingModel] = useState(false);
  const [newModel, setNewModel] = useState("");
  const modelOptions = modelOptionsFor(config, models);
  const controlsDisabled = disabled || busy;

  const cancelAdding = () => {
    setNewModel("");
    setAddingModel(false);
  };

  const addModel = () => {
    const clean = newModel.trim();
    if (!clean || controlsDisabled) return;
    onModelChange(clean);
    cancelAdding();
  };

  return (
    <div className="model-select-row" aria-busy={busy || undefined}>
      <select
        aria-label="选择模型"
        value={config.model || ""}
        disabled={controlsDisabled}
        onChange={(event) => onModelChange(event.target.value)}
      >
        <option value="">请选择模型</option>
        {modelOptions.map((id) => (
          <option key={id} value={id}>
            {models.find((model) => model.id === id)?.name || id}
          </option>
        ))}
      </select>
      <div className={`model-select-actions ${addingModel ? "adding" : ""}`}>
        <button
          type="button"
          className="secondary"
          onClick={onLoadModels}
          disabled={controlsDisabled}
          aria-busy={busy || undefined}
        >
          {busy ? <LoaderCircle className="spin" size={14} /> : <RefreshCcw size={14} />}
          从厂商读取
        </button>
        {addingModel ? (
          <div className="add-model-form">
            <input
              autoFocus
              aria-label="模型 ID"
              value={newModel}
              placeholder="输入模型 ID…"
              disabled={controlsDisabled}
              onChange={(event) => setNewModel(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === "Enter") {
                  event.preventDefault();
                  addModel();
                }
                if (event.key === "Escape") {
                  event.preventDefault();
                  cancelAdding();
                }
              }}
            />
            <button
              type="button"
              onClick={addModel}
              disabled={controlsDisabled || !newModel.trim()}
              aria-label="确认添加模型"
            >
              添加
            </button>
          </div>
        ) : (
          <button
            type="button"
            className="add-model-button"
            onClick={() => setAddingModel(true)}
            disabled={controlsDisabled}
          >
            <Plus size={14} />
            添加模型
          </button>
        )}
      </div>
    </div>
  );
}
