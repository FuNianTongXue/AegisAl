import { Check } from "lucide-react";

export interface WizardProgressStep {
  id: string;
  label: string;
  description?: string;
}

export function WizardProgress({
  steps,
  activeIndex,
  onSelect,
  ariaLabel = "流程进度",
}: {
  steps: WizardProgressStep[];
  activeIndex: number;
  onSelect?: (index: number) => void;
  ariaLabel?: string;
}) {
  return (
    <ol className="wizard-progress" aria-label={ariaLabel}>
      {steps.map((step, index) => {
        const completed = index < activeIndex;
        const active = index === activeIndex;
        const content = (
          <>
            <span className="wizard-progress-marker" aria-hidden="true">
              {completed ? <Check /> : index + 1}
            </span>
            <span className="wizard-progress-copy">
              <strong>{step.label}</strong>
              {step.description ? <small>{step.description}</small> : null}
            </span>
          </>
        );
        return (
          <li className={`${active ? "active" : ""} ${completed ? "completed" : ""}`} key={step.id}>
            {onSelect ? (
              <button
                type="button"
                aria-current={active ? "step" : undefined}
                onClick={() => onSelect(index)}
              >
                {content}
              </button>
            ) : (
              <div aria-current={active ? "step" : undefined}>{content}</div>
            )}
          </li>
        );
      })}
    </ol>
  );
}
