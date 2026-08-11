import { useEffect, useId, useState } from "react";

export function MermaidBlock({ code }: { code: string }) {
  const id = `mermaid-${useId().replaceAll(":", "")}`;
  const [svg, setSvg] = useState("");
  const [error, setError] = useState("");

  useEffect(() => {
    let live = true;
    void import("mermaid").then(async ({ default: mermaid }) => {
      mermaid.initialize({ startOnLoad: false, securityLevel: "strict", theme: "neutral" });
      try {
        const rendered = await mermaid.render(id, code);
        if (live) setSvg(rendered.svg);
      } catch (reason) {
        if (live) setError(String(reason));
      }
    });
    return () => { live = false; };
  }, [code, id]);

  if (error) return <pre className="code-block">{code}</pre>;
  return <div className="mermaid-block" dangerouslySetInnerHTML={{ __html: svg }} />;
}
