import { describe, expect, it } from "vitest";

import { BRAND_NAME_EN, BRAND_NAME_ZH, brandDisplayText } from "./branding";

describe("brandDisplayText", () => {
  it("uses the configured public product names", () => {
    expect(BRAND_NAME_ZH).toBe("神盾");
    expect(BRAND_NAME_EN).toBe("AegisAl");
  });

  it("maps legacy public names without changing unrelated text", () => {
    expect(brandDisplayText("SecFlow 安全智脑客户端")).toBe(`${BRAND_NAME_EN} ${BRAND_NAME_ZH}客户端`);
    expect(brandDisplayText("AegisAI Security Agent")).toBe(`${BRAND_NAME_EN} Security Agent`);
    expect(brandDisplayText("secflow-report.xlsx")).toBe(`${BRAND_NAME_EN}-report.xlsx`);
    expect(brandDisplayText("CVE-2026-4242")).toBe("CVE-2026-4242");
  });

  it("returns an empty string for absent display values", () => {
    expect(brandDisplayText(undefined)).toBe("");
    expect(brandDisplayText(null)).toBe("");
  });
});
