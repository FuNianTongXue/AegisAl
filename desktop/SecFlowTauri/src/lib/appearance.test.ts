// @vitest-environment jsdom

import { afterEach, describe, expect, it } from "vitest";

import { applyDocumentAppearance, parseInformationAppearance } from "./appearance";

describe("information window appearance", () => {
  afterEach(() => {
    delete document.documentElement.dataset.theme;
    document.documentElement.removeAttribute("lang");
    document.documentElement.style.removeProperty("--font-scale");
  });

  it("applies the shared theme and font scale to a document", () => {
    const meta = document.createElement("meta");
    meta.name = "theme-color";
    document.head.append(meta);

    applyDocumentAppearance({ theme: "dark", fontScale: 1.12 }, "zh-Hans");

    expect(document.documentElement.dataset.theme).toBe("dark");
    expect(document.documentElement.lang).toBe("zh-Hans");
    expect(document.documentElement.style.getPropertyValue("--font-scale")).toBe("1.12");
    expect(meta.content).toBe("#171718");
    meta.remove();
  });

  it("accepts only bounded appearance event payloads", () => {
    expect(parseInformationAppearance({ theme: "light", fontScale: 0.9 })).toEqual({
      theme: "light",
      fontScale: 0.9,
    });
    expect(parseInformationAppearance({ theme: "contrast", fontScale: 1 })).toBeNull();
    expect(parseInformationAppearance({ theme: "dark", fontScale: 8 })).toBeNull();
    expect(parseInformationAppearance(null)).toBeNull();
  });
});
