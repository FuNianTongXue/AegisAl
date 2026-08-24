# Aceternity-inspired effects

This folder contains an original local implementation of two public visual patterns documented by Aceternity UI:

- [Sparkles](https://ui.aceternity.com/components/sparkles): the restrained particle field and light sweep used by `AceternitySparklesStage`.
- [Glowing Effect](https://ui.aceternity.com/components/glowing-effect): the pointer-aware card glow used by `AceternityGlowingCard`.

No Aceternity source file, npm package, image, font, or remote runtime is bundled. The implementation uses deterministic React markup and project-local CSS so the desktop client remains offline-capable. Motion is disabled when `prefers-reduced-motion` is enabled.
