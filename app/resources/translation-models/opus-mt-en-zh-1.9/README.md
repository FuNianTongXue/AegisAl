# SecFlow offline English-Chinese translation model

This directory contains the inference-only files from the Argos Translate
English to Chinese package version 1.9. SecFlow loads the CTranslate2 model
directly and does not use Argos, Stanza, a network translation service, an API
key, or an LLM token budget at runtime.

## Upstream and attribution

- Package: `translate-en_zh-1_9.argosmodel`
- Download: <https://argos-net.com/v1/translate-en_zh-1_9.argosmodel>
- Archive SHA-256: `433e7c4f034d87fbe2353161e05f18646d7999452f801a4e1f0378522b9850ab`
- Original model: OPUS-MT
- Authors: Jorg Tiedemann and Santhosh Thottingal
- Paper: "OPUS-MT - Building open translation services for the World",
  Proceedings of EAMT 2020
- License: Creative Commons Attribution 4.0 International (`CC-BY-4.0`)

The upstream attribution is preserved in `UPSTREAM-README.md`. The complete
license text is in `LICENSE.txt` and is also distributed in the client license
directory as `OPUS-MT-CC-BY-4.0.txt`.

## Integrity

`manifest.json` records the size and SHA-256 digest of every bundled file. The
build invokes `scripts/validate_translation_model.py` before packaging and
again against the model copied into the packaged backend. The validator also
pins the known upstream archive and core model digests so changing the manifest
cannot silently replace the translator.

The bundled package intentionally excludes the upstream Stanza tokenizer data.
SecFlow tokenizes with the included SentencePiece model, which is the only
tokenizer required by the direct CTranslate2 inference path.
