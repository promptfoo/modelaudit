### Other changes

- Validate storage IDs in large PyTorch tensor batches and legacy TorchScript v1 parameter mappings with a separate budget of 256,000 metadata opcodes and two million provenance-node visits per archive. Member discovery limits and coverage diagnostics still apply. [#1957](https://github.com/promptfoo/modelaudit/pull/1957)
