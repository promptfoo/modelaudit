### Upgrade notes

- When `OPENAI_API_KEY` is set, `modelaudit scan` can send selected warning or critical README/model-card findings and available document text to OpenAI. The submitted content can include secrets. Run `modelaudit scan ./model --no-triage` to keep the scan local. Advice goes to stderr and does not change reports, verdicts, or exit codes. [#1924](https://github.com/promptfoo/modelaudit/pull/1924)
