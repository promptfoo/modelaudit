# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Bug Fixes

- **hashing:** preserve throughput while checking scan deadlines responsively
- **cli:** handle interrupts during CLI startup without a traceback

## [0.2.49](https://github.com/promptfoo/modelaudit/compare/v0.2.48...v0.2.49) (2026-06-25)

### Bug Fixes

- **picklescan:** restore Windows call-graph detection via cross-view stat identity ([#1715](https://github.com/promptfoo/modelaudit/issues/1715)) ([51c0074](https://github.com/promptfoo/modelaudit/commit/51c00742ad1c090e5a3f61c1f0c6662e66d06a40))
