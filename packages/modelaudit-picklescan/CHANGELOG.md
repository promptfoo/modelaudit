# Changelog

All notable changes to `modelaudit-picklescan` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this package adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Introduce the Rust-native pickle scanning engine and standalone Python API package.
- Probe binary pickle operands for nested pickle streams while leaving arbitrary
  non-pickle text extraction to the root ModelAudit raw detector layer.
