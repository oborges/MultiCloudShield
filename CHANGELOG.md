# Changelog

All notable changes follow Keep a Changelog and Semantic Versioning.

## [Unreleased]

The v0.1.0 implementation is complete on `feat/multicloudshield-v0.1.0`; tagging and release
artifacts remain outstanding.

### Added

- End-to-end demo and live-provider scan architecture for AWS, Azure, GCP, and IBM Cloud.
- Twenty-three deterministic posture policies with evidence and remediation guidance.
- PostgreSQL persistence, REST API, worker, CLI, React dashboard, JSON/CSV exports, and containers.
- Session and API-token authentication, organization-scoped authorization, and finding lifecycle.

### Changed

- Upgrade the frontend build/test toolchain to Vite 8.2, plugin-react 6.0.5, and Vitest 4.1 while
  retaining TypeScript 5.9 until the ESLint toolchain supports TypeScript 7.

### Fixed

- Mount PostgreSQL 18 data at `/var/lib/postgresql` so its versioned cluster layout initializes and
  remains compatible with `pg_upgrade`.
