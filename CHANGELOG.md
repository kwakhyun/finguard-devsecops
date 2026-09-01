# Changelog

이 문서는 FinGuard 공개 포트폴리오의 주요 변경을 기록합니다.

## [0.6.1] - 2026-09-01

### Fixed

- 커밋된 CycloneDX SBOM과 릴리스 주체, 변경 승인 정보의 digest 정합성 복구
- 실제 Semgrep 규칙과 보호 릴리스 정책의 ruleset digest 동기화
- 빈 Ruff 보고서에서도 변조 검증이 유효하도록 회귀 테스트 보강
- GitHub Actions를 Node.js 24 기반 공식 릴리스의 불변 커밋으로 갱신

## [0.6.0] - 2026-09-01

### Added

- SAST, SCA, DAST, 품질 결과를 결합하는 Python 정책 게이트
- 릴리스 대상, 외부 승인, scan provenance와 감사 증적 결속
- GitLab CI, Jenkins, GitHub Actions 파이프라인
- 서명된 증적 검증, Kubernetes 배포 preflight와 자동 rollback
- 정책 예외, SPDX 라이선스, VEX, shadow policy와 Prometheus export

### Verified

- Ruff와 Mypy 통과
- 190개 회귀 테스트와 85% 이상 coverage
- 정상 릴리스 PASS 증적 검증과 위험 릴리스 차단

[0.6.1]: https://github.com/kwakhyun/finguard-devsecops/tree/v0.6.1
[0.6.0]: https://github.com/kwakhyun/finguard-devsecops/tree/v0.6.0
