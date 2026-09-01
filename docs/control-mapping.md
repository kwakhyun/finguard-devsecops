# DevOps 역량과 통제 구현 매핑

이 문서는 DevOps와 DevSecOps 직무의 주요 기술 영역을 실제 코드와 검증 증거에 연결합니다. 경력 연차나 특정 산업의 실무 경험처럼 이 저장소로 입증할 수 없는 항목은 분리해 적습니다.

| 영역 | 통제 ID | 구현 | 검증 증거 |
| --- | --- | --- | --- |
| Python, Bash 자동화 | AUTO-01 | 12개 CLI command, 데모와 운영 wrapper, 안정적인 종료 코드 | `finguard/cli.py`, `scripts/`, CLI 테스트 |
| 품질 정책 | QUAL-01 | Ruff, JUnit, coverage.py 정규화, 단일 coverage 리포트, 임계치 | `tests/test_gate.py`, `COVERAGE_REPORT_AMBIGUOUS` 테스트 |
| Secure Coding, SAST | SAST-01 | Semgrep 사용자 규칙, 로컬 AST scanner, generic SARIF 2.1 adapter | `.semgrep/`, `finguard/parsers/sarif.py` |
| Coverity, SonarQube 확장 | SAST-02 | SARIF를 통한 도구 독립 수집, SonarQube 프로젝트 설정 | `tests/test_reporting.py`, `sonar-project.properties` |
| SCA, SBOM | SCA-01 | Trivy, pip-audit, 중첩 CycloneDX component inventory 정규화, CVSS와 선언 심각도 중 보수적인 값 적용 | `finguard/parsers/json_scanners.py` |
| OSS 라이선스 | OSS-01 | SPDX `AND`, `OR`, `WITH` 표현식, 허용, 금지, 법무 검토 | `finguard/licenses.py`, 표현식 테스트 |
| VEX | SCA-02 | scanner 자체 analysis는 감사 정보로만 보존하고, 별도 서명된 VEX의 subject, 발급자, key, 기간, 근거만 suppression에 사용 | `finguard/vex.py`, `tests/test_vex.py` |
| DAST | DAST-01 | OWASP ZAP 인스턴스별 URI, method, parameter 보존과 필수 릴리스 job | ZAP parser 테스트, CI 파일 |
| scanner 실패 | SAFE-01 | 누락, 오류, 건너뜀, unknown severity를 fail-closed로 차단 | `REQUIRED_SCAN_MISSING`, `SCANNER_ERROR` |
| 입력 안전성 | SAFE-02 | strict JSON, scanner schema와 필수 필드, 50 MiB 상한, XML DTD와 entity 거부, 링크 입력 거부 | parser와 evidence hardening 테스트 |
| 입력 일관성 | SAFE-03 | gate, verify, deploy가 신뢰 입력을 비공개 snapshot으로 고정한 뒤 같은 바이트만 평가하고 사용 | CLI snapshot 회귀 테스트 |
| scan provenance | SUP-01 | report, ruleset, 허용 command hash, 종료 코드, commit, artifact, DB, Runner, signer, 신선도 검증 | `finguard/attestation.py`, P0/P1 강화 테스트 |
| 릴리스 대상 | SUP-02 | commit, image, SBOM, 배포 위치를 canonical SHA-256로 결속 | `finguard/release.py`, mismatch 테스트 |
| 정책 예외 | GOV-01 | finding 범위, 최대 30일, 연장 횟수, 취소, 보상 통제, 직무분리 | `finguard/config.py`, 예외 통제 테스트 |
| CB/SR 변경 통제 | CHG-01 | commit, 승인 역할, 롤백 계획, 배포 창구, 최종 빌드 후 승인 | `finguard/change.py`, `tests/test_gate.py` |
| 외부 승인 신뢰 | CHG-02 | ITSM 발급자와 Cosign key 허용 목록, 전체 변경 요청 hash와 subject 대조 | `finguard/approvals.py`, `tests/test_approvals.py` |
| 감사 증적 | AUD-01 | 원본 snapshot, manifest, closed-world 검증, hash chain, key ID 포함 HMAC, Cosign bundle | `finguard/evidence.py`, 변조 탐지 테스트 |
| 증적 생성 안전성 | AUD-02 | staging 후 원자적 게시, 소유 표식, 출력 링크와 repo root 보호 | `test_force_never_replaces_an_unowned_directory` |
| Git 협업 | FLOW-01 | CODEOWNERS, MR template, 보호 main, MR과 release 신뢰 분리 | `.gitlab/`, pipeline contract 테스트 |
| GitLab CI | CI-01 | needs DAG, rootless BuildKit 단일 빌드, Code Quality, resource group | `.gitlab-ci.yml` |
| Jenkins | CI-02 | 병렬 검사, Podman 단일 빌드, credential binding, 수동 승인 | `Jenkinsfile` |
| 공개 CI 재현 | CI-03 | GitHub Actions에서 품질 검사와 E2E 데모, 실제 Semgrep, Trivy, ZAP 결과를 정책 게이트로 판정 | `.github/workflows/portfolio-ci.yml` |
| 공급망 고정 | SUP-03 | CI와 Dockerfile 이미지 digest 요구, 인프라 이미지 실행 전 검증 | `validate-images`, `validate_onprem_images.py` |
| 배포 통제 | DEP-01 | PASS 증적, Cosign, 정책 ID/버전/원문 hash, 증적 신선도, 정확한 cluster/workload/image, RBAC, 배포 창구 확인 | `finguard/deployment.py`, stale evidence 회귀 테스트 |
| 자동 롤백 | DEP-02 | rollout, smoke test, 결과 저장 또는 서명 실패 시 직전 불변 이미지와 기존 감사 annotation 복원 | deployment 실패 테스트 |
| 배포 감사 | AUD-03 | 실배포 결과 Cosign 서명 강제, 기존 결과와 signature bundle 기본 덮어쓰기 금지, 성공한 bundle만 원자적 게시 | signed result 회귀 테스트 |
| 개발자 피드백 | DX-01 | GitLab Code Quality, SARIF export, 로컬 scanner | `finguard/reporting.py` |
| 정책 rollout | GOV-02 | baseline과 candidate 판정 비교, shadow 증적 보존 | `--shadow-policy`, reporting 테스트 |
| 관측성 | OBS-01 | Prometheus format으로 gate, finding, VEX, 예외, inventory, 승인 검증 지표 export | `finguard export --format prometheus` |

## 포트폴리오에서 확인할 수 있는 사실

- Python으로 여러 보안 도구의 결과를 정규화하고 하나의 fail-closed 정책 게이트로 결합했습니다.
- 검사한 커밋과 배포할 이미지가 달라지는 문제를 막기 위해 이미지, SBOM, 배포 대상, 승인을 하나의 `ReleaseSubject`에 결속했습니다.
- GitLab CI와 Jenkins가 같은 CLI를 사용하므로 정책 로직이 CI 제품에 종속되지 않습니다.
- 판정 결과를 고정된 입력과 함께 서명하고, 정책 원문과 증적 신선도를 배포 시점에 다시 검증합니다. 승인된 배포 창구 안에서 rollout, smoke test 또는 결과 서명이 실패하면 정확한 이전 digest로 되돌리는 경로도 테스트했습니다.

## 분리해서 말해야 하는 범위

- 이 프로젝트는 금융사 내부 시스템 구축 실적이 아니라, 금융 서비스에 필요한 통제를 기술 설계로 풀어낸 포트폴리오입니다.
- Coverity와 SonarQube는 SARIF adapter와 설정을 구현했지만 실제 상용 서버 API를 기동하지 않았습니다.
- FOSSA 제품 연동은 검증 범위에 포함하지 않았습니다. 대신 Trivy, CycloneDX, SPDX로 같은 관리 경계가 작동하도록 구성했습니다.
- 합성 리포트는 parser와 정책 재현용이며 실제 서비스 취약점 진단 실적이 아닙니다.
