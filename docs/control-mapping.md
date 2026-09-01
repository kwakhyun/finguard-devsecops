# DevOps 역량과 통제 구현 매핑

이 문서는 DevOps와 DevSecOps 직무의 주요 기술 영역을 실제 코드와 검증 증거에 연결합니다. 경력 연차나 특정 산업의 실무 경험처럼 이 저장소로 입증할 수 없는 항목은 분리해 적습니다.

| 영역 | 통제 ID | 구현 | 검증 증거 |
| --- | --- | --- | --- |
| Python, Bash 자동화 | AUTO-01 | 12개 CLI 명령, 데모 및 운영 스크립트, 일관된 종료 코드 | `finguard/cli.py`, `scripts/`, CLI 테스트 |
| 품질 정책 | QUAL-01 | Ruff, JUnit, coverage.py 정규화, 단일 커버리지 보고서, 임계값 | `tests/test_gate.py`, `COVERAGE_REPORT_AMBIGUOUS` 테스트 |
| Secure Coding, SAST | SAST-01 | Semgrep 사용자 규칙, 로컬 AST 스캐너, 범용 SARIF 2.1 어댑터 | `.semgrep/`, `finguard/parsers/sarif.py` |
| Coverity, SonarQube 확장 | SAST-02 | SARIF를 통한 도구 독립 수집, SonarQube 프로젝트 설정 | `tests/test_reporting.py`, `sonar-project.properties` |
| SCA, SBOM | SCA-01 | Trivy, pip-audit, 중첩 CycloneDX 구성 요소 인벤토리 정규화, CVSS와 선언 심각도 중 더 높은 값 적용 | `finguard/parsers/json_scanners.py` |
| OSS 라이선스 | OSS-01 | SPDX `AND`, `OR`, `WITH` 표현식, 허용, 금지, 법무 검토 | `finguard/licenses.py`, 표현식 테스트 |
| VEX | SCA-02 | 스캐너 자체 분석은 감사 정보로만 보존하고, 별도로 서명한 VEX의 대상, 발급자, 키, 유효 기간, 근거만 탐지 결과 억제에 사용 | `finguard/vex.py`, `tests/test_vex.py` |
| DAST | DAST-01 | OWASP ZAP 인스턴스별 URI, 메서드, 매개변수를 보존하고 릴리스 필수 잡으로 실행 | ZAP 파서 테스트, CI 파일 |
| 스캐너 실패 | SAFE-01 | 누락, 오류, 건너뜀, 알 수 없는 심각도를 오류 시 차단 방식으로 처리 | `REQUIRED_SCAN_MISSING`, `SCANNER_ERROR` |
| 입력 안전성 | SAFE-02 | 엄격한 JSON 파싱, 스캐너 스키마와 필수 필드, 50 MiB 상한, XML DTD 및 엔터티 거부, 링크 입력 거부 | 파서와 증적 강화 테스트 |
| 입력 일관성 | SAFE-03 | 게이트, 검증, 배포 명령이 신뢰 입력을 비공개 스냅샷으로 고정한 뒤 동일한 바이트만 평가하고 사용 | CLI 스냅샷 회귀 테스트 |
| 스캔 실행 증명서 | SUP-01 | 보고서, 규칙 세트, 허용된 명령어 해시, 종료 코드, 커밋, 아티팩트, 취약점 DB, Runner, 서명자, 최신성 검증 | `finguard/attestation.py`, P0/P1 강화 테스트 |
| 릴리스 대상 | SUP-02 | 커밋, 이미지, SBOM, 배포 위치를 정규형 SHA-256으로 결속 | `finguard/release.py`, 불일치 테스트 |
| 정책 예외 | GOV-01 | 탐지 결과의 범위, 최대 30일, 연장 횟수, 취소, 보상 통제, 직무분리 | `finguard/config.py`, 예외 통제 테스트 |
| CB/SR 변경 통제 | CHG-01 | 커밋, 승인 역할, 롤백 계획, 배포 시간 창구, 최종 빌드 후 승인 | `finguard/change.py`, `tests/test_gate.py` |
| 외부 승인 신뢰 | CHG-02 | ITSM 발급자 및 Cosign 키 허용 목록, 전체 변경 요청 해시와 릴리스 대상 대조 | `finguard/approvals.py`, `tests/test_approvals.py` |
| 감사 증적 | AUD-01 | 원본 스냅샷, 매니페스트, 허용 파일만 인정하는 폐쇄형 검증, 해시 체인, 키 ID를 포함한 HMAC, Cosign 번들 | `finguard/evidence.py`, 변조 탐지 테스트 |
| 증적 생성 안전성 | AUD-02 | 준비 디렉터리 작성 후 원자적 게시, 소유 표식, 출력 링크와 저장소 루트 보호 | `test_force_never_replaces_an_unowned_directory` |
| Git 협업 | FLOW-01 | CODEOWNERS, PR/MR 템플릿, 보호된 `main`, 필수 CI 검사, MR과 릴리스의 신뢰 경계 분리 | `.github/`, `.gitlab/`, 공개 PR 이력, 파이프라인 계약 테스트 |
| GitLab CI | CI-01 | `needs` DAG, 루트 권한이 필요 없는 BuildKit 단일 빌드, Code Quality, 리소스 그룹 | `.gitlab-ci.yml` |
| Jenkins | CI-02 | 병렬 검사, Podman 단일 빌드, 자격 증명 바인딩, 수동 승인 | `Jenkinsfile` |
| 공개 CI 재현 | CI-03 | GitHub Actions에서 품질 검사와 E2E 데모, 실제 Semgrep, Trivy, ZAP 결과를 정책 게이트로 판정 | `.github/workflows/portfolio-ci.yml`, 종료 코드 계약 테스트 |
| 공급망 고정 | SUP-03 | CI와 Dockerfile에서 이미지 다이제스트 요구, 인프라 이미지 실행 전 검증 | `validate-images`, `validate_onprem_images.py` |
| 의존성 갱신 | SUP-04 | Python과 GitHub Actions 의존성을 Dependabot이 주간 주기로 점검 | `.github/dependabot.yml`, GitHub 취약점 알림 |
| 배포 통제 | DEP-01 | PASS 증적, Cosign, 정책 ID와 버전 및 원문 해시, 증적 유효성, 클러스터와 워크로드 및 이미지가 승인 대상과 일치하는지 확인, RBAC 및 배포 시간 창구 검증 | `finguard/deployment.py`, 오래된 증적 회귀 테스트 |
| 자동 롤백 | DEP-02 | 롤아웃, 스모크 테스트, 결과 저장 또는 서명에 실패하면 직전 불변 이미지와 기존 감사 애너테이션 복원 | 배포 실패 테스트 |
| 배포 감사 | AUD-03 | 실제 배포 결과의 Cosign 서명 강제, 기존 결과와 서명 번들 덮어쓰기 기본 금지, 완성된 번들만 원자적으로 게시 | 서명된 결과 회귀 테스트 |
| 개발자 피드백 | DX-01 | GitLab Code Quality, SARIF 내보내기, 로컬 스캐너 | `finguard/reporting.py` |
| 정책 적용 | GOV-02 | 기준 정책과 후보 정책의 판정 비교, 섀도 증적 보존 | `--shadow-policy`, 보고서 생성 테스트 |
| 관측성 | OBS-01 | 게이트, 탐지 결과, VEX, 예외, 인벤토리, 승인 검증 지표를 Prometheus 형식으로 출력 | `finguard export --format prometheus` |

## 포트폴리오에서 확인할 수 있는 사실

- Python으로 여러 보안 도구의 결과를 정규화하고 오류 시 차단하는 하나의 정책 게이트로 결합했습니다.
- 검사한 커밋과 배포할 이미지가 달라지는 문제를 막기 위해 이미지, SBOM, 배포 대상, 승인을 하나의 `ReleaseSubject`에 결속했습니다.
- GitLab CI와 Jenkins가 같은 CLI를 사용하므로 정책 로직이 CI 제품에 종속되지 않습니다.
- 판정 결과를 고정된 입력과 함께 서명하고, 정책 원문과 증적 유효성을 배포 시점에 다시 검증합니다. 승인된 배포 시간 창구 안에서도 롤아웃, 스모크 테스트 또는 결과 서명에 실패하면 정확한 이전 다이제스트로 되돌아가는 경로를 테스트했습니다.

## 분리해서 말해야 하는 범위

- 이 프로젝트는 금융사 내부 시스템 구축 실적이 아니라, 금융 서비스에 필요한 통제를 기술로 구현한 포트폴리오입니다.
- Coverity와 SonarQube는 SARIF 어댑터와 설정을 구현했지만 실제 상용 서버 API와 연동하지 않았습니다.
- FOSSA 제품 연동은 검증 범위에 포함하지 않았습니다. 대신 Trivy, CycloneDX, SPDX로 OSS 취약점과 라이선스를 관리하는 통제를 구성했습니다.
- 합성 보고서는 파서와 정책을 재현하기 위한 입력이며 실제 서비스 취약점 진단 실적이 아닙니다.
