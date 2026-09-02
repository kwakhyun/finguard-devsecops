# FinGuard DevSecOps 포트폴리오

## 프로젝트 요약

FinGuard는 여러 품질 및 보안 도구의 결과를 하나의 모델로 정규화하고, 검사 대상과 승인 대상, 배포 대상이 모두 일치할 때만 릴리스를 허용하는 Python 기반 정책 게이트입니다. 폐쇄망과 온프레미스 운영을 고려해 핵심 로직은 Python 3.11 표준 라이브러리만 사용했습니다.

| 항목 | 내용 |
| --- | --- |
| 개발자 | [@kwakhyun](https://github.com/kwakhyun) |
| 개발 형태 | 개인 프로젝트 |
| 기여도 | 100% — 기획, 설계, 구현, 테스트, CI/CD, 문서화 |
| 주요 기술 | Python, Bash, GitLab CI, Jenkins, GitHub Actions, Semgrep, Trivy, CycloneDX, SPDX, OWASP ZAP, Cosign, Kubernetes |
| 검증 | Ruff, Mypy, 195개 테스트, 85% 이상 커버리지, 정상 통과 및 위험 변경 차단 E2E 시나리오 |

## 해결하려는 문제

보안 도구를 파이프라인에 추가하는 것만으로는 검사한 소스와 최종 배포 이미지가 같다는 사실을 보장할 수 없습니다. 오래된 스캔 결과나 다른 이미지의 승인 증적이 재사용되면 모든 검사가 성공해도 잘못된 릴리스가 배포될 수 있습니다.

FinGuard는 커밋, 이미지 다이제스트, SBOM 해시, 배포 위치, 상태 확인 URL을 하나의 `ReleaseSubject`로 묶습니다. 스캔 실행 증명서, 변경 요청, 외부 승인, 최종 증적, 배포 요청이 모두 같은 대상을 가리킬 때만 PASS를 생성합니다.

## 핵심 설계 결정

1. **도구 실행과 정책 판정을 분리했습니다.** 스캐너는 CI에서 독립적으로 실행하고 FinGuard는 결과 정규화와 판정만 담당합니다. Semgrep, Coverity, SonarQube처럼 도구가 바뀌어도 정책 모델을 유지할 수 있습니다.
2. **검증한 입력을 배포 대상에 결속했습니다.** 전체 Git 객체 ID, 불변 이미지 다이제스트, SBOM 해시, 배포 위치가 하나라도 다르면 오류 시 차단 방식으로 처리합니다.
3. **외부 승인과 CI 권한을 분리했습니다.** 운영 경로는 ITSM이 발급한 Cosign 승인 증적을 공개키로만 검증하도록 설계했습니다. 로컬 HMAC은 재현 가능한 데모에만 사용합니다.
4. **판정뿐 아니라 실패 복구도 검증했습니다.** 롤아웃, 스모크 테스트 또는 결과 서명에 실패하면 배포 직전의 이미지 다이제스트와 감사 애너테이션을 복원합니다.

## 직무 역량 증거

| 역량 | 구현 증거 |
| --- | --- |
| Python과 Bash 자동화 | 12개 CLI 명령, 데모 및 운영 스크립트, 명시적인 종료 코드 |
| SAST, SCA, DAST | Semgrep/SARIF, Trivy/CycloneDX, SPDX, pip-audit, OWASP ZAP 파서와 정책 통합 |
| 정책 기반 품질 관리 | 심각도, 테스트, 커버리지, 라이선스, VEX, 예외 만료, 직무분리를 TOML로 관리 |
| CI/CD | GitLab과 Jenkins의 MR/릴리스 신뢰 경계, GitHub Actions 공개 재현 파이프라인, 보호된 `main` |
| 변경 및 배포 통제 | CB/SR, 승인 시각, 배포 시간 창구, 불변 이미지, Kubernetes 사전 권한 검사와 롤백 |
| 감사 가능성 | 입력 스냅샷, SHA-256 매니페스트, 해시 체인 감사 로그, HMAC/Cosign 서명 |

## 5분 검토 순서

1. [README](README.md)의 핵심 결과와 로컬 재현 명령을 확인합니다.
2. [아키텍처와 위협 모델](docs/architecture.md)에서 신뢰 경계와 릴리스 불변식을 확인합니다.
3. [통제 구현 매핑](docs/control-mapping.md)에서 코드 및 테스트 증거를 확인합니다.
4. [GitHub Actions](https://github.com/kwakhyun/finguard-devsecops/actions/workflows/portfolio-ci.yml)에서 실제 Semgrep, Trivy, ZAP 실행 결과를 확인합니다.
5. [면접 시연 가이드](docs/portfolio-guide.md)로 정상 릴리스와 위험 릴리스 차단을 재현합니다.

## 검증 범위와 한계

예제 스캔 보고서와 샘플 서비스를 이용한 독립 포트폴리오이며 실제 금융사 운영 실적이나 규제 준수 인증을 주장하지 않습니다.
공개 CI는 실제 Semgrep, Trivy, ZAP을 실행하지만, 상용 Coverity/FOSSA API, 실제 ITSM과 IdP, KMS, 온프레미스 Kubernetes 운영은 검증 범위에 포함하지 않았습니다.
운영 확장 항목은 [로드맵](docs/roadmap.md)에 별도로 관리합니다.
