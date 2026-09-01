# 단계별 개선 이력과 로드맵

상태는 이 저장소의 코드와 테스트로 확인한 범위만 표시합니다. 외부 서버 연동이 필요한 항목은 인터페이스를 구현했더라도 완료로 적지 않았습니다.

## P0: 우회, 변조, 오배포 차단 — 완료

| 개선 | 완료 기준 | 구현 위치 |
| --- | --- | --- |
| 안전한 증적 생성 | FinGuard 소유 bundle만 교체, 링크 입력 거부, staging 후 원자적 게시 | `finguard/evidence.py` |
| 릴리스 대상 결속 | commit, image, SBOM, 배포 위치, health URL을 canonical hash로 대조 | `finguard/release.py` |
| 승인 대상 결속 | 전체 변경 요청과 릴리스 대상 hash를 ITSM 서명 payload에 포함 | `finguard/approvals.py` |
| 배포 정책 결속 | 허용한 정책 ID, 버전, 원문 SHA-256가 증적의 캡처 정책과 모두 일치해야 배포 | `finguard/deployment.py`, pipeline contract 테스트 |
| 평가 입력 고정 | gate, verify, deploy가 private snapshot의 동일 바이트만 검증하고 사용 | `finguard/cli.py` |
| 단일 빌드 | 등록소 digest를 SCA, DAST, 승인, 배포에 재사용 | GitLab CI, Jenkinsfile |
| CI 신뢰 분리 | MR job에 운영 키, 변경 승인, Kubernetes 자격 미제공 | pipeline contract 테스트 |
| 부동 도구 이미지 | CI, Dockerfile, 온프레미스 인프라가 digest 참조만 사용 | `validate-images`, 운영 wrapper |
| 안전한 정리 | `make clean` 범위를 저장소의 `build/`로 고정 | `scripts/clean_build.py` |
| 재사용 Runner 오염 차단 | Jenkins가 checkout 전에 전용 workspace를 비워 이전 report, attestation, 미추적 소스를 제거 | `Jenkinsfile`, pipeline contract 테스트 |

## P1: 판정 정확성과 감사 통제 — 완료

| 개선 | 완료 기준 | 구현 위치 |
| --- | --- | --- |
| scan provenance | report, scanner, source, artifact, ruleset, 허용 command hash, 종료 코드, DB, CI 실행 정보, 서명, 신선도 검증 | `finguard/attestation.py` |
| 파서 정확성 | strict JSON, schema와 필수 필드, ZAP 인스턴스, 중첩 CycloneDX component와 CVSS 교차검증, generic SARIF, XML count와 DTD 검증 | `finguard/parsers/` |
| scanner 간 중복 제거 | 도구명과 메시지를 fingerprint에서 제거, 경로 대소문자와 라이선스 버전 구분, 알려진 최고 심각도와 `observed_by` 보존 | `finguard/models.py`, `finguard/gate.py` |
| 정책 모호성 차단 | severity alias, 승인 역할, 라이선스 식별자의 의미상 중복과 상충 분류를 로딩 시 거부 | `finguard/config.py` |
| SPDX 표현식 | `AND`, `OR`, `WITH`, 괄호를 fail-closed로 평가 | `finguard/licenses.py` |
| 예외 governance | 심각도, category, 정책, 서비스, 환경, 기간, 연장, 취소, 보상 통제 | `finguard/config.py` |
| VEX | 별도 서명 증적의 subject, issuer, key, 기간, 근거만 suppression에 사용 | `finguard/vex.py` |
| 테스트 지표 | 여러 coverage 결과의 모호성, 0 tests, 선언 count와 실제 testcase 불일치 차단 | hardening 테스트 |
| 배포 증적 신선도 | 미래 시각 또는 정책 최대 나이를 넘긴 PASS 증적 재사용 차단 | deployment 회귀 테스트 |
| 배포 감사 서명 | 실제 배포 결과의 Cosign 서명 강제, 기존 결과 기본 덮어쓰기 금지, 부분 bundle 원자적 게시 | signing 및 deployment 회귀 테스트 |

## 기능 고도화 1: 승인과 서명 경계 — 완료

- ITSM approval attestation을 전체 `ChangeRequest` hash, `ReleaseSubject` hash, 발급 시각에 결속했습니다.
- 보호 릴리스 정책은 허용된 ITSM issuer, Cosign signature method, key ID만 인정합니다.
- 외부 승인 개인키를 CI에 주입하지 않고 공개키로만 검증합니다.
- 최종 증적도 KMS 또는 Vault URI를 사용한 Cosign으로 서명하고, 배포 Runner는 공개키만 가집니다.

## 기능 고도화 2: 개발자 피드백과 정책 rollout — 완료

- GitLab Code Quality와 SARIF export를 제공합니다.
- baseline과 candidate 판정의 violation과 fingerprint 변화를 비교합니다.
- `--shadow-policy`는 기존 판정을 바꾸지 않고 후보 정책 결과를 증적에 함께 보존합니다.
- MR은 운영 승인을 요구하지 않는 전용 정책으로 빠르게 실패 원인을 보여줍니다.

## 기능 고도화 3: 배포 안전성과 관측성 — 완료

- Kubernetes context와 namespace를 명시하고 `auth can-i` preflight를 통과해야 변경합니다.
- 승인된 health URL로 재시도가 있는 smoke test를 실행합니다. 실배포 결과 서명을 강제하고 rollout, smoke test 또는 결과 서명이 실패하면 정확한 이전 이미지와 감사 annotation을 복원합니다.
- Prometheus format으로 gate, severity, 예외, VEX, OSS inventory, 승인 서명 지표를 생성합니다.
- GitLab DAST network와 container 이름을 pipeline/job ID로 분리했습니다.

## 다음 우선순위

### P2: 실제 외부 시스템 통합

1. ITSM API와 IdP 그룹을 연결해 승인자의 현재 직무를 검증합니다.
2. 현재 각 scanner 실행 job이 직접 발급하는 HMAC attestation을 플랫폼 workload identity와 scanner별 단기 키로 교체합니다.
3. policy bundle과 scanner ruleset을 별도 공급망 증적으로 서명하고 해시 허용 목록을 자동 관리합니다.
4. Dependency-Track, FOSSA 또는 사내 OSS API에 SBOM을 전송하고 법무 승인 상태를 회수합니다.

### P2: 공급망 재현성

1. `requirements-dev.lock`에 포함된 정확 버전을 아티팩트 해시와 함께 관리하고 `--require-hashes`를 적용합니다.
2. 폐쇄망 패키지 mirror 스냅샷과 컨테이너 반입 목록을 릴리스 증적에 추가합니다.
3. OCI registry에 SLSA provenance, SBOM, VEX, 판정을 referrer로 게시합니다.

### P3: 운영 플랫폼

1. 증적을 WORM 또는 object-lock 저장소로 자동 이관하고 색인합니다.
2. Prometheus Pushgateway와 SIEM adapter를 추가하고 SLO와 경보 기준을 정의합니다.
3. GitLab과 Jenkins를 함께 운영하는 경우를 위한 외부 분산 배포 잠금을 도입합니다.
4. 비가역 데이터베이스 변경을 위한 expand-contract 검증과 연습 환경 복구 테스트를 추가합니다.

## 완료 판정 기준

다음 작업은 코드가 존재한다고 완료로 보지 않습니다. 실제 외부 시스템의 신뢰 경계를 통한 통합 테스트, 회전과 장애 사례, 런북, 감사 로그까지 확인해야 완료입니다.
