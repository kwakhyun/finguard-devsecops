# 아키텍처와 위협 모델

## 설계 목표

FinGuard의 핵심 질문은 “어떤 소스와 아티팩트를, 누가 만든 검사 결과와 승인으로, 어디에 배포하려는가”입니다. scanner를 여러 개 연결하는 것보다 입력 결속과 사후 검증을 우선했습니다.

## 구성 요소

1. Parser adapter는 Ruff, JUnit, coverage.py, Semgrep, generic SARIF, Trivy, CycloneDX, pip-audit, OWASP ZAP 결과를 `ScanResult`로 변환합니다.
2. Normalization model은 도구 독립적인 심각도와 fingerprint를 만듭니다. scanner 제품명과 메시지는 fingerprint에 넣지 않습니다.
3. Scan attestation은 리포트 hash, scanner 버전, 도구 URI, 전체 소스 commit, 이미지 digest, ruleset과 command hash, DB metadata, 종료 코드, CI job, Runner, 시각을 기록합니다.
4. `ReleaseSubject`는 commit, 이미지, SBOM, 배포 위치, health URL, builder를 하나의 canonical SHA-256로 묶습니다.
5. Approval attestation은 전체 `ChangeRequest` hash와 `ReleaseSubject` hash를 포함하고 운영 정책에서 Cosign 서명을 요구합니다.
6. Policy engine은 이 입력과 정책 예외, VEX, 테스트 지표를 부수 효과 없이 판정합니다.
7. Gate와 verify CLI는 모든 신뢰 입력을 먼저 비공개 snapshot으로 고정합니다. Evidence writer는 그 입력, 판정, 요약, audit chain, manifest를 staging 디렉터리에 쓴 후 원자적으로 게시합니다.
8. Deployment controller는 별도 snapshot에서 증적, 서명, 정책 원문 SHA-256, 평가 시각을 다시 검증하고 승인된 대상만 rollout합니다. 실배포 결과는 반드시 별도 키로 서명하며 rollout, smoke test, 결과 기록 또는 서명이 실패하면 이전 이미지와 감사 annotation을 복원합니다.

## 신뢰 경계

```text
[개발자 / MR Runner]
  │  운영 키와 변경 승인에 접근 불가
  ▼
[보호 릴리스 Runner] ──읽기──> [digest로 고정된 도구 이미지]
  │                         [내부 패키지 mirror]
  │ 단일 빌드, 보안 검사
  ▼
[보호 Attestor] <──공개키 검증── [ITSM 개인키]
  │
  ▼
[FinGuard Gate] ──서명──> [증적 저장소]
  │                         │
  │                         └─> [WORM/SIEM adapter, 미구현]
  ▼
[배포 Runner: 공개키만 보유] ──쓰기──> [운영 Kubernetes API]
```

MR과 릴리스 job을 나누어 신뢰하지 않는 변경이 운영 자격 증명에 도달하지 못하게 했습니다. 게이트 서명과 배포 검증의 키도 나눕니다. 배포 Runner는 공개키만 보유하므로 스스로 PASS 증적을 만들 수 없습니다. 재사용되는 Jenkins agent는 checkout 전에 전용 workspace를 비워 이전 빌드의 report나 미추적 파일이 새 판정과 이미지에 섞이지 않게 합니다.

## 릴리스 불변식

릴리스 gate가 PASS하려면 다음 관계가 모두 성립해야 합니다.

```text
pipeline commit == change commit == ReleaseSubject commit
registry image digest == ReleaseSubject image digest
CycloneDX report SHA-256 == ReleaseSubject SBOM SHA-256
artifact scan image digest == ReleaseSubject image digest
change.release SHA-256 == runtime ReleaseSubject SHA-256
ITSM approval subject SHA-256 == runtime ReleaseSubject SHA-256
ITSM approval change SHA-256 == complete runtime ChangeRequest SHA-256
deployment policy ID/version/SHA-256 == captured evidence policy ID/version/SHA-256
deployment request target == evidence ReleaseSubject target
deployment time - evidence evaluated_at <= policy maximum evidence age
```

Git object ID는 SHA-1이면 40자, SHA-256이면 64자인 전체 값만 허용하고 prefix 일치는 사용하지 않습니다. image는 반드시 `@sha256:<64 hex>` 형식을 사용합니다.

## 판정 순서

1. 필수 category와 scanner가 사용 가능한 결과를 남겼는지 확인합니다.
2. 리포트 hash, 서명, 시각, commit, artifact, Runner, key ID, command hash, 종료 코드, DB 신선도로 scan provenance를 검증합니다.
3. scanner 간 같은 이슈를 fingerprint로 통합하고 가장 높은 알려진 심각도를 보존합니다. `UNKNOWN`이 알려진 Critical 또는 High를 대체하지 못합니다.
4. 유효한 VEX 상태를 처리한 뒤 보상 통제, 유효 기간, 심각도, 환경, 정책 버전을 모두 만족한 예외만 적용합니다.
5. 심각도와 건수, 수정 버전, SPDX 라이선스, 단일 coverage 리포트, 최소 테스트 수와 XML 원시 count 일관성을 판정합니다.
6. CB/SR 형식, 롤백 계획, 승인 역할과 시각, 직무분리를 판정합니다.
7. ITSM 승인 서명과 실행 대상을 다시 대조합니다.
8. 오류 등급 위반이 하나라도 있으면 FAIL을 반환합니다.

## 위협과 통제

| 위협 | 구현 통제 | 남은 운영 과제 |
| --- | --- | --- |
| scanner 실패를 0건으로 오인 | 누락, `ERROR`, `SKIPPED`, 해석 불가 심각도, 필수 필드와 schema 누락을 차단 | false negative는 다중 도구와 규칙 검토로 보완 |
| 악성 또는 과대 리포트로 parser 고갈 | 50 MiB 제한, strict JSON, XML DTD와 entity 거부, 링크 입력 차단 | 대규모 SBOM은 streaming parser 검토 필요 |
| 검증 후 원본 교체 | gate와 deploy가 먼저 비공개 입력 snapshot을 만들고 같은 바이트만 평가, 서명, 사용 | 운영 저장소 권한과 immutable artifact 설정 필요 |
| 다른 커밋이나 이미지의 리포트 재사용 | 서명된 provenance와 `ReleaseSubject` 대조, CI 도구 이미지 서명과 digest 검증 | scanner별 workload identity와 키 격리 필요 |
| 빌드 이전 사전 승인을 최종 아티팩트에 재사용 | 승인 시각이 `built_at`보다 늦은지 확인 | ITSM 시계 동기화와 공개키 회전 |
| CI가 외부 승인을 위조 | ITSM 개인키는 CI에 제공하지 않고 Cosign 공개키로만 검증 | 실제 승인자 직무는 IdP API로 확인 필요 |
| 판정 파일 변조 | 모든 입력 hash, manifest, audit chain, Cosign 서명 | 장기 보존은 WORM 저장소와 KMS audit log 필요 |
| 오래된 PASS 증적 재사용 | 서명된 평가 시각을 배포 시각과 다시 비교하고 정책의 최대 증적 나이를 초과하면 mutation 전 차단 | 중앙 저장소의 보존과 폐기 정책 필요 |
| 오래된 예외의 영구 사용 | 최대 기간, 연장 횟수, 취소, 보상 통제, 독립 승인자 | 정기 재검토 job과 소유자 알림 필요 |
| 동시 배포 충돌 | GitLab resource group, Jenkins concurrent build 차단, DAST job별 고유 리소스 | 두 CI를 동시 운영하면 외부 분산 잠금 필요 |
| 배포 후 서비스 불능 | rollout 확인, 서명된 health URL smoke test, 정확한 이전 digest와 annotation 복원 | 비가역 DB migration은 expand-contract 절차 필요 |

## 주요 선택

- 코어는 Python 3.11 표준 라이브러리만 사용해 폐쇄망 설치 부담과 실행 시 의존성 면적을 줄였습니다.
- scanner 실행과 정책 판정을 나누어 도구 교체가 배포 기준을 바꾸지 않게 했습니다.
- 라이선스 inventory는 취약점 finding 건수에 포함하지 않고 별도 집계합니다.
- 보호 릴리스는 Cosign을 요구하고, HMAC은 외부 의존성 없는 로컬 시연에만 남겼습니다.
- 정책을 즉시 교체하지 않고 shadow 판정으로 기존과 후보 결과를 비교할 수 있게 했습니다.
