# 운영과 장애 대응 런북

## CLI 종료 코드

| 코드 | 의미 | 조치 |
| ---: | --- | --- |
| 0 | 검사 또는 gate 통과 | 다음 단계 진행 |
| 2 | 정책 위반 | `summary.md`와 `decision.json` 확인 |
| 3 | 정책, 리포트, 서명, 증적 입력 오류 | 원본 복구 또는 재실행 |
| 4 | 내장 scanner 실행 오류 | 대상과 Runner 상태 확인 |
| 130 | 사용자 중단 | 중단 원인 기록 후 재실행 |

## Gate 실패

1. `summary.md`에서 violation code를 확인합니다.
2. `decision.json`의 fingerprint와 `observed_by`로 원본 scanner report를 찾습니다.
3. 입력이 `inputs/`에 존재하는지, manifest hash와 audit chain이 유효한지 확인합니다.
4. 수정 가능한 이슈는 소스나 의존성을 수정하고 같은 commit을 새로 빌드합니다. 이전 리포트를 재사용하지 않습니다.
5. 즉시 수정할 수 없다면 보상 통제, 소유자, 독립 승인자, 위험 ticket, 정책 범위, 만료일을 포함한 예외를 요청합니다.

## Scanner와 provenance 장애

필수 리포트가 없거나 scanner가 오류로 종료하면 gate는 실패합니다. 빈 JSON을 만들어 통과시키지 않습니다. Semgrep, Trivy, CycloneDX, Ruff, pip-audit, ZAP은 필수 schema와 finding 필드를 검사하며 malformed record 하나라도 있으면 전체 입력을 거부합니다. CycloneDX의 중첩 component도 재귀적으로 집계하고 선언 심각도보다 높은 CVSS 점수를 낮춰 해석하지 않습니다. `null` fixed version은 수정 버전이 있는 것으로 보지 않습니다.

1. 내부 registry와 패키지 mirror 상태를 확인합니다.
2. scanner image digest, tool version, ruleset hash, 허용 command hash, 종료 코드, Runner ID가 예정된 값인지 확인합니다.
3. `SCAN_ATTESTATION_STALE`이면 이전 artifact를 붙여 쓰지 말고 같은 commit의 스캔을 재실행합니다.
4. signer나 Runner 허용 목록을 바꾸어 장애를 우회하지 않습니다. 키 회전은 별도 변경으로 처리합니다.

## 외부 승인 실패

| violation | 우선 확인 |
| --- | --- |
| `APPROVAL_ATTESTATION_MISSING` | ITSM이 approval JSON과 detached Cosign bundle을 모두 게시했는지 |
| `APPROVAL_ATTESTATION_UNTRUSTED` | 올바른 공개키와 bundle을 사용했는지 |
| `APPROVAL_ISSUER_UNTRUSTED` | 정책의 ITSM issuer 허용 목록과 일치하는지 |
| `APPROVAL_SIGNER_UNTRUSTED` | 회전 기간의 key ID가 정책에 포함되었는지 |
| `APPROVAL_ATTESTATION_SUBJECT_MISMATCH` | 승인 후 이미지, SBOM, commit, 배포 대상, 위험도, 창구, 롤백 계획 또는 역할이 바뀌지 않았는지 |
| `APPROVAL_ATTESTATION_TIME_INVALID` | 승인 증적이 최종 빌드와 모든 승인 이후에 발급되었는지 |

승인이 대상과 다르면 파일을 수정하지 말고 ITSM에서 해당 `ReleaseSubject`를 다시 검토하고 새 증적을 발급합니다.

## 증적 무결성

로컬 HMAC 검증:

```bash
.venv/bin/python -m finguard verify \
  --evidence build/evidence \
  --signing-key-env FINGUARD_EVIDENCE_KEY
```

운영 Cosign 검증:

```bash
.venv/bin/python -m finguard verify \
  --evidence build/evidence \
  --cosign-verification-key /run/secrets/finguard-evidence.pub
```

해시, audit chain, release subject digest, 정책 ID와 버전 및 원문 SHA-256, 서명 중 하나라도 맞지 않으면 해당 증적으로 배포하지 않습니다. 원본 CI job과 중앙 저장소를 비교하고 KMS 접근 로그를 조사합니다.

운영 증적은 CI artifact 만료에만 의존하지 않고, 조직 보존 정책에 맞는 object lock 저장소로 이관해 변경 ID, commit, image digest, subject hash로 색인합니다.

## 배포 실패와 rollback

배포 전에 정책이 허용한 증적 나이를 초과했거나 평가 시각이 미래이면 새 gate를 실행합니다. 정책 ID, 버전, SHA-256는 파이프라인 허용값과 모두 같아야 합니다. `kubectl auth can-i` preflight가 실패하면 아무 변경도 수행하지 않습니다. mutation 전에 대상 container의 현재 불변 이미지와 FinGuard 감사 annotation을 읽습니다. 이미지 교체 후 rollout, smoke test, 결과 파일 저장 또는 Cosign 서명이 실패하면 그 정확한 이전 이미지와 annotation을 다시 적용하고 rollout 완료를 확인합니다. revision 기반 `rollout undo`에 의존하지 않으므로 다른 revision을 잘못 선택하지 않습니다.

실제 배포는 `--result-cosign-signing-key`가 없으면 mutation 전에 실패합니다. 배포 결과와 서명 bundle은 기본적으로 기존 파일을 덮어쓰지 않습니다. 서명 bundle은 같은 디렉터리의 임시 파일에서 완성한 후에만 원자적으로 게시하므로 signer 실패 시 부분 파일을 제거합니다. 재실행할 때는 build ID가 포함된 새 경로를 사용합니다. 의도적으로 교체해야 할 때만 `--force-result`를 사용합니다.

rollback도 실패하면 무한 재시도하지 않고 운영 변경을 중지합니다. 다음을 기준으로 장애 절차를 시작합니다.

- 변경 ID와 증적 manifest SHA-256
- 이전과 신규 이미지 digest
- 복원 전후의 `finguard.io/change-id`, evidence hash, release subject hash annotation
- Kubernetes event, pod 상태, smoke test 실패 시각
- 데이터베이스 migration의 역호환성
- 서비스 SLO와 고객 영향

## 키 회전

1. 새 key ID와 공개키를 정책과 배포 Runner에 추가합니다.
2. 이전과 새 키를 함께 검증하는 짧은 전환 기간을 둡니다.
3. ITSM 또는 gate signer를 새 개인키로 전환합니다.
4. 이전 key ID를 정책에서 제거하고 KMS audit log를 보존합니다.

## 관측 지표

```bash
.venv/bin/python -m finguard export \
  --decision build/evidence/decision.json \
  --format prometheus \
  --output build/finguard.prom
```

주요 알림 후보는 gate FAIL 비율 급증, scanner 누락, Critical/High 이슈, 예외 건수 증가, 승인 서명 검증 실패입니다. 이 저장소는 metric 파일을 생성하지만 Pushgateway나 SIEM으로 전송하는 외부 adapter는 포함하지 않습니다.
