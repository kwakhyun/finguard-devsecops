# 운영과 장애 대응 런북

## CLI 종료 코드

| 코드 | 의미 | 조치 |
| ---: | --- | --- |
| 0 | 검사 또는 게이트 통과 | 다음 단계 진행 |
| 2 | 정책 위반 | `summary.md`와 `decision.json` 확인 |
| 3 | 정책, 보고서, 서명, 증적 입력 오류 | 원본 복구 또는 재실행 |
| 4 | 내장 스캐너 실행 오류 | 검사 대상과 Runner 상태 확인 |
| 130 | 사용자 중단 | 중단 원인 기록 후 재실행 |

## 게이트 실패

1. `summary.md`에서 위반 코드를 확인합니다.
2. `decision.json`의 `fingerprint`와 `observed_by`를 이용해 원본 스캐너 보고서를 찾습니다.
3. 입력이 `inputs/`에 존재하는지, 매니페스트 해시와 감사 체인이 유효한지 확인합니다.
4. 수정할 수 있는 이슈라면 소스나 의존성을 고치고 변경 내용을 새 커밋으로 기록한 뒤 이미지를 다시 빌드합니다. 이전 보고서는 재사용하지 않습니다.
5. 즉시 수정할 수 없다면 보상 통제, 소유자, 독립 승인자, 위험 티켓, 정책 범위, 만료일을 포함한 예외를 요청합니다.

## 스캐너 및 실행 증명서 장애

필수 보고서가 없거나 스캐너가 오류로 종료하면 게이트는 실패합니다. 빈 JSON을 만들어 통과시키지 않습니다. Semgrep, Trivy, CycloneDX, Ruff, pip-audit, ZAP 보고서에서는 필수 스키마와 탐지 필드를 검사합니다. 형식이 잘못된 레코드가 하나라도 있으면 전체 입력을 거부합니다.

CycloneDX의 중첩 구성 요소도 재귀적으로 집계하며, 선언된 심각도보다 높은 CVSS 점수를 낮춰 해석하지 않습니다. 수정 버전이 `null`이면 수정 가능한 버전이 없는 것으로 판단합니다.

1. 내부 레지스트리와 패키지 미러 상태를 확인합니다.
2. 스캐너 이미지 다이제스트, 도구 버전, 규칙 세트 해시, 허용된 명령어 해시, 종료 코드, Runner ID가 예정된 값인지 확인합니다.
3. `SCAN_ATTESTATION_STALE`이면 이전 아티팩트를 재사용하지 말고 동일한 커밋을 다시 스캔합니다.
4. 서명자나 Runner의 허용 목록을 바꿔 장애를 우회하지 않습니다. 키 회전은 별도 변경으로 처리합니다.

## 외부 승인 실패

| 위반 코드 | 우선 확인 항목 |
| --- | --- |
| `APPROVAL_ATTESTATION_MISSING` | ITSM이 승인 JSON과 분리형 Cosign 번들을 모두 게시했는지 |
| `APPROVAL_ATTESTATION_UNTRUSTED` | 올바른 공개키와 번들을 사용했는지 |
| `APPROVAL_ISSUER_UNTRUSTED` | 정책의 ITSM 발급자 허용 목록과 일치하는지 |
| `APPROVAL_SIGNER_UNTRUSTED` | 회전 기간에 사용할 키 ID가 정책에 포함되었는지 |
| `APPROVAL_ATTESTATION_SUBJECT_MISMATCH` | 승인 후 이미지, SBOM, 커밋, 배포 대상, 위험도, 시간 창구, 롤백 계획 또는 역할이 바뀌지 않았는지 |
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

해시, 감사 체인, 릴리스 대상 다이제스트, 정책 ID와 버전, 정책 원문의 SHA-256, 서명 중 하나라도 맞지 않으면 해당 증적으로 배포하지 않습니다. 원본 CI 잡과 중앙 저장소를 비교하고 KMS 접근 로그를 조사합니다.

운영 증적은 CI 아티팩트의 만료 기간에만 의존하지 않습니다. 조직의 보존 정책에 맞는 객체 잠금 저장소로 이관하고 변경 ID, 커밋, 이미지 다이제스트, 릴리스 대상 해시로 색인합니다.

## 배포 실패와 롤백

증적 생성 후 경과 시간이 정책 한도를 초과했거나 평가 시각이 미래라면 배포 전에 새 게이트를 실행합니다. 정책 ID, 버전, SHA-256은 파이프라인 허용값과 모두 같아야 합니다. `kubectl auth can-i` 사전 권한 검사에 실패하면 아무 변경도 수행하지 않습니다.

실제 변경을 시작하기 전에 대상 컨테이너의 현재 불변 이미지와 FinGuard 감사 애너테이션을 읽습니다. 이미지 교체 후 롤아웃, 스모크 테스트, 결과 파일 저장 또는 Cosign 서명에 실패하면 정확한 이전 이미지와 애너테이션을 다시 적용하고 롤아웃 완료를 확인합니다.

리비전 기반의 `rollout undo`에 의존하지 않으므로 잘못된 리비전을 선택하는 상황을 피할 수 있습니다.

실제 배포는 `--result-cosign-signing-key`가 없으면 Kubernetes를 변경하기 전에 실패합니다. 배포 결과와 서명 번들은 기본적으로 기존 파일을 덮어쓰지 않습니다.

서명 번들은 같은 디렉터리의 임시 파일에서 완성한 후에만 원자적으로 게시하므로, 서명에 실패하면 불완전한 파일을 제거합니다. 재실행할 때는 빌드 ID가 포함된 새 경로를 사용합니다. 기존 결과를 의도적으로 교체할 때만 `--force-result`를 사용합니다.

롤백까지 실패하면 무한히 재시도하지 않고 운영 변경을 중지합니다. 다음 정보를 기준으로 장애 대응 절차를 시작합니다.

- 변경 ID와 증적 매니페스트 SHA-256
- 이전 이미지와 신규 이미지의 다이제스트
- 복원 전후의 `finguard.io/change-id`, 증적 해시, 릴리스 대상 해시 애너테이션
- Kubernetes 이벤트, Pod 상태, 스모크 테스트 실패 시각
- 데이터베이스 마이그레이션의 역호환성
- 서비스 SLO와 고객 영향

## 키 회전

1. 새 키 ID와 공개키를 정책과 배포 Runner에 추가합니다.
2. 이전과 새 키를 함께 검증하는 짧은 전환 기간을 둡니다.
3. ITSM 또는 게이트 서명자를 새 개인키로 전환합니다.
4. 이전 키 ID를 정책에서 제거하고 KMS 감사 로그를 보존합니다.

## 관측 지표

```bash
.venv/bin/python -m finguard export \
  --decision build/evidence/decision.json \
  --format prometheus \
  --output build/finguard.prom
```

주요 알림 대상은 게이트 FAIL 비율 급증, 스캐너 누락, Critical/High 이슈, 예외 건수 증가, 승인 서명 검증 실패입니다. 이 저장소는 지표 파일을 생성하지만 Pushgateway나 SIEM으로 전송하는 외부 어댑터는 포함하지 않습니다.
