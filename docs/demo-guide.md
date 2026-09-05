# 사용 예제와 검증 가이드

## 정상 및 차단 흐름 재현

### 1. 릴리스 대상 확인

FinGuard는 검사한 커밋, 승인한 이미지와 실제 배포 대상이 같은지 검증합니다. `ReleaseSubject`는 커밋, 이미지 다이제스트, SBOM과 배포 위치를 하나의 식별자로 묶으며, 스캔 결과와 승인 증적도 이 대상에 연결됩니다.

### 2. 정상 변경과 증적 검증

```bash
mkdir -p build
demo_output="$(mktemp -d build/demo-evidence.XXXXXX)"
export FINGUARD_DEMO_SIGNING_KEY='local-demo-only-do-not-reuse'
.venv/bin/python -m finguard demo \
  --scenario pass \
  --output "${demo_output}" \
  --signing-key-env FINGUARD_DEMO_SIGNING_KEY \
  --signing-key-id local-demo-v1
.venv/bin/python -m finguard verify \
  --evidence "${demo_output}/pass" \
  --signing-key-env FINGUARD_DEMO_SIGNING_KEY
```

`decision: pass`, 정책 ID, 변경 ID, 검증된 파일 수를 확인합니다. 이어서 `inputs/`, `decision.json`, `summary.md`, `audit.jsonl`, `manifest.json`을 순서대로 확인합니다. 판정 결과와 원본 입력이 같은 증적 번들에 보존됩니다.

### 3. 위험 변경 차단

```bash
.venv/bin/python -m finguard demo \
  --scenario fail \
  --output "${demo_output}"
```

종료 코드 `2`와 다음 원인을 확인합니다.

- Critical 등급의 SCA 취약점과 High 등급의 SAST 위반
- 수정 버전이 없는 차단 등급 취약점
- 정책에서 금지한 AGPL 라이선스
- 커버리지 부족과 테스트 실패
- 구체성이 부족한 롤백 계획과 필수 승인 역할 누락
- 요청자와 배포자가 같은 직무분리 위반

### 4. 검사, 승인, 배포 대상의 일치 여부 확인

`examples/scenarios/pass/release-subject.json`에서 커밋, 이미지 다이제스트, SBOM 해시, 클러스터, 네임스페이스, 배포 리소스, 컨테이너, 상태 확인 URL을 확인합니다. `tests/test_p0_p1_hardening.py`는 다음 불일치와 변조 사례를 검증합니다.

- 이미지 다이제스트를 바꾸면 스캔 결과와 승인 증적이 모두 불일치해 실패합니다.
- 보고서를 수정하면 스캔 실행 증명서의 서명 검증이 실패합니다.
- 승인 발급자, 키 ID, 변경 ID, 릴리스 대상, 시각이 하나라도 다르면 통과하지 못합니다.
- SHA-1은 40자, SHA-256은 64자로 된 전체 Git 객체 ID가 정확히 같아야 합니다. 길이와 관계없이 축약값은 거부합니다.
- 승인 이후 위험도, 배포 허용 시간 또는 롤백 계획만 바꿔도 전체 `ChangeRequest` 다이제스트가 달라져 승인 불일치가 발생합니다.
- 스캐너 명령어, 종료 코드, 취약점 DB 갱신 시각, DAST 단일 대상이 정책과 다르면 통과하지 못합니다.

### 5. 배포 실패와 복구

`tests/test_deployment.py`에서 정책 원문 불일치, 오래된 증적 재사용, 롤아웃 실패, 스모크 테스트 실패, 결과 서명 실패 사례를 확인합니다. 서명 가능한 실패 결과는 서명해 보존하며, 결과 서명에 실패하면 서명되지 않은 로컬 복구 기록을 남깁니다.

Kubernetes 변경 후 롤아웃, 상태 확인, 결과 저장이나 서명에 실패하면 배포 직전에 확인한 이미지 다이제스트와 기존 감사 애너테이션을 복원합니다. 배포 허용 시간이 아니거나 결과 서명 키가 없거나 이전 이미지가 불변 다이제스트가 아니면 Kubernetes를 변경하기 전에 차단합니다.

### 6. CI 신뢰 경계 확인

`.gitlab-ci.yml`과 `Jenkinsfile`에서 다음을 확인합니다.

- MR 잡에는 운영 비밀 정보와 변경 승인 증적을 제공하지 않습니다.
- 릴리스 이미지는 한 번만 빌드하고 다이제스트를 재사용합니다.
- DAST는 릴리스 필수 잡입니다.
- 도구와 인프라 이미지는 다이제스트 참조만 허용합니다.
- ITSM 개인키는 CI에 없으며, 게이트 서명 권한과 배포 검증 키도 분리되어 있습니다.

### 7. 판정 결과 내보내기

- GitLab Code Quality JSON을 MR에 게시해 검사 결과를 확인할 수 있습니다.
- SARIF 내보내기 결과는 다른 코드 스캔 UI에서도 사용할 수 있습니다.
- `compare`와 `--shadow-policy`로 정책 변경 영향을 본 뒤 적용합니다.
- Prometheus 형식 내보내기는 PASS, 이슈, 예외, VEX, OSS 인벤토리, 승인 증적 검증 지표를 제공합니다.

## 코드 리뷰 순서

1. `finguard/release.py`: 정확한 릴리스 대상
2. `finguard/attestation.py`, `finguard/approvals.py`: 스캐너와 외부 승인에 대한 신뢰 검증
3. `finguard/gate.py`: 오류 시 차단하는 정책 판정
4. `finguard/evidence_writer.py`, `finguard/evidence_verifier.py`: 증적 생성과 무결성 검증
5. `finguard/deployment.py`: 증적에 결속된 배포와 롤백
6. `.gitlab-ci.yml` 또는 `Jenkinsfile`: 신뢰 경계와 실행 순서
7. `tests/test_p0_p1_hardening.py`, `tests/test_security_regressions.py`: 우회 경로 회귀 테스트

## 동작과 제약 사항

### 스캐너 실행과 정책 판정의 역할 분리

CI는 스캐너 실행을, FinGuard는 정책 판정을 담당하도록 역할을 나눴습니다. 스캐너를 독립 컨테이너에서 병렬로 실행하거나 다른 도구로 교체해도 정책 모델은 유지됩니다. 로컬 피드백 시간을 줄이기 위해 의존성이 없는 내장 스캐너도 제공합니다.

### 스캐너 오류 처리

필수 범주의 결과가 없거나 스캐너 오류가 있으면 실패합니다. “취약점 0건”과 “검사를 완료하지 못한 상태”를 구분합니다.

### 예외 적용 조건

규칙 전체를 끄지 않고 탐지 결과의 지문 하나에만 예외를 적용합니다. 소유자, 독립 승인자, 위험 티켓, 보상 통제, 정책과 서비스 및 환경 범위, 생성일과 만료일을 요구합니다. Critical 등급은 예외로 처리할 수 없으며 기간 연장도 금지했습니다.

### 서명 방식과 권한

로컬 재현에는 HMAC 서명을 사용합니다. 운영 릴리스에서는 ITSM 승인과 최종 증적을 Cosign으로 검증합니다. 배포 러너는 PASS 증적 검증용 공개키와 별도의 배포 결과 서명 권한을 사용하며, PASS 증적을 생성할 권한은 갖지 않습니다.

### 외부 시스템 검증 범위

예제 보고서와 샘플 서비스로 정책 판정을 재현하고, 공개 CI에서 실제 Semgrep, Trivy, OWASP ZAP을 실행합니다. 별도 kind 클러스터와 Cosign을 사용하는 통합 테스트는 배포, 복구와 결과 서명을 검증합니다. 실제 조직의 ITSM, IdP, KMS 및 운영 Kubernetes 환경과의 연동은 검증 범위에 포함하지 않습니다. 구체적인 시나리오는 [통합 테스트 가이드](integration-testing.md)를 참고하세요.
