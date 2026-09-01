# 면접 시연 가이드

## 7분 시연

### 1. 문제를 한 문장으로 정의

“보안 검사를 파이프라인에 추가하는 데 그치지 않고, 검사한 커밋과 승인한 이미지가 실제 배포 대상과 같은지 다시 검증하는 게이트를 만들었습니다.”

추상적인 생산성 향상 주장보다 `ReleaseSubject`, 외부 승인 서명, 단일 빌드 같은 구체적인 결정을 먼저 보여줍니다.

### 2. 정상 변경을 통과시킨다

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

`decision: pass`, 정책 ID, 변경 ID, 검증된 파일 수를 확인합니다. 이어서 `inputs/`, `decision.json`, `summary.md`, `audit.jsonl`, `manifest.json`을 순서대로 보여줍니다. 이를 통해 판정 결과와 원본 입력을 함께 보존하는 이유를 설명할 수 있습니다.

### 3. 위험 변경을 차단한다

```bash
.venv/bin/python -m finguard demo \
  --scenario fail \
  --output "${demo_output}"
```

종료 코드 `2`와 다음 원인을 확인합니다.

- Critical SCA와 High SAST
- 수정 버전이 없는 차단 등급 취약점
- AGPL 금지 라이선스
- 커버리지 부족과 테스트 실패
- 구체성이 부족한 롤백 계획과 필수 승인 역할 누락
- 요청자와 배포자가 같은 직무분리 위반

### 4. “검사한 것”과 “배포할 것”을 연결한다

`examples/scenarios/pass/release-subject.json`에서 커밋, 이미지 다이제스트, SBOM 해시, 클러스터, 네임스페이스, 배포 리소스, 컨테이너, 상태 확인 URL을 보여줍니다. 그런 다음 `tests/test_p0_p1_hardening.py`의 다음 사례를 설명합니다.

- 이미지 다이제스트를 바꾸면 스캔 결과와 승인 증적이 모두 불일치해 실패합니다.
- 보고서를 수정하면 스캔 실행 증명서의 서명 검증이 실패합니다.
- 승인 발급자, 키 ID, 변경 ID, 릴리스 대상, 시각이 하나라도 다르면 통과하지 못합니다.
- SHA-1은 40자, SHA-256은 64자로 된 전체 Git 객체 ID가 정확히 같아야 합니다. 길이와 관계없이 축약값은 거부합니다.
- 승인 이후 위험도, 배포 시간 창구 또는 롤백 계획만 바꿔도 전체 `ChangeRequest` 다이제스트가 달라져 승인 불일치가 발생합니다.
- 스캐너 명령어, 종료 코드, 취약점 DB 갱신 시각, DAST 단일 대상이 정책과 다르면 통과하지 못합니다.

### 5. 배포 실패를 복구한다

`tests/test_deployment.py`에서 정책 원문 불일치, 오래된 증적 재사용, 롤아웃 실패, 스모크 테스트 실패, 결과 서명 실패 사례를 보여줍니다. 실제 배포에 실패한 결과도 서명해 남깁니다.

Kubernetes를 변경한 뒤 발생한 세 가지 실패 상황에서는 배포 직전에 확인한 이미지 다이제스트와 기존 감사 애너테이션을 복원합니다. 배포 시간 창구 밖이거나 결과 서명 키가 없거나 이전 이미지가 불변 다이제스트가 아니면 Kubernetes를 변경하기 전에 차단합니다.

### 6. CI 신뢰 경계를 보여준다

`.gitlab-ci.yml`과 `Jenkinsfile`에서 다음을 짚어줍니다.

- MR 잡에는 운영 비밀과 변경 승인이 없습니다.
- 릴리스 이미지는 한 번만 빌드하고 다이제스트를 재사용합니다.
- DAST는 선택 옵션이 아니라 릴리스 필수 잡입니다.
- 도구와 인프라 이미지는 다이제스트 참조만 허용합니다.
- ITSM 개인키는 CI에 없으며, 게이트 서명 권한과 배포 검증 키도 분리되어 있습니다.

### 7. 개발자와 운영자에게 제공하는 결과를 보여준다

- MR은 GitLab Code Quality JSON으로 피드백을 받습니다.
- SARIF 내보내기 결과는 다른 코드 스캔 UI에서도 사용할 수 있습니다.
- `compare`와 `--shadow-policy`로 정책 변경 영향을 본 뒤 적용합니다.
- Prometheus 형식 내보내기는 PASS, 이슈, 예외, VEX, OSS 인벤토리, 승인 검증 지표를 제공합니다.

## 코드 리뷰 순서

1. `finguard/release.py`: 정확한 릴리스 대상
2. `finguard/attestation.py`, `finguard/approvals.py`: 스캐너와 외부 승인에 대한 신뢰 검증
3. `finguard/gate.py`: 오류 시 차단하는 정책 판정
4. `finguard/evidence.py`: 안전한 증적 게시와 무결성
5. `finguard/deployment.py`: 증적에 결속된 배포와 롤백
6. `.gitlab-ci.yml` 또는 `Jenkinsfile`: 신뢰 경계와 실행 순서
7. `tests/test_p0_p1_hardening.py`, `tests/test_security_regressions.py`: 우회 경로 회귀 테스트

## 예상 질문

### 왜 모든 스캐너를 Python에서 직접 실행하지 않았나

CI는 스캐너 실행을, FinGuard는 정책 판정을 담당하도록 역할을 나눴습니다. 스캐너를 독립 컨테이너에서 병렬로 실행하거나 다른 도구로 교체해도 정책 모델은 유지됩니다. 로컬 피드백 시간을 줄이기 위해 의존성이 없는 내장 스캐너도 제공합니다.

### 스캐너가 보고서를 만들지 못하면 어떻게 되나

필수 범주의 결과가 없거나 스캐너 오류가 있으면 실패합니다. “취약점 0건”과 “검사를 완료하지 못한 상태”를 구분합니다.

### 예외가 필요한 현실적인 상황은 어떻게 처리하나

규칙 전체를 끄지 않고 탐지 결과의 지문 하나에만 예외를 적용합니다. 소유자, 독립 승인자, 위험 티켓, 보상 통제, 정책과 서비스 및 환경 범위, 생성일과 만료일을 요구합니다. Critical 등급은 예외로 처리할 수 없으며 기간 연장도 금지했습니다.

### HMAC이면 운영에 충분한가

아닙니다. HMAC은 로컬 시연을 쉽게 재현하기 위한 방식입니다. 보호 릴리스에서는 ITSM 승인과 최종 증적을 Cosign으로 검증하고, 배포 Runner에는 공개키만 제공합니다.

### 실제 금융권 경험으로 보아도 되나

아닙니다. 이 저장소는 금융 서비스에 필요한 안정성과 감사 통제를 기술 설계로 구현한 포트폴리오입니다. 합성 보고서와 모의 객체를 사용했으며, 실제 조직의 전자 결재, IdP, KMS, Kubernetes를 연동한 실적은 아닙니다.
