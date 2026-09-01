# 면접 시연 가이드

## 7분 시연

### 1. 문제를 한 문장으로 정의

“scanner를 붙이는 것에서 끝나지 않고, 검사한 커밋과 승인한 이미지, 실제 배포 대상이 같다는 것을 재검증할 수 있는 gate를 만들었습니다.”

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

`decision: pass`, 정책 ID, 변경 ID, 검증된 파일 수를 확인합니다. `inputs/`, `decision.json`, `summary.md`, `audit.jsonl`, `manifest.json`을 순서대로 보여주면 판정과 원본을 함께 보존하는 이유가 잘 드러납니다.

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
- 불충분한 롤백 계획과 승인 역할
- 요청자와 배포자가 같은 직무분리 위반

### 4. “검사한 것”과 “배포할 것”을 연결한다

`examples/scenarios/pass/release-subject.json`에서 commit, image digest, SBOM hash, cluster, namespace, deployment, container, health URL을 보여줍니다. 그런 다음 `tests/test_p0_p1_hardening.py`의 다음 사례를 설명합니다.

- 이미지 digest를 바꾸면 scan과 승인이 모두 mismatch로 실패합니다.
- 리포트를 수정하면 attestation 서명 검증이 실패합니다.
- 승인 issuer, key ID, 변경 ID, subject, 시각이 하나라도 다르면 통과하지 못합니다.
- 40자 SHA-1 또는 64자 SHA-256 전체 Git object ID가 정확히 같아야 하며 짧은 prefix는 길이와 관계없이 거부합니다.
- 승인 이후 위험도, 창구 또는 롤백 계획만 바꾸어도 전체 `ChangeRequest` digest가 달라져 승인 mismatch가 발생합니다.
- scanner command, 종료 코드, DB 갱신 시각, DAST 단일 target이 정책과 다르면 통과하지 못합니다.

### 5. 배포 실패를 복구한다

`tests/test_deployment.py`의 정책 원문 불일치, 오래된 증적 재사용, rollout 실패, smoke test 실패, 결과 서명 실패 사례를 보여줍니다. 실패한 실배포 결과도 서명하며, mutation 이후의 세 실패는 배포 직전에 읽은 정확한 이전 이미지 digest와 기존 감사 annotation을 복원합니다. 배포 창구 밖이거나 결과 서명 키가 없거나 이전 이미지가 불변 digest가 아니면 mutation 전에 차단합니다.

### 6. CI 신뢰 경계를 보여준다

`.gitlab-ci.yml`과 `Jenkinsfile`에서 다음을 짚어줍니다.

- MR job에는 운영 비밀과 변경 승인이 없습니다.
- 릴리스 이미지는 한 번만 빌드하고 digest를 재사용합니다.
- DAST는 선택 flag가 아니라 릴리스 필수 job입니다.
- 도구와 인프라 이미지는 digest 참조만 허용합니다.
- ITSM 개인키는 CI에 없고, gate signing 권한과 deploy verification 키도 나누어져 있습니다.

### 7. 개발자와 운영자의 인터페이스를 마무리로 보여준다

- MR은 GitLab Code Quality JSON으로 피드백을 받습니다.
- SARIF export는 다른 코드 스캔 UI에 재사용할 수 있습니다.
- `compare`와 `--shadow-policy`로 정책 변경 영향을 본 뒤 적용합니다.
- Prometheus export는 PASS, 이슈, 예외, VEX, OSS inventory, 승인 검증 지표를 제공합니다.

## 코드 리뷰 순서

1. `finguard/release.py`: 정확한 릴리스 대상
2. `finguard/attestation.py`, `finguard/approvals.py`: scanner와 외부 승인 신뢰
3. `finguard/gate.py`: fail-closed 정책 판정
4. `finguard/evidence.py`: 안전한 증적 게시와 무결성
5. `finguard/deployment.py`: 증적 결합 배포와 rollback
6. `.gitlab-ci.yml` 또는 `Jenkinsfile`: 신뢰 경계와 실행 순서
7. `tests/test_p0_p1_hardening.py`, `tests/test_security_regressions.py`: 우회 경로 회귀 테스트

## 예상 질문

### 왜 scanner를 Python에서 모두 실행하지 않았나

CI가 실행 책임을 갖고 FinGuard는 판정 책임을 갖게 나눈습니다. scanner를 독립 컨테이너에서 병렬로 실행하고 교체해도 정책 모델은 유지됩니다. 로컬 반복 주기만 줄이기 위해 의존성 없는 내장 scanner를 제공합니다.

### scanner가 리포트를 만들지 못하면 어떻게 되나

필수 category가 없거나 scanner 오류가 있으면 실패합니다. “취약점 0건”과 “검사하지 못함”을 구분합니다.

### 예외가 필요한 현실적인 상황은 어떻게 처리하나

규칙 전체를 끄지 않고 fingerprint 하나에만 적용합니다. 소유자와 독립 승인자, 위험 ticket, 보상 통제, 정책과 서비스 및 환경 범위, 생성일과 만료일을 요구합니다. Critical은 예외처리할 수 없고 연장도 금지했습니다.

### HMAC이면 운영에 충분한가

아닙니다. HMAC은 시연 재현성을 위한 호환 경로입니다. 보호 릴리스는 ITSM 승인과 최종 증적을 Cosign으로 검증하고, 배포 Runner에는 공개키만 제공합니다.

### 실제 금융권 경험으로 보아도 되나

아닙니다. 이 저장소는 금융 서비스의 안정성과 감사 통제를 기술 설계로 풀어낸 포트폴리오입니다. 합성 리포트와 mock을 사용했으며 실제 조직의 전자 결재, IdP, KMS, Kubernetes를 연동한 실적은 아닙니다.
