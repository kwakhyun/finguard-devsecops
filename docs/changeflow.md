# Git과 CB/SR ChangeFlow

## 전체 흐름

```text
작업 브랜치
  -> Merge Request 경량 게이트
  -> CODEOWNERS 리뷰
  -> 보호 main 병합
  -> 이미지 단일 빌드와 digest 확정
  -> 아티팩트 SCA, SBOM, DAST
  -> ReleaseSubject 생성
  -> ITSM에서 보안과 릴리스 승인
  -> ITSM Cosign 승인 증적 발급
  -> 보호 릴리스 게이트와 증적 서명
  -> 수동 운영 배포
  -> rollout, smoke test, 필요 시 자동 rollback
  -> 결과와 증적 보존
```

작업 브랜치는 짧게 유지하고 main으로 직접 push하지 않습니다. `policies/`, `.semgrep/`, `finguard/gate.py`, 서명 및 배포 코드, CI 파일은 품질 담당자와 보안 담당자의 공동 리뷰 대상입니다.

## MR과 릴리스 경계

MR pipeline은 소스 품질, SAST, filesystem SCA와 SBOM만 실행합니다. 운영 변경 파일, ITSM 증적, 서명 키, Kubernetes 자격 증명은 제공하지 않습니다. 대신 GitLab Code Quality 리포트를 MR에 게시해 수정 주기를 짧게 만듭니다.

보호 main pipeline은 신뢰할 수 있는 Runner에서 동작합니다. 이미지를 한 번 빌드한 뒤 같은 digest를 검사하고, 그 결과로 만든 `ReleaseSubject`를 외부 변경관리 시스템에서 승인합니다.

## CB와 SR

- CB는 애플리케이션, 설정, 인프라 변경처럼 배포 가능한 변경 묶음에 사용합니다.
- SR은 표준화된 운영 요청이나 사전 정의된 서비스 작업에 사용합니다.

예제 정책은 두 유형에 같은 최소 통제를 적용합니다. 실제 조직에서 위험도와 작업 유형별 승인 수가 다르면 정책을 분리해야 합니다.

## 입력 계약

`change.toml`은 다음을 포함합니다.

- 변경 ID, 유형, 서비스, 환경, commit SHA
- 요청자, 배포자, 위험도, 롤백 계획, 배포 시간 창구
- 최종 빌드 대상을 그대로 복사한 `[release]`
- 보안과 릴리스 역할의 독립 승인 목록과 시각

이 파일만으로는 운영 릴리스를 승인하지 않습니다. ITSM adapter가 승인 목록을 포함한 전체 `ChangeRequest`의 canonical SHA-256와 `ReleaseSubject` hash를 approval attestation에 넣고 Cosign으로 서명해야 합니다. CI는 발급자, key ID, 서명, 전체 변경 요청 hash, 발급 시각을 다시 검증합니다. 승인 이후 롤백 계획, 배포 창구, 위험도 또는 역할을 바꾸면 기존 승인 증적은 더 이상 일치하지 않습니다.

## 직무분리

기본 정책은 다음 충돌을 허용하지 않습니다.

- 요청자와 배포자가 같은 경우
- 승인자가 요청자나 배포자와 같은 경우
- 서로 다른 계정의 필수 승인 두 건이 없는 경우
- 보안 또는 릴리스 관리자 역할이 누락된 경우
- 승인이 최종 `built_at`보다 이른 경우

현재 포트폴리오는 승인자 identity를 전자 결재가 서명한 문자열로 검증합니다. 실제 도입은 ITSM이 IdP 그룹과 재직 상태를 확인한 후에만 서명하게 해야 합니다.

## 긴급 변경과 정책 변경

긴급 변경도 보안 검사를 생략하지 않습니다. 시간이 긴 DAST 범위를 조정해야 한다면 별도 emergency policy, 만료 시각이 있는 예외, 사후 검토 기한을 함께 사용합니다. 기본 정책에는 우회 flag를 두지 않았습니다.

정책 변경은 버전을 올리고 `--shadow-policy`로 기존 판정과 비교합니다. PASS가 FAIL로 바뀌는 서비스와 새로 활성화되는 finding을 파악한 뒤 단계적으로 적용합니다. 보호 파이프라인의 정책 ID, 버전, SHA-256 허용값도 함께 갱신해야 하며 셋 중 하나라도 다르면 배포가 차단됩니다. 릴리스 정책은 증적 생성 후 4시간 안에만 배포를 허용합니다.
