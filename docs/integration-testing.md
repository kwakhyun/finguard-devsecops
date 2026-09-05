# 실제 릴리스 통합 테스트

`make quality`는 Python 회귀 테스트와 정적 검사를 실행합니다. `make integration-release`는 별도 kind 클러스터와 로컬 레지스트리를 만들고, 실제 CLI와 Cosign으로 배포부터 복구까지 검증합니다. 종료 시 로그 수집, 클러스터 삭제, 레지스트리 삭제를 각각 시도하며 기존 Kubernetes 컨텍스트를 사용하지 않습니다.

## 실행

Python 개발 환경과 실행 중인 Docker 엔진이 필요합니다. 테스트 도구는 공식 릴리스의 SHA-256을 대조한 뒤 지정 디렉터리에만 설치합니다. Linux amd64/arm64와 macOS amd64/arm64를 지원하는 설치 스크립트입니다.

```bash
bash scripts/install_integration_tools.sh /private/tmp/finguard-tools
export PATH="/private/tmp/finguard-tools:$PATH"
make integration-release
```

Linux에서는 `/private/tmp/finguard-tools` 대신 `/tmp/finguard-tools`를 지정합니다. 별도 Docker 컨텍스트를 쓰려면 실행 전에 `DOCKER_CONTEXT`를 지정합니다. 기존 결과를 덮어쓰지 않으므로 재실행 시 `make integration-release BUILD_DIR=build/retry-01`처럼 새 경로를 사용합니다.

고정 도구는 kind 0.33.0, kubectl 1.35.8, Cosign 3.1.3입니다. Kubernetes 노드와 아키텍처별 레지스트리 이미지도 스크립트의 SHA-256으로 고정합니다. 이미지 다운로드 및 임시 클러스터 기동에 네트워크 접근과 여유 메모리, 디스크가 필요합니다.

## 검증하는 동작

| 시나리오 | 검사 내용 |
| --- | --- |
| 정상 배포 | 로컬 레지스트리에 게시한 후보 이미지 다이제스트로 변경하고 실제 HTTP 상태 확인, 결과 서명 검증 |
| HTTP 상태 확인 실패 | `/missing`의 실제 HTTP 404로 실패를 유도하고 이전 이미지와 감사 애너테이션 복원, 실패 결과 서명 검증 |
| 서명 키 장애 | 존재하지 않는 결과 서명 키로 실패를 유도하고 롤백 확인, 최종 결과 게시 금지와 로컬 복구 기록 확인 |
| SIGTERM | 이미지 변경을 관찰한 뒤 실제 CLI 프로세스에 SIGTERM 전송, 복구 및 종료 코드 143과 중단 결과 서명 확인 |
| 같은 출력 경로의 중복 실행 | 첫 배포가 진행 중일 때 두 번째 CLI가 경로 예약 오류로 종료되는지 확인 |
| 결과 변조 | 정상 서명 번들에 대해 변경한 JSON의 암호학적 검증이 실패하는지 확인 |

별도 회귀 테스트는 SIGINT와 `KeyboardInterrupt`, 복구 중 반복 신호, 예약 이후 다른 작성자가 생성한 결과 파일, 게시 직전의 파일 경합, 서명 준비 실패 시 기존 결과 보존도 검사합니다.

## 결과와 신뢰 범위

결과는 `build/integration-release/`에 남습니다. 각 시나리오의 `cli.log`, 증적 번들, `deployment.json`, 서명 번들, `deployment.json.recovery.json`, 공개키, 클러스터 로그를 확인할 수 있습니다. 모든 검사를 통과해야 `integration-summary.json`이 생성됩니다. 개인키와 kubeconfig는 임시 디렉터리에만 보관하고 실행 후 제거합니다.

Kubernetes API, 컨테이너 이미지 전달, HTTP 요청, 운영체제 신호와 Cosign 서명 검증은 실제로 실행합니다. 보안 보고서와 변경 승인 내용은 예제이고, 게이트는 로컬 기준 정책을 사용합니다. 운영 릴리스 정책의 스캐너 신원, ITSM/IdP API, 외부 KMS, 공개 투명성 로그와 상용 보안 서버의 통합을 입증하는 테스트는 아닙니다.

테스트 전용 Cosign 래퍼는 로컬 키로 서명하며 공개 투명성 로그 업로드와 로그 포함 검증만 비활성화합니다. 공개키에 의한 서명 검증과 변조 거부는 유지합니다. 이 래퍼는 임시 PATH에만 추가하고 운영 GitLab/Jenkins 설정에는 적용하지 않습니다.

GitHub Actions의 `Kubernetes release and recovery` 잡은 같은 테스트를 실행하고 `finguard-kubernetes-release` 아티팩트를 보존합니다. 코드가 추가됐다는 사실과 공개 CI가 실제로 성공했다는 사실은 구분해야 하며, 공개 실행 상태는 해당 Actions 실행 결과로 확인합니다.

## 2026-09-05 로컬 실행 결과

macOS arm64의 별도 Colima VM에서 실제 kind 클러스터를 기동해 모든 시나리오를 통과했습니다. [실행 요약 JSON](verification/2026-09-05-release-integration.json)에 도구 버전, 이미지 다이제스트, 종료 코드와 검증 범위를 기록했습니다. 정상 배포는 0, HTTP 실패와 서명 장애는 3, SIGTERM은 143을 반환했습니다. 실패 및 중단 시 이전 이미지와 감사 애너테이션 복원을 확인했고, 정상적으로 게시된 결과는 실제 Cosign으로 검증했습니다. 변조 입력은 거부됐습니다.

같은 작업 트리에서 `make quality`도 통과했습니다. Python 테스트 206개, 커버리지 85.93%, Ruff 및 Mypy 통과입니다. 테스트 클러스터와 레지스트리는 실행 후 제거했습니다. 이 기록은 로컬 실행 결과이며 아직 게시하지 않은 GitHub Actions 변경의 원격 실행 성공을 의미하지 않습니다.


## 후속 구조 개선 검증

같은 날짜의 후속 변경에서는 스냅샷 자원 제한, VEX 처리, 지문 캐시, CI 보고서 재사용과 모듈 책임 분리를 적용했습니다. `make quality`에서 225개 테스트와 86.52% 커버리지를 확인했습니다. 로그 수집, 클러스터 삭제 또는 레지스트리 삭제에 오류를 주입해 나머지 정리가 실행되는지 검사했고, 원래 배포 오류가 정리 오류에 가려지지 않는지도 확인했습니다. 정리만 실패한 경우 통합 테스트 자체가 실패합니다.

후속 변경 시 Docker 소켓 접근이 거부되어 실제 kind 시나리오는 다시 실행하지 않았습니다. 위 실제 클러스터 실행 기록은 후속 리팩터링 이전 결과입니다.
