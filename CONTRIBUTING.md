# Contributing

## 개발 흐름

1. main에서 짧은 작업 브랜치를 만듭니다.
2. 변경에 맞는 테스트를 먼저 추가하거나 수정합니다.
3. `make quality`과 `make scan`을 실행합니다.
4. Pull Request 또는 Merge Request 템플릿에 위험, 검증, 배포, 롤백 정보를 작성합니다.
5. CODEOWNERS 검토를 받은 뒤 보호된 main에 병합합니다.

정책, scanner adapter, 증적, 배포 코드의 변경은 기존 PASS 입력을 실패시키거나 FAIL 입력을 통과시키지 않는지 반드시 확인합니다. 의도적으로 판정을 바꾼 경우 정책 버전을 올리고 변경 이유를 문서화합니다.

## parser 추가

새 도구를 추가할 때는 원본 payload를 그대로 gate에 넘기지 않습니다. `ScanResult`와 `Finding`으로 변환하고 다음 테스트를 포함합니다.

- 정상 리포트와 빈 리포트
- scanner 오류 또는 잘못된 형식
- 심각도 매핑
- 위치와 component 정보
- 같은 이슈의 안정적인 fingerprint
- 입력 파일 SHA-256와 scanner provenance 결속

## 보안

실제 비밀, 내부 registry 주소, 고객 데이터, 운영 cluster 정보를 fixture나 로그에 넣지 않습니다. 취약점은 공개 issue보다 [SECURITY.md](SECURITY.md)의 절차로 제보합니다.
