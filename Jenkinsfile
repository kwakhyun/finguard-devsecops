pipeline {
    agent { label 'onprem-linux' }

    options {
        timestamps()
        disableConcurrentBuilds()
        buildDiscarder(logRotator(numToKeepStr: '30', artifactNumToKeepStr: '30'))
    }

    parameters {
        string(name: 'CHANGE_MANIFEST', defaultValue: '/srv/finguard/approved/change.toml', description: 'ITSM이 게시한 승인 CB/SR 파일')
        string(name: 'APPROVAL_ATTESTATION', defaultValue: '/srv/finguard/approved/approval-attestation.json', description: 'ITSM이 발급한 릴리스 승인 증적')
        string(name: 'APPROVAL_ATTESTATION_BUNDLE', defaultValue: '/srv/finguard/approved/approval-attestation.sigstore.json', description: 'ITSM Cosign 서명 번들')
        string(name: 'VEX_ATTESTATION', defaultValue: '', description: '선택적인 보안팀 VEX 승인 증적')
        string(name: 'VEX_ATTESTATION_BUNDLE', defaultValue: '', description: '선택적인 VEX Cosign 번들')
        string(name: 'REGISTRY_IMAGE', defaultValue: '', description: '내부 registry/repository')
        string(name: 'RELEASE_SERVICE', defaultValue: 'customer-credit-api', description: '릴리스 서비스 DNS 이름')
        string(name: 'ZAP_IMAGE', defaultValue: '', description: '내부 ZAP 이미지 @sha256 참조')
        string(name: 'SEMGREP_VERSION', defaultValue: '', description: '관리되는 Semgrep toolcache 버전')
        string(name: 'TRIVY_VERSION', defaultValue: '', description: '관리되는 Trivy toolcache 버전')
        string(name: 'ZAP_VERSION', defaultValue: '', description: 'ZAP_IMAGE에 포함된 ZAP 버전')
        booleanParam(name: 'DEPLOY_PRODUCTION', defaultValue: false, description: '승인 증적으로 운영 배포')
    }

    environment {
        REPORT_DIR = 'build/reports'
        ATTESTATION_DIR = 'build/attestations'
        EVIDENCE_DIR = "build/evidence/${BUILD_NUMBER}"
        PYTHON = '.venv/bin/python'
        RUFF_VERSION = '0.16.5'
        PYTEST_VERSION = '8.4.2'
        COVERAGE_VERSION = '7.16.0'
        RELEASE_POLICY_ID = 'FIN-SW-DEVSECOPS-RELEASE'
        RELEASE_POLICY_VERSION = '5.1.0'
        RELEASE_POLICY_SHA256 = '981e7715ce40a347212511a3fba523dc9e15b7af5774d65f636676cedce1d6e3'
        TRIVY_DB_METADATA_PATH = '/var/lib/trivy/db/metadata.json'
    }

    stages {
        stage('Prepare') {
            steps {
                // Agents may reuse workspaces. Remove stale reports,
                // attestations, virtualenv packages, and untracked source.
                deleteDir()
                checkout scm
                sh 'python3 -m venv .venv'
                sh '.venv/bin/pip install -r requirements-dev.lock'
                sh '.venv/bin/pip install --no-deps -e .'
                sh 'mkdir -p "$REPORT_DIR" "$ATTESTATION_DIR"'
            }
        }

        stage('Source Quality and SAST') {
            parallel {
                stage('Lint') {
                    steps {
                        sh 'test "$(.venv/bin/python -c \'import importlib.metadata as m; print(m.version("ruff"))\')" = "$RUFF_VERSION"'
                        sh 'date -u +%Y-%m-%dT%H:%M:%SZ > build/ruff.started; .venv/bin/ruff check . --exit-zero --output-format=json --output-file="$REPORT_DIR/ruff.json"; date -u +%Y-%m-%dT%H:%M:%SZ > build/ruff.finished'
                        script {
                            if (env.BRANCH_NAME == 'main') {
                                withCredentials([string(credentialsId: 'finguard-scan-attestation-key', variable: 'FINGUARD_SCAN_ATTESTATION_KEY')]) {
                                    sh '$PYTHON -m finguard attest-report --report "$REPORT_DIR/ruff.json" --output "$ATTESTATION_DIR/ruff.json" --scanner ruff --category lint --scanner-version "$RUFF_VERSION" --scanner-uri "toolcache://ruff/$RUFF_VERSION" --source-commit "$GIT_COMMIT" --ruleset pyproject.toml --command "ruff check" --ci-job-id "$BUILD_TAG:lint" --runner-id jenkins:onprem-release --exit-code 0 --complete --started-at "$(cat build/ruff.started)" --finished-at "$(cat build/ruff.finished)" --signing-key-env FINGUARD_SCAN_ATTESTATION_KEY --key-id onprem-scan-attestor-v1'
                                }
                            }
                        }
                        sh '.venv/bin/ruff format --check .'
                        sh '.venv/bin/mypy finguard sample_service'
                    }
                }
                stage('Test') {
                    steps {
                        sh 'test "$(.venv/bin/python -c \'import importlib.metadata as m; print(m.version("pytest"))\')" = "$PYTEST_VERSION"; test "$(.venv/bin/python -c \'import importlib.metadata as m; print(m.version("coverage"))\')" = "$COVERAGE_VERSION"'
                        sh 'date -u +%Y-%m-%dT%H:%M:%SZ > build/test.started; pytest_status=0; $PYTHON -m pytest --junitxml="$REPORT_DIR/junit.xml" --cov=finguard --cov-report=xml:"$REPORT_DIR/coverage.xml" || pytest_status=$?; date -u +%Y-%m-%dT%H:%M:%SZ > build/test.finished; printf "%s" "$pytest_status" > build/test.status'
                        script {
                            if (env.BRANCH_NAME == 'main') {
                                withCredentials([string(credentialsId: 'finguard-scan-attestation-key', variable: 'FINGUARD_SCAN_ATTESTATION_KEY')]) {
                                    sh 'test_status=$(cat build/test.status); completion=--incomplete; test "$test_status" -le 1 && completion=--complete; $PYTHON -m finguard attest-report --report "$REPORT_DIR/junit.xml" --output "$ATTESTATION_DIR/junit.json" --scanner junit --category test --scanner-version "$PYTEST_VERSION" --scanner-uri "toolcache://pytest/$PYTEST_VERSION" --source-commit "$GIT_COMMIT" --ruleset pyproject.toml --command "pytest junit" --ci-job-id "$BUILD_TAG:test" --runner-id jenkins:onprem-release --exit-code "$test_status" "$completion" --started-at "$(cat build/test.started)" --finished-at "$(cat build/test.finished)" --signing-key-env FINGUARD_SCAN_ATTESTATION_KEY --key-id onprem-scan-attestor-v1; $PYTHON -m finguard attest-report --report "$REPORT_DIR/coverage.xml" --output "$ATTESTATION_DIR/coverage.json" --scanner coverage.py --category test --scanner-version "$COVERAGE_VERSION" --scanner-uri "toolcache://coverage/$COVERAGE_VERSION" --source-commit "$GIT_COMMIT" --ruleset pyproject.toml --command "pytest coverage" --ci-job-id "$BUILD_TAG:test" --runner-id jenkins:onprem-release --exit-code "$test_status" "$completion" --started-at "$(cat build/test.started)" --finished-at "$(cat build/test.finished)" --signing-key-env FINGUARD_SCAN_ATTESTATION_KEY --key-id onprem-scan-attestor-v1'
                                }
                            }
                        }
                        sh 'test "$(cat build/test.status)" -le 1'
                    }
                }
                stage('SAST') {
                    steps {
                        sh 'test -n "${SEMGREP_VERSION}"'
                        sh 'test "$(semgrep --version | head -n 1)" = "$SEMGREP_VERSION"'
                        sh 'date -u +%Y-%m-%dT%H:%M:%SZ > build/semgrep.started; semgrep scan --config .semgrep/secure-coding.yml --json --output "$REPORT_DIR/semgrep.json" .; date -u +%Y-%m-%dT%H:%M:%SZ > build/semgrep.finished'
                        script {
                            if (env.BRANCH_NAME == 'main') {
                                withCredentials([string(credentialsId: 'finguard-scan-attestation-key', variable: 'FINGUARD_SCAN_ATTESTATION_KEY')]) {
                                    sh '$PYTHON -m finguard attest-report --report "$REPORT_DIR/semgrep.json" --output "$ATTESTATION_DIR/semgrep.json" --scanner semgrep --category sast --scanner-version "$SEMGREP_VERSION" --scanner-uri "toolcache://semgrep/$SEMGREP_VERSION" --source-commit "$GIT_COMMIT" --ruleset .semgrep/secure-coding.yml --command "semgrep scan" --ci-job-id "$BUILD_TAG:sast" --runner-id jenkins:onprem-release --exit-code 0 --complete --started-at "$(cat build/semgrep.started)" --finished-at "$(cat build/semgrep.finished)" --signing-key-env FINGUARD_SCAN_ATTESTATION_KEY --key-id onprem-scan-attestor-v1'
                                }
                            }
                        }
                    }
                }
            }
        }

        stage('Merge Request SCA') {
            when { not { branch 'main' } }
            steps {
                sh 'test -n "${TRIVY_VERSION}"'
                sh 'trivy --config config/trivy.yaml fs --scanners vuln,misconfig,secret,license --license-full --format json --output "$REPORT_DIR/trivy.json" .'
                sh 'trivy --config config/trivy.yaml fs --format cyclonedx --output "$REPORT_DIR/sbom.cdx.json" .'
            }
        }

        stage('Build Candidate Once') {
            when { branch 'main' }
            steps {
                sh 'test -n "${REGISTRY_IMAGE}"'
                sh 'mkdir -p build'
                sh 'podman build --pull=never --tag "${REGISTRY_IMAGE}:${GIT_COMMIT}" .'
                sh 'podman push --digestfile build/image.digest "${REGISTRY_IMAGE}:${GIT_COMMIT}"'
                script {
                    env.IMAGE_DIGEST = readFile('build/image.digest').trim()
                    env.IMMUTABLE_IMAGE_REF = "${params.REGISTRY_IMAGE}@${env.IMAGE_DIGEST}"
                }
            }
        }

        stage('Release SCA') {
            when { branch 'main' }
            steps {
                sh 'test -n "${TRIVY_VERSION}"'
                sh 'test "$(trivy --version | sed -n \'s/^Version:[[:space:]]*//p\' | head -n 1)" = "$TRIVY_VERSION"'
                sh 'date -u +%Y-%m-%dT%H:%M:%SZ > build/trivy.started; trivy --config config/trivy.yaml image --scanners vuln,misconfig,secret,license --license-full --format json --output "$REPORT_DIR/trivy.json" "$IMMUTABLE_IMAGE_REF"; date -u +%Y-%m-%dT%H:%M:%SZ > build/trivy.finished'
                sh 'date -u +%Y-%m-%dT%H:%M:%SZ > build/sbom.started; trivy --config config/trivy.yaml image --format cyclonedx --output "$REPORT_DIR/sbom.cdx.json" "$IMMUTABLE_IMAGE_REF"; date -u +%Y-%m-%dT%H:%M:%SZ > build/sbom.finished'
                sh 'test -f "$TRIVY_DB_METADATA_PATH"'
                withCredentials([string(credentialsId: 'finguard-scan-attestation-key', variable: 'FINGUARD_SCAN_ATTESTATION_KEY')]) {
                    sh '$PYTHON -m finguard attest-report --report "$REPORT_DIR/trivy.json" --output "$ATTESTATION_DIR/trivy.json" --scanner trivy --category sca --scanner-version "$TRIVY_VERSION" --scanner-uri "toolcache://trivy/$TRIVY_VERSION" --source-commit "$GIT_COMMIT" --image-digest "$IMAGE_DIGEST" --ruleset config/trivy.yaml --database "$TRIVY_DB_METADATA_PATH" --command "trivy image security" --ci-job-id "$BUILD_TAG:sca" --runner-id jenkins:onprem-release --exit-code 0 --complete --started-at "$(cat build/trivy.started)" --finished-at "$(cat build/trivy.finished)" --signing-key-env FINGUARD_SCAN_ATTESTATION_KEY --key-id onprem-scan-attestor-v1'
                    sh '$PYTHON -m finguard attest-report --report "$REPORT_DIR/sbom.cdx.json" --output "$ATTESTATION_DIR/cyclonedx.json" --scanner cyclonedx --category sca --scanner-version "$TRIVY_VERSION" --scanner-uri "toolcache://trivy/$TRIVY_VERSION" --source-commit "$GIT_COMMIT" --image-digest "$IMAGE_DIGEST" --ruleset config/trivy.yaml --database "$TRIVY_DB_METADATA_PATH" --command "trivy image cyclonedx" --ci-job-id "$BUILD_TAG:sca" --runner-id jenkins:onprem-release --exit-code 0 --complete --started-at "$(cat build/sbom.started)" --finished-at "$(cat build/sbom.finished)" --signing-key-env FINGUARD_SCAN_ATTESTATION_KEY --key-id onprem-scan-attestor-v1'
                }
            }
        }

        stage('Release DAST') {
            when { branch 'main' }
            steps {
                sh '$PYTHON -m finguard validate-images "${ZAP_IMAGE}"'
                sh 'test -n "${ZAP_VERSION}"'
                withCredentials([file(credentialsId: 'finguard-tool-image-cosign-public-key', variable: 'FINGUARD_TOOL_IMAGE_COSIGN_PUBLIC_KEY')]) {
                    sh 'cosign verify --key "$FINGUARD_TOOL_IMAGE_COSIGN_PUBLIC_KEY" "${ZAP_IMAGE}"'
                }
                sh 'cp config/zap-rules.conf "$REPORT_DIR/zap-rules.conf"'
                sh 'podman network create "finguard-${BUILD_NUMBER}"'
                sh 'podman run --detach --name "finguard-target-${BUILD_NUMBER}" --network "finguard-${BUILD_NUMBER}" --pull=never "$IMMUTABLE_IMAGE_REF"'
                sh 'for attempt in $(seq 1 30); do podman exec "finguard-target-${BUILD_NUMBER}" python -m sample_service.healthcheck && break; sleep 1; done'
                sh 'podman exec "finguard-target-${BUILD_NUMBER}" python -m sample_service.healthcheck'
                sh 'zap_target="http://finguard-target-${BUILD_NUMBER}:8080/"; date -u +%Y-%m-%dT%H:%M:%SZ > build/zap.started; zap_status=0; podman run --rm --network "finguard-${BUILD_NUMBER}" --volume "$WORKSPACE/$REPORT_DIR:/zap/wrk:rw" --pull=never "${ZAP_IMAGE}" zap-baseline.py -t "$zap_target" -c zap-rules.conf -J zap.json || zap_status=$?; date -u +%Y-%m-%dT%H:%M:%SZ > build/zap.finished; printf "%s" "$zap_status" > build/zap.status'
                withCredentials([string(credentialsId: 'finguard-scan-attestation-key', variable: 'FINGUARD_SCAN_ATTESTATION_KEY')]) {
                    sh 'zap_status=$(cat build/zap.status); completion=--incomplete; test "$zap_status" -le 2 && completion=--complete; $PYTHON -m finguard attest-report --report "$REPORT_DIR/zap.json" --output "$ATTESTATION_DIR/zap.json" --scanner owasp-zap --category dast --scanner-version "$ZAP_VERSION" --scanner-uri "${ZAP_IMAGE}" --source-commit "$GIT_COMMIT" --image-digest "$IMAGE_DIGEST" --ruleset config/zap-rules.conf --command "zap-baseline.py -c zap-rules.conf" --ci-job-id "$BUILD_TAG:dast" --runner-id jenkins:onprem-release --exit-code "$zap_status" "$completion" --target-uri "http://finguard-target-${BUILD_NUMBER}:8080/" --started-at "$(cat build/zap.started)" --finished-at "$(cat build/zap.finished)" --signing-key-env FINGUARD_SCAN_ATTESTATION_KEY --key-id onprem-scan-attestor-v1; test "$zap_status" -le 2'
                }
            }
            post {
                always {
                    sh 'podman rm --force "finguard-target-${BUILD_NUMBER}" 2>/dev/null || true'
                    sh 'podman network rm "finguard-${BUILD_NUMBER}" 2>/dev/null || true'
                }
            }
        }

        stage('Merge Request Gate') {
            when { not { branch 'main' } }
            steps {
                sh '$PYTHON -m finguard gate --policy policies/merge-request.toml --reports "$REPORT_DIR" --expected-commit "$GIT_COMMIT" --output "$EVIDENCE_DIR"'
            }
        }

        stage('Release Subject') {
            when { branch 'main' }
            steps {
                sh '$PYTHON -m finguard subject --service "${RELEASE_SERVICE}" --repository "${GIT_URL}" --commit "$GIT_COMMIT" --image "$IMMUTABLE_IMAGE_REF" --sbom "$REPORT_DIR/sbom.cdx.json" --environment production --cluster "$KUBE_CONTEXT" --namespace "$KUBE_NAMESPACE" --deployment "$KUBE_DEPLOYMENT" --container "$KUBE_CONTAINER" --healthcheck-url "$RELEASE_HEALTHCHECK_URL" --builder-id jenkins:onprem-release --output build/release-subject.json'
            }
        }

        stage('Approved Release Gate') {
            when { branch 'main' }
            steps {
                input message: '생성된 Release Subject를 ITSM에서 승인했습니까?', ok: '증적 생성'
                withCredentials([
                    string(credentialsId: 'finguard-scan-attestation-key', variable: 'FINGUARD_SCAN_ATTESTATION_KEY'),
                    file(credentialsId: 'finguard-itsm-cosign-public-key', variable: 'FINGUARD_APPROVAL_COSIGN_PUBLIC_KEY'),
                    file(credentialsId: 'finguard-vex-cosign-public-key', variable: 'FINGUARD_VEX_COSIGN_PUBLIC_KEY'),
                    string(credentialsId: 'finguard-evidence-cosign-signing-key', variable: 'FINGUARD_EVIDENCE_COSIGN_SIGNING_KEY'),
                    file(credentialsId: 'finguard-evidence-cosign-public-key', variable: 'FINGUARD_EVIDENCE_COSIGN_PUBLIC_KEY')
                ]) {
                    sh 'test -f "${CHANGE_MANIFEST}"'
                    sh 'test -f "${APPROVAL_ATTESTATION}"'
                    sh 'test -f "${APPROVAL_ATTESTATION_BUNDLE}"'
                    sh 'command -v cosign >/dev/null'
                    sh '''
                        set -- "$PYTHON" -m finguard gate --policy policies/financial-release.toml --reports "$REPORT_DIR" --attestations "$ATTESTATION_DIR" --attestation-key-env FINGUARD_SCAN_ATTESTATION_KEY --change "$CHANGE_MANIFEST" --approval-attestation "$APPROVAL_ATTESTATION" --approval-cosign-bundle "$APPROVAL_ATTESTATION_BUNDLE" --approval-cosign-verification-key "$FINGUARD_APPROVAL_COSIGN_PUBLIC_KEY" --approval-cosign-key-id onprem-itsm-cosign-v1 --subject build/release-subject.json --expected-commit "$GIT_COMMIT" --output "$EVIDENCE_DIR" --cosign-signing-key "$FINGUARD_EVIDENCE_COSIGN_SIGNING_KEY"
                        if [ -n "$VEX_ATTESTATION" ]; then
                            test -f "$VEX_ATTESTATION"
                            test -f "$VEX_ATTESTATION_BUNDLE"
                            set -- "$@" --vex-attestation "$VEX_ATTESTATION" --vex-cosign-bundle "$VEX_ATTESTATION_BUNDLE" --vex-cosign-verification-key "$FINGUARD_VEX_COSIGN_PUBLIC_KEY" --vex-cosign-key-id onprem-vex-cosign-v1
                        fi
                        "$@"
                    '''
                    sh '$PYTHON -m finguard verify --evidence "$EVIDENCE_DIR" --cosign-verification-key "$FINGUARD_EVIDENCE_COSIGN_PUBLIC_KEY"'
                }
            }
        }

        stage('Deploy Production') {
            when {
                allOf {
                    branch 'main'
                    expression { params.DEPLOY_PRODUCTION }
                }
            }
            steps {
                input message: '승인된 digest를 운영에 배포합니까?', ok: '배포'
                withCredentials([
                    file(credentialsId: 'finguard-evidence-cosign-public-key', variable: 'FINGUARD_EVIDENCE_COSIGN_PUBLIC_KEY'),
                    string(credentialsId: 'finguard-deployment-cosign-signing-key', variable: 'FINGUARD_DEPLOYMENT_COSIGN_SIGNING_KEY')
                ]) {
                    sh 'command -v cosign >/dev/null; command -v kubectl >/dev/null'
                    sh '$PYTHON -m finguard deploy --cluster "$KUBE_CONTEXT" --namespace "$KUBE_NAMESPACE" --deployment "$KUBE_DEPLOYMENT" --container "$KUBE_CONTAINER" --image "$IMMUTABLE_IMAGE_REF" --expected-policy-id "$RELEASE_POLICY_ID" --expected-policy-version "$RELEASE_POLICY_VERSION" --expected-policy-sha256 "$RELEASE_POLICY_SHA256" --evidence "$EVIDENCE_DIR" --output "build/deployment-result-${BUILD_NUMBER}.json" --cosign-verification-key "$FINGUARD_EVIDENCE_COSIGN_PUBLIC_KEY" --require-signature --result-cosign-signing-key "$FINGUARD_DEPLOYMENT_COSIGN_SIGNING_KEY" --result-cosign-bundle "build/deployment-result-${BUILD_NUMBER}.sigstore.json"'
                }
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'build/**/*.json,build/**/*.xml,build/**/*.md,build/**/*.toml,build/**/*.sig', allowEmptyArchive: true, fingerprint: true
            junit testResults: 'build/reports/junit.xml', allowEmptyResults: true
        }
    }
}
