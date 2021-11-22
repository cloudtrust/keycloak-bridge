pipeline {
  agent any
  options {
    timestamps()
    timeout(time: 3600, unit: 'SECONDS')
  }
  parameters {
    string(name: 'CREATE_RELEASE', defaultValue: 'false')
    string(name: 'VERSION', defaultValue: '1.0-test')
    string(name: 'REPO_URL', defaultValue: '')
  }
  environment{
    BUILD_PATH="/home/jenkins/gopath/src/github.com/cloudtrust/keycloak-bridge"
    APP="ct-bridge"
  }
  stages {
    stage('Build') {
      agent {
        label 'jenkins-slave-go-ct'
      }
      steps {
        script {
          sh 'printenv'
          def isBranch = ""
          if (!env.CHANGE_ID) {
            isBranch = " || true"
          }
          withCredentials([usernamePassword(credentialsId: 'cloudtrust-cicd-sonarqube', usernameVariable: 'USER', passwordVariable: 'PASS')]) {
            sh """
              set -eo pipefail

              mkdir -p "${BUILD_PATH}"
              cp -r "${WORKSPACE}/." "${BUILD_PATH}/"
              cd "${BUILD_PATH}"

              golint ./... | tee golint.out || true

              go generate ./...
              go mod vendor
              
              ./scripts/build.sh --version "${params.VERSION}" --env "\$(uname -o)-\$(uname -m)"

              go test -coverprofile=coverage.out -json ./... | tee report.json
              go tool cover -func=coverage.out
              bash -c \"go vet ./... > >(cat) 2> >(tee govet.out)\" || true
              gometalinter --vendor --disable=gotype --disable=golint --disable=vet --disable=gocyclo --exclude=/usr/local/go/src --deadline=300s ./... | tee gometalinter.out || true

              go list -json -deps | nancy -no-color || true

              JAVA_TOOL_OPTIONS="" sonar-scanner \
                -Dsonar.host.url=https://sonarqube-cloudtrust-cicd.openshift.west.ch.elca-cloud.com \
                -Dsonar.login="${USER}" \
                -Dsonar.password="${PASS}" \
                -Dsonar.sourceEncoding=UTF-8 \
                -Dsonar.projectKey=keycloak-bridge \
                -Dsonar.projectName=keycloak-bridge \
                -Dsonar.projectVersion="${env.GIT_COMMIT}" \
                -Dsonar.sources=. \
                -Dsonar.exclusions=**/*_test.go,**/vendor/**,**/mock/** \
                -Dsonar.tests=. \
                -Dsonar.test.inclusions=**/*_test.go \
                -Dsonar.test.exclusions=**/vendor/** \
                -Dsonar.go.coverage.reportPaths=./coverage.out \
                -Dsonar.go.tests.reportPaths=./report.json \
                -Dsonar.go.govet.reportPaths=./govet.out \
                -Dsonar.go.golint.reportPaths=./golint.out \
                -Dsonar.go.gometalinter.reportPaths=./gometalinter.out ${isBranch}
            """
          }

          if (params.CREATE_RELEASE == "true"){
            echo "creating release ${VERSION} and uploading it to ${REPO_URL}"
            // upload to repo
            withCredentials([usernamePassword(credentialsId: 'cloudtrust-cicd-artifactory-opaque', usernameVariable: 'USR', passwordVariable: 'PWD')]){
              sh """
                cd ${BUILD_PATH}/bin
                tar -czvf ${APP}-${params.VERSION}.tar.gz ./keycloak_bridge
                curl --fail -k -u"${USR}:${PWD}" -T "${BUILD_PATH}/bin/${APP}-${params.VERSION}.tar.gz" --keepalive-time 2 "${REPO_URL}/${APP}-${params.VERSION}.tar.gz"
              """
            }
            if (!env.TAG_NAME || env.TAG_NAME != params.VERSION) {
              def git_url = "${env.GIT_URL}".replaceFirst("^(http[s]?://www\\.|http[s]?://|www\\.)","")
              withCredentials([usernamePassword(credentialsId: "support-triustid-ch",
                  passwordVariable: 'PWD',
                  usernameVariable: 'USR')]) {
                sh("git config --global user.email 'ci@dev.null'")
                sh("git config --global user.name 'ci'")
                sh("git tag ${VERSION} -m 'CI'")
                sh("git push https://${USR}:${PWD}@${git_url} --tags")
              }
            } else {
              echo "Tag ${env.TAG_NAME} already exists. Skipping."
            }
            echo "release ${VERSION} available at ${REPO_URL}/${APP}-${params.VERSION}.tar.gz"
          }
        }
      }
    }
  }
}
