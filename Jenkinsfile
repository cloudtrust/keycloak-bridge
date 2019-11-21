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
    stage('Init') {
      steps {
        script {
          echo "========================================="
          echo "CREATE_RELEASE=${params.CREATE_RELEASE}"
          echo "VERSION=${params.VERSION}"
          echo "REPOSITORY_URL=${params.REPO_URL}"
          echo "========================================="
          sh 'printenv'
        }
      }
    }
    stage('Build') {
      agent {
        label 'jenkins-slave-go-ct'
      }
      steps {
        script {
          sh """
            set -eo pipefail

            mkdir -p "${BUILD_PATH}"
            cp -r "${WORKSPACE}/." "${BUILD_PATH}/"
            cd "${BUILD_PATH}"

            dep ensure

            ./scripts/build.sh --version "${params.VERSION}" --env "\$(uname -o)-\$(uname -m)"

            go generate ./...

            go test -coverprofile=coverage.out -json ./... | tee report.json
            bash -c \"go vet ./... > >(cat) 2> >(tee govet.out)\" || true
            golint | tee golint.out || true
            gometalinter | tee gometalinter.out || true

            nancy -noColor Gopkg.lock || true

            JAVA_TOOL_OPTIONS="" sonar-scanner \
              -Dsonar.host.url=http://sonarqube:9000 \
              -Dsonar.sourceEncoding=UTF-8 \
              -Dsonar.projectKey=keycloak-bridge \
              -Dsonar.projectName=keycloak-bridge \
              -Dsonar.projectVersion="${params.VERSION}" \
              -Dsonar.sources=. \
              -Dsonar.exclusions=**/*_test.go,**/vendor/**,**/mock/** \
              -Dsonar.tests=. \
              -Dsonar.test.inclusions=**/*_test.go \
              -Dsonar.test.exclusions=**/vendor/** \
              -Dsonar.go.coverage.reportPaths=./coverage.out \
              -Dsonar.go.tests.reportPaths=./report.json \
              -Dsonar.go.govet.reportPaths=./govet.out \
              -Dsonar.go.golint.reportPaths=./golint.out \
              -Dsonar.go.gometalinter.reportPaths=./gometalinter.out

          """

          if (params.CREATE_RELEASE == "true"){
            echo "creating release ${VERSION} and uploading it to ${REPO_URL}"
            // upload to repo
            withCredentials([usernamePassword(credentialsId: 'cloudtrust-cicd-artifactory-opaque', usernameVariable: 'USR', passwordVariable: 'PWD')]){
              sh """
                cd ${BUILD_PATH}/bin
                tar -czvf ${APP}-${params.VERSION}.tar.gz ./keycloak_bridge
                curl -k -u"${USR}:${PWD}" -T "${BUILD_PATH}/bin/${APP}-${params.VERSION}.tar.gz" --keepalive-time 2 "${REPO_URL}/${APP}-${params.VERSION}.tar.gz"
              """
            }
            def git_url = "${env.GIT_URL}".replaceFirst("^(http[s]?://www\\.|http[s]?://|www\\.)","")
            withCredentials([usernamePassword(credentialsId: "3d6daa6f-8eea-43d0-b69e-0616258d5b1b",
                passwordVariable: 'PWD',
                usernameVariable: 'USR')]) {
              sh("git config --global user.email 'ci@dev.null'")
              sh("git config --global user.name 'ci'")
              sh("git tag ${VERSION} -m 'CI'")
              sh("git push https://${USR}:${PWD}@${git_url} --tags")
            }
            echo "release ${VERSION} available at ${REPO_URL}/${APP}-${params.VERSION}.tar.gz"
          }
        }
      }
    }
  }
}
