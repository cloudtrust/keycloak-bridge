FROM r-docker-registry-access-redhat-com.artifactory.svc.elca.ch/ubi8-minimal:8.10-1777452756@sha256:8244f6075f3fdc246dc5f1ed0c20a487469070840e34e8b9125f8254baa6849f AS build-env

LABEL name="ephemeral/ct-keycloak-bridge" releaseName="ct-keycloak-bridge" repository="prj-cloudtrust-docker" releaseRepository="prj-cloudtrust-docker"

RUN curl -s https://artifactory.svc.elca.ch:443/artifactory/prj_cloudtrust_generic_public/cert/ELCACorporateRootCA.crt -o /etc/pki/ca-trust/source/anchors/elca-local-root.pem && \
    curl -s https://artifactory.svc.elca.ch:443/artifactory/prj_cloudtrust_generic_public/cert/ELCACorporateRootCA-2025.pem -o /etc/pki/ca-trust/source/anchors/elca-local-root-2025.pem && \
    curl -s https://artifactory.svc.elca.ch:443/artifactory/prj_cloudtrust_generic_public/cert/root.pem -o /etc/pki/ca-trust/source/anchors/elca-cloud-root.pem && \
    curl -s https://artifactory.svc.elca.ch:443/artifactory/prj_cloudtrust_generic_public/cert/west-ge.pem -o /etc/pki/ca-trust/source/anchors/elca-west-ge-2019.pem && \
    curl -s https://artifactory.svc.elca.ch:443/artifactory/prj_cloudtrust_generic_public/cert/west-gl.pem -o /etc/pki/ca-trust/source/anchors/elca-west-gl-2019.pem && \
    curl -s https://artifactory.svc.elca.ch:443/artifactory/prj_cloudtrust_generic_public/cert/west-ls.pem -o /etc/pki/ca-trust/source/anchors/elca-west-ls-2020.pem && \
    curl -s https://artifactory.svc.elca.ch:443/artifactory/prj_cloudtrust_generic_public/cert/west-ge-2025.pem -o /etc/pki/ca-trust/source/anchors/elca-west-ge-2025.pem && \
    curl -s https://artifactory.svc.elca.ch:443/artifactory/prj_cloudtrust_generic_public/cert/west-gl-2025.pem -o /etc/pki/ca-trust/source/anchors/elca-west-gl-2025.pem && \
    curl -s https://artifactory.svc.elca.ch:443/artifactory/prj_cloudtrust_generic_public/cert/west-ls-2025.pem -o /etc/pki/ca-trust/source/anchors/elca-west-ls-2025.pem && \
    update-ca-trust

COPY ./bin/keycloak_bridge /usr/bin/keycloak_bridge
RUN chmod +x /usr/bin/keycloak_bridge

FROM r-docker-registry-access-redhat-com.artifactory.svc.elca.ch/ubi8-micro:8.10-1774415318@sha256:936355df011657b9c6eaefbc08cd1e3e9a0103afbd0a2b83296be59586af8f8d

COPY --from=build-env /etc/pki /etc/pki
COPY --from=build-env /etc/ssl /etc/ssl
COPY --from=build-env /usr/bin/keycloak_bridge /usr/bin/keycloak_bridge

ENV TZ=Europe/Zurich

USER 1000

ENTRYPOINT ["/usr/bin/keycloak_bridge"]
CMD ["--config-file", "/opt/keycloak_bridge.yml"]
