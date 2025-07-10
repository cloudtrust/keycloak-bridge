FROM docker.artifactory.svc.elca.ch/redhat/ubi8-minimal:8.10-1751443646 AS build-env

LABEL name="ephemeral/ct-keycloak-bridge" releaseName="ct-keycloak-bridge" repository="prj-cloudtrust-docker" releaseRepository="prj-cloudtrust-docker"

RUN curl -s https://artifactory.svc.elca.ch:443/artifactory/prj_cloudtrust_generic_public/cert/ELCACorporateRootCA.crt -o /etc/pki/ca-trust/source/anchors/elca-local-root.pem && \
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

FROM docker.artifactory.svc.elca.ch/redhat/ubi8-micro:8.10-1751466198

COPY --from=build-env /etc/pki /etc/pki
COPY --from=build-env /etc/ssl /etc/ssl
COPY --from=build-env /usr/bin/keycloak_bridge /usr/bin/keycloak_bridge

ENV TZ=Europe/Zurich

USER 1000

ENTRYPOINT ["/usr/bin/keycloak_bridge"]
CMD ["--config-file", "/opt/keycloak_bridge.yml"]
