FROM r-docker-registry-access-redhat-com.artifactory.svc.elca.ch/ubi8-minimal:8.10-1778576163@sha256:03bcee28f6137a3103a9218d2d7e6a453658d04a084ec9a41d1501c0d28cff37 AS build-env

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

FROM r-docker-registry-access-redhat-com.artifactory.svc.elca.ch/ubi8-micro:8.10-1778057490@sha256:6815c92ac2d9989e90132b8cbd707f85e86fce17baeaceb647d12b5614c35f91

COPY --from=build-env /etc/pki /etc/pki
COPY --from=build-env /etc/ssl /etc/ssl
COPY --from=build-env /usr/bin/keycloak_bridge /usr/bin/keycloak_bridge

ENV TZ=Europe/Zurich

USER 1000

ENTRYPOINT ["/usr/bin/keycloak_bridge"]
CMD ["--config-file", "/opt/keycloak_bridge.yml"]
