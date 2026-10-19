# Supply a trusted ModelAudit image built from this branch: a local tag or repository manifest digest.
ARG MODELAUDIT_IMAGE
FROM ${MODELAUDIT_IMAGE}

# Build context contains the verified, extracted Linux Codex 0.163.0 package.
USER root
COPY codex-package/ /opt/codex/
RUN test -x /opt/codex/codex-resources/bwrap \
    && chmod -R a-w /opt/codex \
    && ln -s /opt/codex/bin/codex /usr/local/bin/codex \
    && test "$(codex --version)" = "codex-cli 0.163.0" \
    && mkdir -p /home/reviewer /work /request /artifacts \
    && chown 10001:10001 /home/reviewer /work

ENV HOME=/home/reviewer
ENV SHELL=/bin/sh
ENV PROMPTFOO_DISABLE_TELEMETRY=1
WORKDIR /work
USER 10001:10001
ENTRYPOINT ["python", "-m", "modelaudit.review.worker"]
