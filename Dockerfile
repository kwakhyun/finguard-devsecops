FROM python:3.11-slim-bookworm@sha256:c425d915a89a6dcd3183b1797ad9bd8878caff5a417f6371c8df93c8ea8b727f

ARG APP_UID=10001
ARG APP_GID=10001

RUN groupadd --gid "${APP_GID}" app \
    && useradd --uid "${APP_UID}" --gid app --create-home --shell /usr/sbin/nologin app

WORKDIR /app
COPY --chown=app:app sample_service /app/sample_service

USER app
EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
  CMD ["python", "-m", "sample_service.healthcheck"]

ENTRYPOINT ["python", "-m", "sample_service.app"]
