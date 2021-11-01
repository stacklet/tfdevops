# syntax = docker/dockerfile:1.3
ARG PYTHON_BUILD_IMAGE=python:3.10.0-bullseye
ARG PYTHON_DIST_IMAGE=python:3.10.0-slim-bullseye

# Build Container
FROM $PYTHON_BUILD_IMAGE as build

RUN adduser --disabled-login --gecos "" tfdevops

RUN python3 -m venv /app && chown -R tfdevops: /app
USER tfdevops

ENV POETRY_VERSION=1.1.11 \
    VIRTUAL_ENV="/app" \
    PATH="/home/tfdevops/.local/bin:/app/bin:${PATH}"

RUN curl -sSL https://raw.githubusercontent.com/python-poetry/poetry/master/install-poetry.py | python3 -

COPY pyproject.toml poetry.lock /app
WORKDIR /app

RUN --mount=type=cache,target=/home/tfdevops/.cache,uid=1000 poetry install --no-root --no-dev

ADD . /app
RUN --mount=type=cache,target=/home/tfdevops/.cache,uid=1000 poetry install --no-dev

FROM $PYTHON_DIST_IMAGE

ENV PYTHONFAULTHANDLER=1 \
  PYTHONUNBUFFERED=1 \
  PYTHONHASHSEED=random \
  AWS_RETRY_MODE=adaptive \
  AWS_STS_REGIONAL_ENDPOINTS=regional \
  AWS_MAX_ATTEMPTS=6 \
  LC_ALL="C.UTF-8" LANG="C.UTF-8"

COPY --from=build /etc/passwd /etc/passwd
COPY --from=build /etc/group /etc/group
COPY --chown=tfdevops:tfdevops --from=build /app /app

USER tfdevops
WORKDIR /app
ENTRYPOINT ["/app/bin/tfdevops"]
CMD ["--help"]
