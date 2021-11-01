

lint:
  pre-commit run --all-files

test:
  pytest -v tests/unit

image:
  DOCKER_BUILDKIT=1 docker buildx build \
     --label "org.opencontainers.image.vendor=stacklet" \
     --label "org.opencontainers.image.source=https://github.com/stacklet/tfdevops" \
     --label "org.opencontainers.image.licenses=Apache-2.0" \
     --label "org.opencontainers.image.title=Terraform Devops Guru" \
     -t "tfdevops:latest" \
     --progress plain \
     --load .
