#!/usr/bin/env bash
set -euo pipefail

# Keep executable builder artifacts immutable. docker/setup-buildx-action can
# obtain Buildx from mutable GitHub release assets and otherwise follows a
# mutable BuildKit image alias. This bootstrap pins and verifies both layers.
BUILDX_VERSION="v0.36.1"
BUILDX_COMMIT="1d8dde89b8aba914e05e45366770736fea1fd690"
BUILDX_LINUX_AMD64_SHA256="48af8a397ebd60178778bf63611dbcebe5f5e7a9be90eb9147b24b9587455778"
BUILDKIT_IMAGE="docker.io/moby/buildkit:v0.32.2@sha256:28a898719c18a33f4e8000685287fa36fd0dd9560c6440227d3a732d79bb41d8"
BUILDER_NAME="${SECURE_BUILDX_BUILDER:-mcp-lib-secure}"

case "$(uname -s)/$(uname -m)" in
  Linux/x86_64) ;;
  *)
    echo "unsupported runner architecture for verified Buildx bootstrap: $(uname -s)/$(uname -m)" >&2
    exit 2
    ;;
esac

buildx_tmp="$(mktemp)"
trap 'rm -f "$buildx_tmp"' EXIT

curl --fail --location --silent --show-error \
  --proto '=https' --tlsv1.2 \
  "https://github.com/docker/buildx/releases/download/${BUILDX_VERSION}/buildx-${BUILDX_VERSION}.linux-amd64" \
  --output "$buildx_tmp"
printf '%s  %s\n' "$BUILDX_LINUX_AMD64_SHA256" "$buildx_tmp" | sha256sum --check --strict -

plugin_dir="${HOME}/.docker/cli-plugins"
mkdir -p "$plugin_dir"
install -m 0755 "$buildx_tmp" "$plugin_dir/docker-buildx"

buildx_version="$(docker buildx version)"
printf '%s\n' "$buildx_version"
grep -Fq "$BUILDX_VERSION" <<<"$buildx_version"
grep -Fq "$BUILDX_COMMIT" <<<"$buildx_version"

docker buildx rm --force "$BUILDER_NAME" >/dev/null 2>&1 || true
docker buildx create \
  --name "$BUILDER_NAME" \
  --driver docker-container \
  --driver-opt "image=${BUILDKIT_IMAGE}" \
  --use >/dev/null

inspect="$(docker buildx inspect "$BUILDER_NAME" --bootstrap)"
printf '%s\n' "$inspect"
grep -Fq 'v0.32.2' <<<"$inspect"

container="buildx_buildkit_${BUILDER_NAME}0"
actual_image="$(docker inspect --format '{{.Config.Image}}' "$container")"
if [[ "$actual_image" != "$BUILDKIT_IMAGE" ]]; then
  echo "unexpected BuildKit image: $actual_image" >&2
  exit 3
fi

if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  printf 'builder=%s\n' "$BUILDER_NAME" >> "$GITHUB_OUTPUT"
fi
