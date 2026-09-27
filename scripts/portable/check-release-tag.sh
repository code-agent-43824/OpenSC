#!/usr/bin/env bash
# Refuses a portable release tag that is malformed or already used by a Git
# tag or a published GitHub release, so a workflow run can never replace the
# assets of an existing release.
set -euo pipefail

: "${RELEASE_TAG:?RELEASE_TAG is required}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"

api="${GITHUB_API_URL:-https://api.github.com}/repos/$GITHUB_REPOSITORY"
auth=()
if [ -n "${GH_TOKEN:-}" ]; then
  auth=(--header "Authorization: Bearer $GH_TOKEN")
fi

if [[ ! "$RELEASE_TAG" =~ ^[0-9]+\.[0-9]+\.[0-9]+-portable\.[0-9]+$ ]]; then
  echo "::error::Release tag must look like 0.27.1-portable.5" >&2
  exit 1
fi

for resource in "git/ref/tags/$RELEASE_TAG" "releases/tags/$RELEASE_TAG"; do
  code=$(curl --silent --show-error --retry 3 --output /dev/null \
    --write-out '%{http_code}' ${auth[@]+"${auth[@]}"} \
    --header 'Accept: application/vnd.github+json' "$api/$resource")
  case "$code" in
    404) ;;
    200)
      echo "::error::$RELEASE_TAG is already used ($resource); choose a new tag" >&2
      exit 1
      ;;
    *)
      echo "::error::Cannot check $resource: HTTP $code" >&2
      exit 1
      ;;
  esac
done

echo "Release tag $RELEASE_TAG is unused"
