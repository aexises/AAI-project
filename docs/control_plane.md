# TraceGuard control plane

The v1 control plane exposes `/v1/actions/evaluate`, signed policy bundles, policy
lifecycle endpoints, review resolution, audit export, and an OpenAI-compatible
`/v1/chat/completions` policy gate. It fails closed when no active policy exists.

`ControlPlane` currently ships with an in-memory repository for development and tests.
Production deployers must supply transactional PostgreSQL persistence, an object-store
evidence adapter, KMS-backed signing/encryption, a queue worker, and an OIDC identity
resolver before handling production traffic. The included `token_resolver` is a test and
development adapter only; it is not an OIDC implementation.

The SDK can fall back only to a valid HMAC-signed cached policy bundle and only for rules
explicitly marked `cache_eligible`. Escalations, blocks, expired bundles, unknown actions,
and control-plane outages without a qualifying cached rule all remain blocked.

Kubernetes manifests use a non-root, read-only container with dropped capabilities. The
release template deliberately contains no deployable image: release rendering fails unless
automation supplies immutable `sha256` digests for both the Python base and TraceGuard image.
Tags, malformed digests, the checked-in placeholder, and unresolved `${...}` or `{{...}}`
template values are rejected before a rendered manifest is written.

Use the following reproducible build-render-apply flow. All digests must come from approved
base-image and registry build metadata; they are not tags.

```bash
export PYTHON_IMAGE='python@sha256:<64 lowercase hex characters>'
export TRACEGUARD_REPOSITORY='<registry>/<repository>'
export RELEASE_TAG='release-<immutable-build-identifier>'
```

Build and push using the validated base-image digest. The registry then records the immutable
digest for the pushed release:

```bash
docker build --build-arg PYTHON_IMAGE="$PYTHON_IMAGE" --tag "$TRACEGUARD_REPOSITORY:$RELEASE_TAG" .
docker push "$TRACEGUARD_REPOSITORY:$RELEASE_TAG"
export TRACEGUARD_IMAGE='<registry>/<repository>@sha256:<digest recorded for this pushed release>'
```

Render to an explicit release artifact, review its image digest, and apply that artifact. The
command validates both image digests and the Dockerfile before it writes; it refuses to use the
checked-in template as its output and never mutates that template.

```bash
mkdir -p artifacts/release
python -m traceguard release-render \
  --base-image "$PYTHON_IMAGE" \
  --release-image "$TRACEGUARD_IMAGE" \
  --output artifacts/release/control-plane.yaml
rg -F "image: $TRACEGUARD_IMAGE" artifacts/release/control-plane.yaml
! rg -n 'REPLACE_WITH_|\$\{|\{\{' artifacts/release/control-plane.yaml
kubectl apply --filename artifacts/release/control-plane.yaml
```

Never apply `deploy/kubernetes/control-plane.yaml` directly. Provide the existing
`traceguard-secrets/signing-key` through your secret manager; no secret value or Kubernetes
`Secret` object belongs in this repository. The existing non-root user, read-only filesystem,
dropped capabilities, disabled service-account-token mount, and runtime-default seccomp profile
remain required controls.
