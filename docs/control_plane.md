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
release template deliberately contains no deployable image: validation fails unless release
automation supplies immutable `sha256` digests for both the Python base and TraceGuard image.
Tags, malformed digests, and the checked-in placeholder are rejected before building or
applying a manifest.

Use this reproducible pre-release check with values from your approved registry and build
metadata:

```bash
export PYTHON_IMAGE='python@sha256:<64 lowercase hex characters>'
export TRACEGUARD_IMAGE='<registry>/<repository>@sha256:<64 lowercase hex characters>'
python -m traceguard release-validate --base-image "$PYTHON_IMAGE" --release-image "$TRACEGUARD_IMAGE"
```

Then build only after that command succeeds, passing the same base image explicitly:

```bash
docker build --build-arg PYTHON_IMAGE="$PYTHON_IMAGE" --tag "$TRACEGUARD_IMAGE" .
```

Release automation must render `deploy/kubernetes/control-plane.yaml` with
`$TRACEGUARD_IMAGE` before `kubectl apply`; never apply the checked-in placeholder. Provide
`traceguard-secrets/signing-key` through your secret manager. No secret value belongs in the
manifest or repository. The existing non-root user, read-only filesystem, dropped
capabilities, disabled service-account-token mount, and runtime-default seccomp profile remain
required controls.
