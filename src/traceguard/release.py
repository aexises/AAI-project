"""Fail-closed validation for container release inputs."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_REPOSITORY_COMPONENT_RE = re.compile(r"^[a-z0-9]+(?:[._-][a-z0-9]+)*$")
_IMAGE_LINE_RE = re.compile(r"^(?P<indent>\s*)image:\s*(?P<value>[^#\r\n]+?)(?:\s+#.*)?$")
_PLACEHOLDER_MARKERS = ("replace", "placeholder", "changeme", "todo")
_RELEASE_DIGEST_PLACEHOLDER = "REPLACE_WITH_RELEASE_DIGEST"
_UNRESOLVED_TEMPLATE_RE = re.compile(r"REPLACE_WITH_[A-Z0-9_]+|\$\{[^}\r\n]+\}|\{\{[^}\r\n]+\}\}")


class ReleaseValidationError(ValueError):
    """Raised when an image reference cannot safely identify a release artifact."""


@dataclass(frozen=True)
class ManifestImage:
    """An image field discovered in a Kubernetes manifest."""

    path: Path
    line: int
    value: str


def validate_image_digest(image: str, *, label: str) -> str:
    """Return a canonical immutable image reference or raise a fail-closed error.

    Tags, non-sha256 algorithms, malformed repository names, and known template
    markers are intentionally rejected. A digest is syntactically validated here;
    registry existence and signature verification belong to the release pipeline.
    """

    candidate = image.strip()
    if not candidate or candidate != image or any(character.isspace() for character in candidate):
        raise ReleaseValidationError(f"{label} must be a non-empty image digest without whitespace")
    if candidate.count("@") != 1:
        raise ReleaseValidationError(f"{label} must use exactly one @sha256 digest separator")

    repository, digest = candidate.split("@", 1)
    if not repository or not _DIGEST_RE.fullmatch(digest):
        raise ReleaseValidationError(
            f"{label} must be an immutable image reference ending in @sha256:<64 lowercase hex>"
        )
    if any(marker in candidate.lower() for marker in _PLACEHOLDER_MARKERS):
        raise ReleaseValidationError(f"{label} contains a placeholder or example value")

    parts = repository.split("/")
    for index, part in enumerate(parts):
        if index == 0 and len(parts) > 1 and ":" in part:
            host, separator, port = part.rpartition(":")
            if (
                not separator
                or not _REPOSITORY_COMPONENT_RE.fullmatch(host)
                or not port.isdecimal()
            ):
                raise ReleaseValidationError(f"{label} has an invalid registry port")
        elif not _REPOSITORY_COMPONENT_RE.fullmatch(part):
            if index == len(parts) - 1 and ":" in part:
                raise ReleaseValidationError(f"{label} must not include a mutable image tag")
            raise ReleaseValidationError(f"{label} has an invalid repository name: {repository!r}")
    return candidate


def validate_dockerfile(dockerfile: Path, *, base_image: str) -> None:
    """Require a caller-supplied immutable base image for the Docker build."""

    try:
        contents = dockerfile.read_text(encoding="utf-8")
    except OSError as exc:
        raise ReleaseValidationError(f"cannot read Dockerfile {dockerfile}: {exc}") from exc

    arg_lines = [
        line.strip()
        for line in re.findall(
            r"^\s*ARG\s+PYTHON_IMAGE(?:\s*=\s*[^\s#]+)?\s*$", contents, re.MULTILINE
        )
    ]
    from_pattern = re.compile(r"^\s*FROM\s+\$\{PYTHON_IMAGE\}(?:\s+AS\s+\w+)?\s*$", re.MULTILINE)
    if not arg_lines or any(line != "ARG PYTHON_IMAGE" for line in arg_lines):
        raise ReleaseValidationError(
            f"{dockerfile} must declare ARG PYTHON_IMAGE without a mutable default"
        )
    if not from_pattern.search(contents):
        raise ReleaseValidationError(f"{dockerfile} must build FROM ${{PYTHON_IMAGE}}")
    validate_image_digest(base_image, label="PYTHON_IMAGE")


def manifest_images(manifest: Path) -> list[ManifestImage]:
    """Extract Kubernetes ``image:`` values without loading untrusted YAML objects."""

    try:
        lines = manifest.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ReleaseValidationError(f"cannot read manifest {manifest}: {exc}") from exc
    images: list[ManifestImage] = []
    for line_number, text in enumerate(lines, start=1):
        match = _IMAGE_LINE_RE.match(text)
        if match:
            images.append(
                ManifestImage(
                    path=manifest,
                    line=line_number,
                    value=match.group("value").strip().strip("\"'"),
                )
            )
    if not images:
        raise ReleaseValidationError(f"{manifest} contains no Kubernetes image fields")
    return images


def validate_manifest(manifest: Path, *, release_image: str | None = None) -> None:
    """Validate every manifest image, optionally rendering the release placeholder."""

    replacement = (
        validate_image_digest(release_image, label="TRACEGUARD_RELEASE_IMAGE")
        if release_image is not None
        else None
    )
    for image in manifest_images(manifest):
        value = (
            replacement
            if _RELEASE_DIGEST_PLACEHOLDER in image.value and replacement
            else image.value
        )
        try:
            validate_image_digest(value, label=f"{image.path}:{image.line} image")
        except ReleaseValidationError as exc:
            raise ReleaseValidationError(str(exc)) from exc


def render_release_manifest(
    *,
    dockerfile: Path,
    template: Path,
    output: Path,
    base_image: str,
    release_image: str,
) -> Path:
    """Render one digest-pinned Kubernetes manifest without changing its template.

    The output destination must differ from the checked-in template. Rendering is
    validated before an atomic replacement of the requested output path, so a
    rejected input never leaves a partial or unsafe manifest behind.
    """

    try:
        template_path = template.resolve(strict=True)
    except OSError as exc:
        raise ReleaseValidationError(f"cannot resolve manifest template {template}: {exc}") from exc
    output_path = output.resolve(strict=False)
    if output_path == template_path:
        raise ReleaseValidationError("render output must differ from the manifest template")
    if not output_path.parent.is_dir():
        raise ReleaseValidationError(
            f"render output directory does not exist: {output_path.parent}"
        )

    validate_dockerfile(dockerfile, base_image=base_image)
    replacement = validate_image_digest(release_image, label="TRACEGUARD_RELEASE_IMAGE")
    try:
        contents = template_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ReleaseValidationError(
            f"cannot read manifest template {template_path}: {exc}"
        ) from exc

    placeholder_count = contents.count(_RELEASE_DIGEST_PLACEHOLDER)
    image_placeholder_count = sum(
        image.value.count(_RELEASE_DIGEST_PLACEHOLDER) for image in manifest_images(template_path)
    )
    if placeholder_count != image_placeholder_count:
        raise ReleaseValidationError(
            "release digest placeholder must occur only in a Kubernetes image field"
        )
    if placeholder_count == 0:
        raise ReleaseValidationError(
            f"manifest template contains no {_RELEASE_DIGEST_PLACEHOLDER} placeholder"
        )

    rendered_lines: list[str] = []
    for line in contents.splitlines(keepends=True):
        body = line.rstrip("\r\n")
        line_ending = line[len(body) :]
        image_match = _IMAGE_LINE_RE.match(body)
        if image_match and _RELEASE_DIGEST_PLACEHOLDER in image_match.group("value"):
            rendered_lines.append(
                f"{image_match.group('indent')}image: {replacement}"
                f"{body[image_match.end('value') :]}{line_ending}"
            )
        else:
            rendered_lines.append(line)
    rendered = "".join(rendered_lines)
    unresolved = _UNRESOLVED_TEMPLATE_RE.search(rendered)
    if unresolved:
        raise ReleaseValidationError(
            f"rendered manifest contains an unresolved placeholder: {unresolved.group(0)!r}"
        )

    temporary_output = output_path.with_name(f".{output_path.name}.tmp")
    try:
        temporary_output.write_text(rendered, encoding="utf-8")
        validate_manifest(temporary_output)
        temporary_output.replace(output_path)
    except OSError as exc:
        raise ReleaseValidationError(
            f"cannot write rendered manifest {output_path}: {exc}"
        ) from exc
    finally:
        try:
            temporary_output.unlink(missing_ok=True)
        except OSError:
            pass
    return output_path


def validate_release_artifacts(
    *, dockerfile: Path, manifests: list[Path], base_image: str, release_image: str | None = None
) -> None:
    """Validate all supplied release inputs before building or applying them."""

    if not manifests:
        raise ReleaseValidationError("at least one Kubernetes manifest is required")
    validate_dockerfile(dockerfile, base_image=base_image)
    for manifest in manifests:
        validate_manifest(manifest, release_image=release_image)
