from pathlib import Path

import pytest

from traceguard.cli import main
from traceguard.release import (
    ReleaseValidationError,
    render_release_manifest,
    validate_dockerfile,
    validate_image_digest,
    validate_manifest,
)

VALID_BASE_IMAGE = "python@sha256:" + "a" * 64
VALID_RELEASE_IMAGE = "registry.invalid/traceguard/api@sha256:" + "b" * 64


def test_image_digest_requires_an_immutable_sha256_reference() -> None:
    assert validate_image_digest(VALID_RELEASE_IMAGE, label="image") == VALID_RELEASE_IMAGE
    for image in (
        "python:3.11-slim",
        "ghcr.io/example/traceguard@sha256:REPLACE_WITH_RELEASE_DIGEST",
        "registry.example.invalid/traceguard/api@sha256:" + "A" * 64,
        "registry.example.invalid/traceguard/api:latest@sha256:" + "a" * 64,
    ):
        with pytest.raises(ReleaseValidationError):
            validate_image_digest(image, label="image")


def test_manifest_placeholder_fails_without_a_release_digest() -> None:
    with pytest.raises(ReleaseValidationError, match="immutable image reference"):
        validate_manifest(Path("deploy/kubernetes/control-plane.yaml"))


def test_dockerfile_rejects_a_mutable_python_image_default(tmp_path) -> None:
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("ARG PYTHON_IMAGE=python:3.11-slim\nFROM ${PYTHON_IMAGE}\n")
    with pytest.raises(ReleaseValidationError, match="without a mutable default"):
        validate_dockerfile(dockerfile, base_image=VALID_BASE_IMAGE)


def test_release_dockerfile_has_a_build_time_digest_check() -> None:
    dockerfile = Path("Dockerfile").read_text(encoding="utf-8")
    assert "ARG PYTHON_IMAGE\nFROM ${PYTHON_IMAGE}" in dockerfile
    assert "PYTHON_IMAGE must be an immutable sha256 digest" in dockerfile


def test_release_validation_renders_only_a_valid_release_digest(capsys) -> None:
    assert (
        main(
            [
                "release-validate",
                "--base-image",
                VALID_BASE_IMAGE,
                "--release-image",
                VALID_RELEASE_IMAGE,
            ]
        )
        == 0
    )
    assert '"valid": true' in capsys.readouterr().out


def test_release_validation_rejects_the_previous_mutable_base_image(capsys) -> None:
    assert main(["release-validate", "--base-image", "python:3.11-slim"]) == 1
    assert "@sha256 digest separator" in capsys.readouterr().err


def test_release_render_writes_a_valid_manifest_without_mutating_the_template(
    tmp_path, capsys
) -> None:
    template = Path("deploy/kubernetes/control-plane.yaml")
    original = template.read_text(encoding="utf-8")
    output = tmp_path / "control-plane.rendered.yaml"

    assert (
        main(
            [
                "release-render",
                "--base-image",
                VALID_BASE_IMAGE,
                "--release-image",
                VALID_RELEASE_IMAGE,
                "--output",
                str(output),
            ]
        )
        == 0
    )

    rendered = output.read_text(encoding="utf-8")
    assert VALID_RELEASE_IMAGE in rendered
    assert "REPLACE_WITH_RELEASE_DIGEST" not in rendered
    assert template.read_text(encoding="utf-8") == original
    assert str(output) in capsys.readouterr().out


def test_release_render_rejects_an_unsafe_digest_without_writing_output(tmp_path, capsys) -> None:
    output = tmp_path / "control-plane.rendered.yaml"

    assert (
        main(
            [
                "release-render",
                "--base-image",
                VALID_BASE_IMAGE,
                "--release-image",
                "registry.invalid/traceguard/api:latest",
                "--output",
                str(output),
            ]
        )
        == 1
    )

    assert not output.exists()
    assert "@sha256 digest separator" in capsys.readouterr().err


def test_release_render_rejects_a_mutable_base_without_writing_output(tmp_path, capsys) -> None:
    output = tmp_path / "control-plane.rendered.yaml"

    assert (
        main(
            [
                "release-render",
                "--base-image",
                "python:3.11-slim",
                "--release-image",
                VALID_RELEASE_IMAGE,
                "--output",
                str(output),
            ]
        )
        == 1
    )

    assert not output.exists()
    assert "@sha256 digest separator" in capsys.readouterr().err


def test_release_render_refuses_the_template_as_its_output(tmp_path) -> None:
    template = tmp_path / "control-plane.yaml"
    original = (
        "apiVersion: v1\nkind: Pod\nspec:\n  containers:\n"
        "    - name: api\n"
        "      image: registry.invalid/traceguard@sha256:REPLACE_WITH_RELEASE_DIGEST\n"
    )
    template.write_text(original, encoding="utf-8")

    with pytest.raises(ReleaseValidationError, match="must differ"):
        render_release_manifest(
            dockerfile=Path("Dockerfile"),
            template=template,
            output=template,
            base_image=VALID_BASE_IMAGE,
            release_image=VALID_RELEASE_IMAGE,
        )

    assert template.read_text(encoding="utf-8") == original


def test_release_render_rejects_unresolved_template_values(tmp_path) -> None:
    template = tmp_path / "control-plane.yaml"
    output = tmp_path / "control-plane.rendered.yaml"
    template.write_text(
        "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: ${UNRESOLVED_NAME}\n"
        "---\napiVersion: v1\nkind: Pod\nspec:\n  containers:\n"
        "    - name: api\n"
        "      image: registry.invalid/traceguard@sha256:REPLACE_WITH_RELEASE_DIGEST\n",
        encoding="utf-8",
    )

    with pytest.raises(ReleaseValidationError, match="unresolved placeholder"):
        render_release_manifest(
            dockerfile=Path("Dockerfile"),
            template=template,
            output=output,
            base_image=VALID_BASE_IMAGE,
            release_image=VALID_RELEASE_IMAGE,
        )

    assert not output.exists()
