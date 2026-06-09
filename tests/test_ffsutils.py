import errno

import pytest

from ffsutils import (
    NULL_HASH,
    base32_crockford,
    base32_crockford_decode,
    build_versioned_filename,
    ensure_within_base,
    get_suffix_from_path,
    normalize_vpath,
    parse_versioned_filename,
    sha256_to_crockford,
)


@pytest.mark.unit
@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("/", ""),
        ("/a/b", "a/b"),
        ("a//b/.", "a/b"),
        (r"a\\b", "a/b"),
        (" a/b ", "a/b"),
        ("a/../b", "a/b"),
    ],
)
def test_normalize_vpath(raw, expected):
    assert normalize_vpath(raw) == expected


@pytest.mark.unit
def test_ensure_within_base_rejects_escape(tmp_path):
    base = tmp_path / "base"
    base.mkdir()

    ensure_within_base(str(base), str(base / "child"))

    with pytest.raises(OSError) as exc:
        ensure_within_base(str(base), str(tmp_path / "outside"))
    assert exc.value.errno == errno.EINVAL


@pytest.mark.unit
def test_parse_and_build_versioned_filename_with_subdirs_and_dots():
    name = build_versioned_filename(
        "dir/archive.tar.gz",
        "A1B2C3D4E5F6G7H8J9K0MNPQRS",
        "write",
        timestamp=1234567890,
        flags=7,
    )

    assert name == "dir/archive.tar.gz.A1B2C3D4E5F6G7H8J9K0MNPQRS.write.7.1234567890"
    parsed = parse_versioned_filename(name)
    assert parsed == {
        "logical_name": "dir/archive.tar.gz",
        "content_hash": "A1B2C3D4E5F6G7H8J9K0MNPQRS",
        "mode": "write",
        "flags": 7,
        "timestamp": 1234567890,
    }


@pytest.mark.unit
def test_parse_preserves_leading_dot_in_logical_name():
    """A reserved dotdir (.ffsfs-nodes/<node>.json) must keep its leading dot
    through parse — lstrip('./') used to eat it, renaming the reserved dir to
    'ffsfs-nodes' and breaking the hide + peer path matching."""
    name = build_versioned_filename(
        ".ffsfs-nodes/borg.json", "A1B2C3D4E5F6G7H8J9K0MNPQRS",
        "write", timestamp=1781002443, flags=0)
    parsed = parse_versioned_filename(name)
    assert parsed["logical_name"] == ".ffsfs-nodes/borg.json"

    # a real "./" prefix is still stripped
    p2 = parse_versioned_filename(
        "./a/b.txt.A1B2C3D4E5F6G7H8J9K0MNPQRS.write.0.1")
    assert p2["logical_name"] == "a/b.txt"


@pytest.mark.unit
def test_build_versioned_filename_validates_inputs():
    with pytest.raises(ValueError):
        build_versioned_filename("file.txt", "bad", "write", 1)
    with pytest.raises(ValueError):
        build_versioned_filename("file.txt", "A1B2C3D4", "Write", 1)
    with pytest.raises(ValueError):
        build_versioned_filename("file.txt", "A1B2C3D4", "write", 1, flags=-1)


@pytest.mark.unit
def test_crockford_round_trip_and_hash_format():
    for n in [0, 1, 31, 32, 1024, 987654321]:
        assert base32_crockford_decode(base32_crockford(n)) == n

    assert base32_crockford_decode("o") == 0
    assert base32_crockford_decode("l") == 1
    assert len(sha256_to_crockford(b"hello")) == 26


@pytest.mark.unit
def test_get_suffix_from_version_and_temp():
    versioned = "file.txt.A1B2C3D4.write.0.123"
    assert get_suffix_from_path(versioned) == "A1B2C3D4.write.0.123"

    temp = f"file.txt.{NULL_HASH}.ABC123"
    assert get_suffix_from_path(temp) == f"{NULL_HASH}.{NULL_HASH}.ABC123"
