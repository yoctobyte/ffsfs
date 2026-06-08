import pytest

import ffssetup
from ffsvolumes import StoragePool, DEVICE_USB, JOB_GENERAL


_MB = 1024 * 1024


@pytest.fixture
def realm(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    ffssetup.create_realm_config(
        "rI", str(tmp_path / "mnt"), str(tmp_path / "store"),
        passphrase="a strong realm passphrase")
    return "rI"


@pytest.mark.unit
def test_collaboration_defaults_to_solo(realm):
    data = ffssetup.load_realm(realm)
    assert data["collaboration"] == ffssetup.COLLABORATION_SOLO


@pytest.mark.unit
def test_set_collaboration(realm):
    ffssetup.set_collaboration(realm, "shared")
    assert ffssetup.load_realm(realm)["collaboration"] == "shared"
    with pytest.raises(ValueError):
        ffssetup.set_collaboration(realm, "bogus")


@pytest.mark.unit
def test_suggest_backend_defaults_usb():
    s = ffssetup.suggest_backend_defaults(DEVICE_USB)
    assert s["mirror"] is True
    assert s["max_file_size"] == 64 * _MB
    assert s["role"] == "archive"


@pytest.mark.unit
def test_suggest_backend_defaults_unknown_is_neutral():
    s = ffssetup.suggest_backend_defaults(None)
    assert s["mirror"] is False and s["max_file_size"] is None


@pytest.mark.unit
def test_add_backend_applies_usb_assumptions(realm, tmp_path):
    vol = ffssetup.add_backend(realm, str(tmp_path / "stick"), device_class=DEVICE_USB)
    assert vol.device_class == DEVICE_USB
    assert vol.is_removable is True
    assert vol.mirror is True
    assert vol.max_file_size == 64 * _MB
    assert vol.job == JOB_GENERAL
    # persisted to realm config
    pool = StoragePool.from_dict(ffssetup.load_realm(realm)["storage_pool"])
    saved = pool.find_by_path(str(tmp_path / "stick"))
    assert saved is not None and saved.device_class == DEVICE_USB
    assert saved.max_file_size == 64 * _MB


@pytest.mark.unit
def test_add_backend_themed_job_overrides_general(realm, tmp_path):
    vol = ffssetup.add_backend(
        realm, str(tmp_path / "music"), device_class=DEVICE_USB, job_prefix="/music")
    assert vol.job_prefix == "/music"
    assert vol.job == "/music"  # themed job replaces "general"
    pool = StoragePool.from_dict(ffssetup.load_realm(realm)["storage_pool"])
    saved = pool.find_by_path(str(tmp_path / "music"))
    assert saved.job_prefix == "/music"


@pytest.mark.unit
def test_add_backend_rejects_unknown_device_class(realm, tmp_path):
    with pytest.raises(ValueError):
        ffssetup.add_backend(realm, str(tmp_path / "x"), device_class="floppy")


@pytest.mark.unit
def test_explicit_args_override_assumptions(realm, tmp_path):
    # caller-specified mirror/max_file_size must win over the device assumption
    vol = ffssetup.add_backend(
        realm, str(tmp_path / "stick2"), device_class=DEVICE_USB,
        mirror=False, max_file_size=1234)
    assert vol.mirror is False
    assert vol.max_file_size == 1234
