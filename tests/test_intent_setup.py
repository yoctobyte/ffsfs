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
def test_external_disk_has_no_small_file_cap():
    # a USB/eSATA external HDD/SSD must NOT get the small-key cap
    from ffsvolumes import DEVICE_EXTERNAL
    s = ffssetup.suggest_backend_defaults(DEVICE_EXTERNAL)
    assert s["max_file_size"] is None
    assert s["mirror"] is True
    # external is removable
    from ffsvolumes import Volume
    assert Volume(path="/tmp/x", device_class=DEVICE_EXTERNAL).is_removable is True


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
def test_set_realm_secret(realm, monkeypatch, tmp_path):
    import ffspeer_auth
    before = ffssetup.load_realm(realm)["realm_secret"]
    # same passphrase + realm derives the SAME secret on every host
    ffssetup.set_realm_secret(realm, passphrase="team shared phrase")
    after = ffssetup.load_realm(realm)["realm_secret"]
    assert after != before
    assert after == ffspeer_auth.secret_from_passphrase("team shared phrase", realm)
    # exact hex is taken verbatim; too-short hex rejected
    hexsec = "ab" * 20
    ffssetup.set_realm_secret(realm, secret=hexsec)
    assert ffssetup.load_realm(realm)["realm_secret"] == hexsec
    with pytest.raises(ValueError):
        ffssetup.set_realm_secret(realm, secret="abcd")


@pytest.mark.unit
def test_parse_size():
    assert ffssetup._parse_size("", 999) == 999          # blank keeps current
    assert ffssetup._parse_size("none", 999) is None      # explicit clear
    assert ffssetup._parse_size("0", 999) is None
    assert ffssetup._parse_size("2G", None) == 2 * 1024 ** 3
    assert ffssetup._parse_size("512M", None) == 512 * 1024 ** 2
    assert ffssetup._parse_size("1024", None) == 1024     # plain bytes
    assert ffssetup._parse_size("garbage", 7) == 7        # unparseable keeps


@pytest.mark.unit
def test_choose_realm_accepts_number(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    ffssetup.create_realm_config("alpha", str(tmp_path / "a-mnt"), str(tmp_path / "a"))
    ffssetup.create_realm_config("bravo", str(tmp_path / "b-mnt"), str(tmp_path / "b"))
    realms = ffssetup.list_realms()           # sorted: ['alpha', 'bravo']
    monkeypatch.setattr(ffssetup, "_prompt", lambda *a, **k: "2")
    assert ffssetup._choose_realm() == realms[1]
    monkeypatch.setattr(ffssetup, "_prompt", lambda *a, **k: "newrealm")
    assert ffssetup._choose_realm() == "newrealm"   # a name still creates


@pytest.mark.unit
def test_edit_backend_persists_changes(realm, tmp_path, monkeypatch):
    ffssetup.add_backend(realm, str(tmp_path / "ext"), device_class="external")
    # scripted answers in _prompt call order: pick #2, keep role/media,
    # set max file size 1G, keep the rest.
    answers = iter(["2", "", "", "1G", "", "", "", ""])
    monkeypatch.setattr(ffssetup, "_prompt", lambda *a, **k: next(answers))
    monkeypatch.setattr(ffssetup, "_yes_no", lambda *a, **k: False)
    ffssetup.prompt_edit_backend(realm)

    pool = StoragePool.from_dict(ffssetup.load_realm(realm)["storage_pool"])
    saved = pool.find_by_path(str(tmp_path / "ext"))
    assert saved is not None
    assert saved.max_file_size == 1024 ** 3
    assert saved.mirror is False      # we answered no to the mirror prompt


@pytest.mark.unit
def test_explicit_args_override_assumptions(realm, tmp_path):
    # caller-specified mirror/max_file_size must win over the device assumption
    vol = ffssetup.add_backend(
        realm, str(tmp_path / "stick2"), device_class=DEVICE_USB,
        mirror=False, max_file_size=1234)
    assert vol.mirror is False
    assert vol.max_file_size == 1234
