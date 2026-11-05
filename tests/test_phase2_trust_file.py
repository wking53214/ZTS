"""Phase 2 audit, L4: the trust-root file is read as carefully as the grants it vouches for.

The audit's findings: duplicate JSON keys resolved silently to the last one (the grant parser already
refused them); the directory holding the file and any symlink were never checked; and the file was
checked by path and then read by path, so the name could be pointed elsewhere in between.
"""

from __future__ import annotations

import json
import os
import threading

import pytest

from issuer_kit import IssuerKey, trust_doc
from release_kit import Clock
from zts.trust import MAX_TRUST_BYTES, FileTrustRoot, TrustRootError

CLOCK = Clock()


def write(path, document, mode=0o644):
    path.write_text(document if isinstance(document, str) else json.dumps(document))
    os.chmod(path, mode)
    return path


def directory(parent, name, mode):
    d = parent / name
    d.mkdir()
    os.chmod(d, mode)
    return d


@pytest.fixture
def key():
    return IssuerKey("issuer-a")


# ------------------------------------------------------------------ strict parsing


def test_a_repeated_key_is_refused_not_resolved_to_the_last_one(tmp_path, key):
    entry = key.entry(CLOCK, status="revoked")
    text = json.dumps({"version": 1, "keys": [entry]}).replace('"status": "revoked"',
                                                                '"status": "revoked", "status": "active"')
    assert text.count('"status"') == 2
    with pytest.raises(TrustRootError, match="repeats a key"):
        FileTrustRoot(write(tmp_path / "t.json", text))
    nested = json.dumps(trust_doc(key.entry(CLOCK))).replace('{"version": 1,', '{"version": 1, "version": 1,')
    with pytest.raises(TrustRootError, match="repeats a key"):
        FileTrustRoot(write(tmp_path / "t2.json", nested))


@pytest.mark.parametrize("junk", ["{ nope", "[]", "null", '{"version": 1, "keys": [], "x": NaN}', "\xff\xfe", "{}"])
def test_other_malformed_documents_are_still_refused(tmp_path, junk):
    p = tmp_path / "t.json"
    p.write_bytes(junk.encode("latin-1", errors="replace"))
    os.chmod(p, 0o644)
    with pytest.raises(TrustRootError):
        FileTrustRoot(p)


def test_a_well_formed_root_still_loads(tmp_path, key):
    assert FileTrustRoot(write(tmp_path / "t.json", trust_doc(key.entry(CLOCK)))).current().keys


# ------------------------------------------------------------------ the directories


@pytest.mark.parametrize("mode,why", [(0o777, "can be written by other users"), (0o775, "can be written by other users"),
                                      (0o757, "can be written by other users")])
def test_a_file_in_a_directory_others_can_write_is_refused(tmp_path, key, mode, why):
    d = directory(tmp_path, "shared", mode)
    with pytest.raises(TrustRootError, match=why):
        FileTrustRoot(write(d / "t.json", trust_doc(key.entry(CLOCK))))


def test_a_writable_directory_higher_up_is_refused_too(tmp_path, key):
    outer = directory(tmp_path, "outer", 0o777)
    inner = directory(outer, "inner", 0o755)
    with pytest.raises(TrustRootError, match="can be written by other users"):
        FileTrustRoot(write(inner / "t.json", trust_doc(key.entry(CLOCK))))


def test_a_sticky_directory_is_accepted_because_others_cannot_replace_our_file(tmp_path, key):
    d = directory(tmp_path, "sticky", 0o1777)  # like /tmp
    assert FileTrustRoot(write(d / "t.json", trust_doc(key.entry(CLOCK)))).current().keys


def test_a_directory_made_writable_after_loading_is_noticed_on_the_next_use(tmp_path, key):
    d = directory(tmp_path, "d", 0o755)
    root = FileTrustRoot(write(d / "t.json", trust_doc(key.entry(CLOCK))))
    assert root.current().keys
    os.chmod(d, 0o777)  # the file itself did not change, so its stamp is the same
    with pytest.raises(TrustRootError, match="can be written by other users"):
        root.current()
    os.chmod(d, 0o755)
    assert root.current().keys, "and it recovers when the directory is safe again"


@pytest.mark.skipif(os.getuid() != 0, reason="needs root to hand a directory to another user")
def test_a_directory_owned_by_someone_else_is_refused(tmp_path, key):
    d = directory(tmp_path, "theirs", 0o755)
    write(d / "t.json", trust_doc(key.entry(CLOCK)))
    os.chown(d, 12345, 12345)
    with pytest.raises(TrustRootError, match="not owned by this user or root"):
        FileTrustRoot(d / "t.json")


# ---------------------------------------------------------------------- symlinks


def test_a_symlink_chain_in_safe_directories_is_accepted_as_configuration_mounts_make_them(tmp_path, key):
    mount = directory(tmp_path, "mount", 0o755)
    version = directory(mount, "..v1", 0o755)
    write(version / "trust.json", trust_doc(key.entry(CLOCK)))
    (mount / "..data").symlink_to("..v1")
    (mount / "trust.json").symlink_to("..data/trust.json")
    assert FileTrustRoot(mount / "trust.json").current().keys


def test_a_symlink_into_a_directory_others_can_write_is_refused(tmp_path, key):
    bad = directory(tmp_path, "bad", 0o777)
    write(bad / "t.json", trust_doc(key.entry(CLOCK)))
    safe = directory(tmp_path, "safe", 0o755)
    (safe / "t.json").symlink_to(bad / "t.json")
    with pytest.raises(TrustRootError, match="can be written by other users"):
        FileTrustRoot(safe / "t.json")


def test_a_link_retargeted_into_a_writable_directory_after_loading_is_refused(tmp_path, key):
    good = directory(tmp_path, "good", 0o755)
    write(good / "t.json", trust_doc(key.entry(CLOCK)))
    bad = directory(tmp_path, "bad", 0o777)
    write(bad / "t.json", trust_doc(key.entry(CLOCK)))
    safe = directory(tmp_path, "safe", 0o755)
    link = safe / "t.json"
    link.symlink_to(good / "t.json")
    root = FileTrustRoot(link)
    assert root.current().keys
    link.unlink()
    link.symlink_to(bad / "t.json")
    with pytest.raises(TrustRootError, match="can be written by other users"):
        root.current()


def test_a_link_that_points_at_another_link_in_a_writable_directory_is_refused(tmp_path, key):
    """The final file sits in safe directories, but the middle link is in a directory others can write,
    so they can retarget it. Resolving the whole chain at once would never look at that directory."""
    final = directory(tmp_path, "final", 0o755)
    write(final / "t.json", trust_doc(key.entry(CLOCK)))
    open_dir = directory(tmp_path, "open", 0o777)
    (open_dir / "middle").symlink_to(final / "t.json")
    safe = directory(tmp_path, "safe", 0o755)
    (safe / "t.json").symlink_to(open_dir / "middle")
    with pytest.raises(TrustRootError, match="can be written by other users"):
        FileTrustRoot(safe / "t.json")


def test_a_loop_of_links_is_refused_not_followed_forever(tmp_path):
    (tmp_path / "a").symlink_to(tmp_path / "b")
    (tmp_path / "b").symlink_to(tmp_path / "a")
    with pytest.raises(TrustRootError):
        FileTrustRoot(tmp_path / "a")


def test_a_link_that_reaches_a_writable_directory_through_dot_dot_and_a_linked_directory_is_refused(tmp_path, key):
    """`lnkdir/../t.json` looks like a file beside the link when read as text, but the operating system walks
    out of the REAL directory lnkdir points into. Only the fully resolved path shows where the file is."""
    open_dir = directory(tmp_path, "open", 0o777)
    inner = directory(open_dir, "inner", 0o755)
    write(open_dir / "t.json", trust_doc(key.entry(CLOCK)))
    safe = directory(tmp_path, "safe", 0o755)
    (safe / "lnkdir").symlink_to(inner)
    (safe / "t.json").symlink_to("lnkdir/../t.json")
    assert os.path.realpath(safe / "t.json") == str(open_dir / "t.json")
    with pytest.raises(TrustRootError, match="can be written by other users"):
        FileTrustRoot(safe / "t.json")


@pytest.mark.skipif(os.getuid() != 0, reason="needs root to hand a file to another user")
def test_a_file_owned_by_someone_else_is_refused_even_in_a_safe_directory(tmp_path, key):
    p = write(tmp_path / "t.json", trust_doc(key.entry(CLOCK)))
    os.chown(p, 12345, 12345)
    with pytest.raises(TrustRootError, match="is not owned by this user or root"):
        FileTrustRoot(p)


# --------------------------------------------------------------- what kind of file


def test_a_fifo_in_the_place_of_the_file_is_refused_instead_of_hanging(tmp_path):
    p = tmp_path / "t.json"
    os.mkfifo(p, 0o644)
    outcome = {}

    def attempt():
        try:
            FileTrustRoot(p)
            outcome["r"] = "loaded"
        except TrustRootError as exc:
            outcome["r"] = str(exc)
    t = threading.Thread(target=attempt, daemon=True)
    t.start()
    t.join(5)
    assert not t.is_alive(), "opening a FIFO must not block"
    assert "not a regular file" in outcome["r"]


def test_an_oversized_file_is_refused_without_being_read_whole(tmp_path):
    p = tmp_path / "t.json"
    p.write_bytes(b" " * (MAX_TRUST_BYTES + 1))
    os.chmod(p, 0o644)
    with pytest.raises(TrustRootError, match="larger than"):
        FileTrustRoot(p)


# ----------------------------------------------------------- one open, checked and read


def test_the_file_that_is_checked_is_the_file_that_is_read(tmp_path, key, monkeypatch):
    """Swap the name for another file at the instant the real one is opened. The content loaded must be
    the opened file's, because its owner, mode and kind were taken from that same open file."""
    other = IssuerKey("issuer-b")
    path = write(tmp_path / "t.json", trust_doc(key.entry(CLOCK)))
    attacker = write(tmp_path / "attacker.json", trust_doc(other.entry(CLOCK)))
    real_open, swapped = os.open, []

    def opening(name, *args, **kwargs):
        fd = real_open(name, *args, **kwargs)
        if str(name) == str(path) and not swapped:
            swapped.append(True)
            os.replace(attacker, path)  # after our open: the name now means a different file
        return fd
    monkeypatch.setattr(os, "open", opening)
    root = FileTrustRoot(path)
    first = set(root._root.keys)  # what the load that raced with the swap actually used
    monkeypatch.undo()
    assert swapped and first == {key.kid}, "the root that was loaded is the one that was opened and checked"
    # The stamp describes the file that was read, so the replaced file is noticed and loaded on the next use.
    assert set(root.current().keys) == {other.kid}
