"""Tests for witness configuration service."""
from auths import Auths
from auths.witness import Witness


def test_add_and_list_witness(tmp_path):
    client = Auths(repo_path=str(tmp_path / ".auths"), passphrase="Test-pass-123")
    client.identities.create(label="main")

    w = client.witnesses.add("http://witness.example.com:3333", label="primary")
    assert w.url == "http://witness.example.com:3333"
    assert isinstance(w, Witness)

    witnesses = client.witnesses.list()
    assert len(witnesses) == 1
    assert "witness.example.com" in witnesses[0].url


def test_remove_witness(tmp_path):
    client = Auths(repo_path=str(tmp_path / ".auths"), passphrase="Test-pass-123")
    client.identities.create(label="main")

    client.witnesses.add("http://witness.example.com:3333")
    client.witnesses.remove("http://witness.example.com:3333")

    assert len(client.witnesses.list()) == 0


def test_add_duplicate_witness_is_idempotent(tmp_path):
    client = Auths(repo_path=str(tmp_path / ".auths"), passphrase="Test-pass-123")
    client.identities.create(label="main")

    client.witnesses.add("http://witness.example.com:3333")
    client.witnesses.add("http://witness.example.com:3333")

    witnesses = client.witnesses.list()
    assert len(witnesses) == 1
