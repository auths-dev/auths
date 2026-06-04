"""Tests for witness configuration service."""
from auths import Auths
from auths.witness import Witness

WITNESS_AID = "did:keri:BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo"


def test_add_and_list_witness(tmp_path):
    client = Auths(repo_path=str(tmp_path / ".auths"), passphrase="Test-pass-123")
    client.identities.create(label="main")

    w = client.witnesses.add(
        "http://witness.example.com:3333", WITNESS_AID, label="primary",
    )
    assert w.url == "http://witness.example.com:3333"
    assert isinstance(w, Witness)

    witnesses = client.witnesses.list()
    assert len(witnesses) == 1
    assert "witness.example.com" in witnesses[0].url
    assert witnesses[0].did == WITNESS_AID


def test_remove_witness(tmp_path):
    client = Auths(repo_path=str(tmp_path / ".auths"), passphrase="Test-pass-123")
    client.identities.create(label="main")

    client.witnesses.add("http://witness.example.com:3333", WITNESS_AID)
    client.witnesses.remove("http://witness.example.com:3333")

    assert len(client.witnesses.list()) == 0


def test_add_duplicate_witness_is_idempotent(tmp_path):
    client = Auths(repo_path=str(tmp_path / ".auths"), passphrase="Test-pass-123")
    client.identities.create(label="main")

    client.witnesses.add("http://witness.example.com:3333", WITNESS_AID)
    client.witnesses.add("http://witness.example.com:3333", WITNESS_AID)

    witnesses = client.witnesses.list()
    assert len(witnesses) == 1
