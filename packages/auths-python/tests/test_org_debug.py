"""Diagnostic test for org operations."""
import json
from auths import Auths
from auths._native import list_org_members as _list_org_members


def test_org_debug(tmp_path):
    """Debug: create org and inspect internal state."""
    admin_home = tmp_path / "admin"
    admin_home.mkdir()
    repo = str(admin_home / ".auths")

    client = Auths(repo_path=repo, passphrase="Test-pass-123")

    # Step 1: Create personal identity
    personal = client.identities.create(label="admin")
    print(f"\n[DEBUG] Personal DID: {personal.did}")
    print(f"[DEBUG] Personal PK:  {personal.public_key}")

    # Step 2: Create org
    org = client.orgs.create("team")
    print(f"[DEBUG] Org DID:    {org.did}")
    print(f"[DEBUG] Org prefix: {org.prefix}")

    # Step 3: List org members (should include admin self-attestation)
    raw_json = _list_org_members(org.did, True, repo)
    members = json.loads(raw_json)
    print(f"[DEBUG] Members after create_org ({len(members)}):")
    for m in members:
        print(f"  - did={m['member_did']}, role={m['role']}, revoked={m['revoked']}")
        print(f"    caps={m['capabilities']}")
        print(f"    prefix={m.get('member_prefix')}")

    # Step 4: Add member (org mints the member key from a label)
    try:
        member = client.orgs.add_member(
            org.did, "alice", role="member", repo_path=repo,
        )
        print(f"[DEBUG] add_member succeeded: {member}")
    except Exception as e:
        print(f"[DEBUG] add_member FAILED: {e}")
        raise

    # Step 6: List again
    raw_json2 = _list_org_members(org.did, True, repo)
    members2 = json.loads(raw_json2)
    print(f"[DEBUG] Members after add_member ({len(members2)}):")
    for m in members2:
        print(f"  - did={m['member_did']}, role={m['role']}, revoked={m['revoked']}")
