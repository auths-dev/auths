"""Import path smoke tests."""


def test_client_import():
    from auths import Auths
    assert Auths is not None


def test_error_imports():
    from auths import AuthsError, VerificationError, CryptoError
    assert all(cls is not None for cls in [AuthsError, VerificationError, CryptoError])


def test_bare_function_imports():
    from auths import verify_attestation, sign_bytes, get_token
    assert all(fn is not None for fn in [verify_attestation, sign_bytes, get_token])


def test_submodule_imports():
    from auths.verify import verify_chain
    from auths.sign import sign_action
    from auths.agent import AgentAuth
    from auths.git import discover_layout, verify_commit_range
    assert all(x is not None for x in [verify_chain, sign_action, AgentAuth, discover_layout, verify_commit_range])


def test_backwards_compat_alias():
    from auths.agent import AuthsAgentAuth
    from auths.agent import AgentAuth
    assert AuthsAgentAuth is AgentAuth
