"""Generate keripy 1.3.4 delegation fixtures: a delegated inception (`dip`) anchored
by the delegator's interaction event, with the delegate-side `-G` SealSourceCouple.

Oracle for auths-keri Epic E.1 (reciprocal source seal). Deterministic (zero/fixed
salt). NOT run in CI — provenance only; regenerate with `python3 gen_delegation.py`
(needs keripy 1.3.4).

Counters are pinned to CESR v1 (`gvrsn=Vrsn_1_0`) to match auths' attachment codecs.
The `-G` couple is `Seqner(sn of delegator anchor)` + `Saider(said of delegator anchor)`.
"""
import json
import pathlib
from keri.core import eventing, coring, signing, counting
from keri import kering

HERE = pathlib.Path(__file__).parent

del_signers = signing.Salter(raw=b"\x00" * 16).signers(count=3, transferable=True, temp=True)
agt_signers = signing.Salter(raw=b"\x11" * 16).signers(count=3, transferable=True, temp=True)


def vk(s, i):
    return s[i].verfer.qb64


def nd(s, i):
    return coring.Diger(ser=s[i].verfer.qb64b).qb64


# Delegator (root) inception — single sig.
delegator = eventing.incept(keys=[vk(del_signers, 0)], isith="1", ndigs=[nd(del_signers, 1)],
                            nsith="1", code=coring.MtrDex.Blake3_256)

# Delegate (agent) delegated inception (dip) naming delegator as delpre.
dip = eventing.delcept(keys=[vk(agt_signers, 0)], isith="1", delpre=delegator.pre,
                       ndigs=[nd(agt_signers, 1)], nsith="1", code=coring.MtrDex.Blake3_256)

# Delegator anchors the dip via an interaction event with a key-event seal.
seal = dict(i=dip.pre, s="0", d=dip.said)
ixn = eventing.interact(pre=delegator.pre, dig=delegator.said, sn=1, data=[seal])
anchor_sn = 1

# Delegate-side source-seal couple (-G): Seqner(anchor sn) + Saider(anchor said).
seqner = coring.Seqner(sn=anchor_sn)
saider = coring.Saider(qb64=ixn.said)
gctr = counting.Counter(code=counting.Codens.SealSourceCouples, count=1, gvrsn=kering.Vrsn_1_0)
gsrc_att = bytes(gctr.qb64b) + bytes(seqner.qb64b) + bytes(saider.qb64b)

# Full dip attachment as streamed: controller idx sig group (-A) then source seal (-G).
dsig = agt_signers[0].sign(ser=dip.raw, index=0)
sctr = counting.Counter(code=counting.Codens.ControllerIdxSigs, count=1, gvrsn=kering.Vrsn_1_0)
dip_att = bytes(sctr.qb64b) + bytes(dsig.qb64b) + gsrc_att

(HERE / "delegation.delegator.json").write_bytes(delegator.raw)
(HERE / "delegation.dip.json").write_bytes(dip.raw)
(HERE / "delegation.ixn.json").write_bytes(ixn.raw)
(HERE / "delegation.gsrc.att").write_bytes(gsrc_att)
(HERE / "delegation.dip.att").write_bytes(dip_att)
(HERE / "delegation.meta.json").write_text(json.dumps({
    "delegator_pre": delegator.pre,
    "dip_pre": dip.pre,
    "dip_said": dip.said,
    "anchor_sn": anchor_sn,
    "anchor_said": ixn.said,
}, indent=2))

print("wrote delegation fixtures to", HERE)
print("gsrc att:", gsrc_att.decode())
print("dip  att:", dip_att.decode())
print("anchor:", anchor_sn, ixn.said)
