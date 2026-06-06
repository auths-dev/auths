"""Generate keripy 1.3.4 fixtures: a 3->2 key-removal rotation with dual-index (2A) sigers.

Oracle for auths-keri Epic B (dual-index CESR signatures). Deterministic (zero salt).
NOT run in CI — provenance only; regenerate with `python3 gen_rot_remove.py` (needs keripy 1.3.4).

Counters are pinned to CESR v1 (`gvrsn=Vrsn_1_0` -> `-A` ControllerIdxSigs) to match auths'
`serialize_attachment`. The siger codes (`A`/`2A`) are CESR-version-independent.

icp:  kt=2 k=[s0,s1,s2]  nt=2 n=Diger[s2,s3,s4]
rot:  kt=2 k=[s3,s4]     nt=2 n=Diger[s0,s1]   (true shrink; drops s2 = prior n[0])
rot sigers: s3 -> index 0 / ondex 1 (was prior n[1]); s4 -> index 1 / ondex 2 (was prior n[2])
"""
import pathlib
from keri.core import eventing, coring, signing, counting
from keri import kering

HERE = pathlib.Path(__file__).parent
salter = signing.Salter(raw=b"\x00" * 16)
signers = salter.signers(count=5, transferable=True, temp=True)
def vk(i): return signers[i].verfer.qb64
def nd(i): return coring.Diger(ser=signers[i].verfer.qb64b).qb64

def ctrl_counter(n):
    return counting.Counter(code=counting.Codens.ControllerIdxSigs, count=n, gvrsn=kering.Vrsn_1_0)

icp = eventing.incept(keys=[vk(0), vk(1), vk(2)], isith="2",
                      ndigs=[nd(2), nd(3), nd(4)], nsith="2", code=coring.MtrDex.Blake3_256)
isigs = [signers[0].sign(ser=icp.raw, index=0), signers[1].sign(ser=icp.raw, index=1)]
icp_att = bytes(ctrl_counter(len(isigs)).qb64b) + b"".join(bytes(s.qb64b) for s in isigs)

rot = eventing.rotate(pre=icp.pre, keys=[vk(3), vk(4)], dig=icp.said, sn=1, isith="2",
                      ndigs=[nd(0), nd(1)], nsith="2")
rsigs = [signers[3].sign(ser=rot.raw, index=0, ondex=1),
         signers[4].sign(ser=rot.raw, index=1, ondex=2)]
rot_att = bytes(ctrl_counter(len(rsigs)).qb64b) + b"".join(bytes(s.qb64b) for s in rsigs)

(HERE / "rot_remove.icp.json").write_bytes(icp.raw)
(HERE / "rot_remove.icp.att").write_bytes(icp_att)
(HERE / "rot_remove.rot.json").write_bytes(rot.raw)
(HERE / "rot_remove.rot.att").write_bytes(rot_att)
print("wrote 4 fixtures to", HERE)
print("rot att:", rot_att.decode())
for tag, s in (("rsig0", rsigs[0]), ("rsig1", rsigs[1])):
    print(f"{tag}: code={s.code} index={s.index} ondex={s.ondex} len={len(s.qb64)}")
