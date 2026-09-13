"""Meta: every numbered vector TV-E--01..62 exists as a named test, and the
fixture anchors match the spec's §9.3 golden bytes."""

import os
import re

from evalseal import fixture as fx
from evalseal.canon import canonical_hash
from evalseal.render import (render_badge, render_leaderboard, render_page)

HERE = os.path.dirname(__file__)


def _test_names():
    names = set()
    for fn in os.listdir(HERE):
        if fn.startswith("test_") and fn.endswith(".py"):
            with open(os.path.join(HERE, fn)) as f:
                names.update(re.findall(r"def (test_\w+)", f.read()))
    return names


def test_all_62_vectors_present():
    names = _test_names()
    missing = [f"TV-E--{i:02d}" for i in range(1, 63)
               if not any(n.startswith(f"test_tv_e_{i:02d}") for n in names)]
    assert not missing, f"missing vectors: {missing}"


def test_fixture_golden_anchors():
    """Byte-identity anchors from spec §9.3 / tests/fixtures."""
    fixdir = os.path.join(HERE, "..", "fixtures")
    assert canonical_hash({}) == \
        "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
    assert fx.HR == "sha256:86a0eea84e415d7f46022c9bb37f4c6b125e5e80a78e01cc1ecf23c938df24fa"
    assert canonical_hash(fx.CERT) == \
        "sha256:938254e438ac1770da82010f2a6c37a97a4b2f73e834287cb8517bdcac603483"
    pack = fx.pack_bytes()
    golden = os.path.join(fixdir, "pack.zip")
    if os.path.exists(golden):
        with open(golden, "rb") as f:
            assert f.read() == pack
    assert len(pack) == 91036
    for name, fn in (("report.pdf", lambda: __import__("evalseal.render", fromlist=["x"]).render_pdf(fx.CERT, fx.RESULT, fx.RELEASE)),
                     ("badge.svg", lambda: render_badge(fx.CERT, fx.STATUS)),
                     ("page.html", lambda: render_page(fx.CERT, fx.RESULT, fx.STATUS, fx.RELEASE)),
                     ("leaderboard.html", lambda: render_leaderboard(fx.PAGE, fx.RELEASE)),
                     ("transcript.bin", lambda: fx.RAW)):
        golden = os.path.join(fixdir, name)
        if os.path.exists(golden):
            with open(golden, "rb") as f:
                assert f.read() == fn(), name
