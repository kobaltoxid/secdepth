import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "skills" / "secdepth" / "scripts"))
import versions  # noqa: E402


def ordered(cmp, items):
    """Each item must sort strictly before the next."""
    for a, b in zip(items, items[1:]):
        assert cmp(a, b) < 0 and cmp(b, a) > 0, (a, b)


class ComparatorTests(unittest.TestCase):
    def test_semver(self):
        ordered(versions.cmp_semver, ["0.0.0-20201016220609-9e8e0b390897", "0.1.0", "1.0.0-alpha", "1.0.0-alpha.1",
                                      "1.0.0-alpha.beta", "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0", "1.2.10"])
        self.assertEqual(versions.cmp_semver("1.0.0+build.1", "1.0.0"), 0)
        self.assertEqual(versions.cmp_semver("v1.2", "1.2.0"), 0)

    def test_pep440(self):
        ordered(versions.cmp_pep440, ["1.0.dev1", "1.0a1", "1.0a2.dev1", "1.0a2", "1.0b1", "1.0rc1", "1.0",
                                      "1.0+local", "1.0.post1", "1.1", "2!0.1"])
        self.assertEqual(versions.cmp_pep440("1.0", "1.0.0"), 0)
        self.assertEqual(versions.cmp_pep440("1.0RC1", "1.0rc1"), 0)

    def test_maven(self):
        ordered(versions.cmp_maven, ["1.0-alpha1", "1.0-beta1", "1.0-M1", "1.0-RC1", "1.0-SNAPSHOT", "1.0", "1.0-sp1",
                                     "1.0.1", "1.1", "2.14.1", "2.15.0"])
        self.assertEqual(versions.cmp_maven("1.0", "1.0.0"), 0)
        self.assertEqual(versions.cmp_maven("1.0-ga", "1"), 0)

    def test_dpkg(self):
        ordered(versions.cmp_dpkg, ["1.0~rc1", "1.0", "1.0-1", "1.0-1+deb12u1", "1.0a", "1:0.5"])
        ordered(versions.cmp_dpkg, ["3.0.11-1~deb12u1", "3.0.11-1~deb12u2", "3.0.11-1", "3.0.13-1~deb12u1"])
        self.assertEqual(versions.cmp_dpkg("1.0-0", "1.0-0"), 0)

    def test_apk(self):
        ordered(versions.cmp_apk, ["1.2.3_alpha1", "1.2.3_rc1", "1.2.3", "1.2.3-r1", "1.2.3_p1", "1.2.3a", "1.2.4"])


class AffectsTests(unittest.TestCase):
    def test_ranges_and_lists(self):
        aff = {"ranges": [{"type": "SEMVER", "events": [{"introduced": "6.7.0"}, {"fixed": "6.7.3"},
                                                        {"introduced": "6.9.0"}, {"fixed": "6.9.7"}]}]}
        self.assertTrue(versions.affects(aff, "6.7.0", "npm"))
        self.assertFalse(versions.affects(aff, "6.7.3", "npm"))
        self.assertFalse(versions.affects(aff, "6.8.0", "npm"))
        self.assertTrue(versions.affects(aff, "6.9.6", "npm"))
        last = {"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"last_affected": "2.10"}]}]}
        self.assertTrue(versions.affects(last, "2.10", "PyPI"))
        self.assertFalse(versions.affects(last, "2.10.1", "PyPI"))
        open_ended = {"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "1.0"}]}]}
        self.assertTrue(versions.affects(open_ended, "9.9", "PyPI"))
        listed = {"versions": ["1.2.0"], "ranges": [{"type": "GIT", "events": [{"introduced": "abc"}]}]}
        self.assertTrue(versions.affects(listed, "1.2.0", "SwiftURL"))
        self.assertFalse(versions.affects(listed, "1.3.0", "SwiftURL"))

    def test_distribution_and_unknown(self):
        deb = {"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.0.13-1~deb12u1"}]}]}
        self.assertTrue(versions.affects(deb, "3.0.11-1~deb12u2", "Debian:12"))
        self.assertFalse(versions.affects(deb, "3.0.13-1~deb12u1", "Debian:12"))
        self.assertIsNone(versions.affects({"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]},
                                           "1.0", "Hackage"))
        self.assertIsNone(versions.affects(deb, "not a version!", "PyPI"))



class EmptyAffectedTests(unittest.TestCase):
    def test_entry_without_versions_or_ranges_affects_nothing(self):
        self.assertFalse(versions.affects({"package": {"name": "jinja2"}}, "2.10", "PyPI"))
        self.assertIsNone(versions.affects({"ranges": [{"type": "GIT", "events": [{"introduced": "abc"}]}]}, "2.10", "PyPI"))


if __name__ == "__main__":
    unittest.main()
