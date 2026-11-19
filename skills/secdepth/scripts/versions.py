"""Exact version ordering per ecosystem, and OSV `affected` evaluation.

Used for offline matching against OSV exports, where secdepth decides itself whether a version is
affected. Comparators follow each ecosystem's rules: Semantic Versioning, PEP 440, Maven's
ComparableVersion, dpkg and apk. `affects` returns None when an ecosystem has no comparator, so
callers can report the gap instead of guessing.
"""
import functools
import re

# --- Semantic Versioning (npm, Go, crates.io, NuGet, Hex, Pub, Packagist, RubyGems) -----------------

_SEMVER = re.compile(r"^v?(\d+(?:\.\d+)*)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$")


def _semver_key(version):
    m = _SEMVER.match(version.strip())
    if not m:
        raise ValueError("not a semantic version: %r" % version)
    release = [int(x) for x in m.group(1).split(".")]
    release += [0] * (4 - len(release))
    pre = m.group(2)
    if pre is None:
        return (release, 1, ())
    ids = tuple((0, int(p), "") if p.isdigit() else (1, 0, p) for p in pre.split("."))
    return (release, 0, ids)


def cmp_semver(a, b):
    ka, kb = _semver_key(a), _semver_key(b)
    return (ka > kb) - (ka < kb)


# --- PEP 440 (PyPI) --------------------------------------------------------------------------------

_PEP440 = re.compile(
    r"^\s*v?(?:(?P<epoch>\d+)!)?(?P<release>\d+(?:\.\d+)*)"
    r"(?:[-_.]?(?P<pre_l>alpha|a|beta|b|preview|pre|c|rc)[-_.]?(?P<pre_n>\d+)?)?"
    r"(?:-(?P<post_n1>\d+)|[-_.]?(?P<post_l>post|rev|r)[-_.]?(?P<post_n2>\d+)?)?"
    r"(?:[-_.]?(?P<dev_l>dev)[-_.]?(?P<dev_n>\d+)?)?"
    r"(?:\+(?P<local>[a-z0-9]+(?:[-_.][a-z0-9]+)*))?\s*$", re.I)
_PRE = {"a": 0, "alpha": 0, "b": 1, "beta": 1, "c": 2, "rc": 2, "pre": 2, "preview": 2}
INF = float("inf")


def _pep440_key(version):
    m = _PEP440.match(version)
    if not m:
        raise ValueError("not a PEP 440 version: %r" % version)
    release = [int(x) for x in m.group("release").split(".")]
    while len(release) > 1 and release[-1] == 0:
        release.pop()
    if m.group("pre_l"):
        pre = (_PRE[m.group("pre_l").lower()], int(m.group("pre_n") or 0))
    elif not (m.group("post_n1") or m.group("post_l")) and m.group("dev_l"):
        pre = (-INF, 0)          # 1.0.dev1 sorts before 1.0a1
    else:
        pre = (INF, 0)
    post_n = m.group("post_n1") or m.group("post_n2")
    post = (int(post_n or 0),) if (m.group("post_n1") or m.group("post_l")) else (-INF,)
    dev = (int(m.group("dev_n") or 0),) if m.group("dev_l") else (INF,)
    local = tuple((0, int(p), "") if p.isdigit() else (-1, 0, p) for p in re.split(r"[-_.]", m.group("local") or "") if p)
    return (int(m.group("epoch") or 0), tuple(release), pre, post, dev, local)


def cmp_pep440(a, b):
    ka, kb = _pep440_key(a), _pep440_key(b)
    return (ka > kb) - (ka < kb)


# --- Maven ComparableVersion ----------------------------------------------------------------------

_QUALIFIERS = {"alpha": 0, "a": 0, "beta": 1, "b": 1, "milestone": 2, "m": 2, "rc": 3, "cr": 3, "snapshot": 4,
               "": 5, "ga": 5, "final": 5, "release": 5, "sp": 6}


def _maven_items(version):
    items = []
    for part in re.findall(r"\d+|[A-Za-z]+", version.lower()):
        if part.isdigit():
            items.append((2, int(part), ""))
        else:
            # Maven drops zeros before a qualifier: 1.0-SNAPSHOT normalises to 1-snapshot.
            while items and items[-1] == (2, 0, ""):
                items.pop()
            order = _QUALIFIERS.get(part)
            items.append((1, order, "") if order is not None else (1, 7, part))
    # Trailing zeros and release-equivalent qualifiers do not change the version (1.0 == 1 == 1.0-ga).
    while items and items[-1] in ((2, 0, ""), (1, 5, "")):
        items.pop()
    return items


def cmp_maven(a, b):
    ia, ib = _maven_items(a), _maven_items(b)
    for i in range(max(len(ia), len(ib))):
        # A missing item compares as the neutral release marker: numbers are newer, qualifiers older.
        x = ia[i] if i < len(ia) else (1, 5, "")
        y = ib[i] if i < len(ib) else (1, 5, "")
        if x != y:
            if x[0] != y[0]:
                return 1 if x[0] > y[0] else -1
            return 1 if x[1:] > y[1:] else -1
    return 0


# --- dpkg (Debian, Ubuntu) ------------------------------------------------------------------------

def _dpkg_order(ch):
    if ch == "~":
        return -1
    if ch.isdigit():
        return 0
    if not ch:
        return 0
    if ch.isalpha():
        return ord(ch)
    return ord(ch) + 256


def _verrevcmp(a, b):
    i = j = 0
    while i < len(a) or j < len(b):
        first_diff = 0
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ac = _dpkg_order(a[i]) if i < len(a) else 0
            bc = _dpkg_order(b[j]) if j < len(b) else 0
            if ac != bc:
                return ac - bc
            i += 1
            j += 1
        while i < len(a) and a[i] == "0":
            i += 1
        while j < len(b) and b[j] == "0":
            j += 1
        while i < len(a) and a[i].isdigit() and j < len(b) and b[j].isdigit():
            if not first_diff:
                first_diff = ord(a[i]) - ord(b[j])
            i += 1
            j += 1
        if i < len(a) and a[i].isdigit():
            return 1
        if j < len(b) and b[j].isdigit():
            return -1
        if first_diff:
            return first_diff
    return 0


def _dpkg_parts(version):
    epoch, _, rest = version.rpartition(":") if ":" in version else ("0", "", version)
    upstream, _, revision = rest.rpartition("-") if "-" in rest else (rest, "", "")
    return int(epoch or 0), upstream, revision


def cmp_dpkg(a, b):
    ea, ua, ra = _dpkg_parts(a)
    eb, ub, rb = _dpkg_parts(b)
    if ea != eb:
        return (ea > eb) - (ea < eb)
    result = _verrevcmp(ua, ub) or _verrevcmp(ra, rb)
    return (result > 0) - (result < 0)


# --- apk (Alpine) ---------------------------------------------------------------------------------

_APK_SUFFIX = {"alpha": 0, "beta": 1, "pre": 2, "rc": 3, "": 4, "cvs": 5, "svn": 6, "git": 7, "hg": 8, "p": 9}
_APK = re.compile(r"^(\d+(?:\.\d+)*)([a-z]?)((?:_(?:alpha|beta|pre|rc|cvs|svn|git|hg|p)\d*)*)(?:-r(\d+))?$")


def _apk_key(version):
    m = _APK.match(version)
    if not m:
        raise ValueError("not an apk version: %r" % version)
    numbers = tuple(int(x) for x in m.group(1).split("."))
    suffixes = tuple((_APK_SUFFIX[s.rstrip("0123456789")], int(re.sub(r"\D", "", s) or 0))
                     for s in m.group(3).split("_")[1:]) or ((_APK_SUFFIX[""], 0),)
    return (numbers, m.group(2), suffixes, int(m.group(4) or 0))


def cmp_apk(a, b):
    ka, kb = _apk_key(a), _apk_key(b)
    return (ka > kb) - (ka < kb)


COMPARATORS = {
    "npm": cmp_semver, "Go": cmp_semver, "crates.io": cmp_semver, "NuGet": cmp_semver, "Hex": cmp_semver,
    "Pub": cmp_semver, "Packagist": cmp_semver, "RubyGems": cmp_semver, "PyPI": cmp_pep440, "Maven": cmp_maven,
    "Debian": cmp_dpkg, "Ubuntu": cmp_dpkg, "Alpine": cmp_apk,
}


def comparator(ecosystem):
    return COMPARATORS.get(ecosystem.split(":")[0])


def affects(affected, version, ecosystem):
    """True or False for one OSV `affected` entry, or None when the version cannot be compared."""
    if version in (affected.get("versions") or []):
        return True
    cmp = comparator(ecosystem)
    ranges = [r for r in affected.get("ranges") or [] if r.get("type") in ("SEMVER", "ECOSYSTEM")]
    if not ranges:
        # With a version list (or no data at all) the list is authoritative, as in OSV's own matching;
        # only GIT-only ranges leave the question open.
        return None if affected.get("ranges") and not affected.get("versions") else False
    if cmp is None:
        return None
    try:
        for rng in ranges:
            events = rng.get("events") or []
            intro = None
            for event in events:
                if "introduced" in event:
                    intro = event["introduced"]
                elif intro is not None and ("fixed" in event or "last_affected" in event):
                    above = intro == "0" or cmp(version, intro) >= 0
                    if "fixed" in event:
                        below = cmp(version, event["fixed"]) < 0
                    else:
                        below = cmp(version, event["last_affected"]) <= 0
                    if above and below:
                        return True
                    intro = None
            if intro is not None and (intro == "0" or cmp(version, intro) >= 0):
                return True  # introduced with no fix yet
    except ValueError:
        return None
    return False


def sort_key(ecosystem):
    cmp = comparator(ecosystem)
    return functools.cmp_to_key(cmp) if cmp else None
