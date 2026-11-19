#!/usr/bin/env python3
"""Download OSV's per-ecosystem exports and look up advisories in them offline.

Usage: osvdata.py download DIR ECOSYSTEM [ECOSYSTEM ...]   # for example: npm PyPI Go Debian

Each export is saved as DIR/<ecosystem>/all.zip with its Last-Modified date. A package-name index is
built on first use and rebuilt when the zip changes. Withdrawn advisories are kept, so stale scanner
reports can be explained.
"""
import datetime
import json
import pathlib
import re
import shutil
import sys
import urllib.request
import zipfile

EXPORT = "https://osv-vulnerabilities.storage.googleapis.com/%s/all.zip"


def normalise(ecosystem, name):
    return re.sub(r"[-_.]+", "-", name).lower() if ecosystem == "PyPI" else name


def download(dest, ecosystems, opener=urllib.request.urlopen):
    dest = pathlib.Path(dest)
    for eco in ecosystems:
        folder = dest / eco
        folder.mkdir(parents=True, exist_ok=True)
        with opener(EXPORT % urllib.request.quote(eco), timeout=600) as resp, open(folder / "all.zip.part", "wb") as fh:
            shutil.copyfileobj(resp, fh, 1 << 20)
            last_modified = resp.headers.get("Last-Modified")
        (folder / "all.zip.part").replace(folder / "all.zip")
        (folder / "meta.json").write_text(json.dumps({
            "ecosystem": eco, "last_modified": last_modified, "url": EXPORT % eco,
            "downloaded_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}))
        print("%s: %d bytes, data from %s" % (eco, (folder / "all.zip").stat().st_size, last_modified))


class Store:
    def __init__(self, dest):
        self.dest = pathlib.Path(dest)
        self._names = {}      # ecosystem -> {name: [member]}
        self._ids = {}        # advisory id -> (ecosystem, member)
        self._zips = {}

    def available(self, ecosystem):
        return (self.dest / ecosystem / "all.zip").is_file()

    def meta(self, ecosystem):
        path = self.dest / ecosystem / "meta.json"
        return json.loads(path.read_text()) if path.is_file() else {}

    def _load(self, ecosystem):
        if ecosystem in self._names:
            return
        zpath = self.dest / ecosystem / "all.zip"
        stamp = "%d-%d" % (zpath.stat().st_size, int(zpath.stat().st_mtime))
        index_path = self.dest / ecosystem / "index.json"
        index = json.loads(index_path.read_text()) if index_path.is_file() else {}
        zf = self._zips[ecosystem] = zipfile.ZipFile(zpath)
        if index.get("stamp") != stamp:
            names, ids = {}, {}
            for member in zf.namelist():
                record = json.loads(zf.read(member))
                ids[record["id"]] = member
                for affected in record.get("affected") or []:
                    pkg = affected.get("package") or {}
                    if pkg.get("ecosystem", "").split(":")[0] == ecosystem and pkg.get("name"):
                        names.setdefault(normalise(ecosystem, pkg["name"]), []).append(member)
            index = {"stamp": stamp, "names": names, "ids": ids}
            index_path.write_text(json.dumps(index))
        self._names[ecosystem] = index["names"]
        for advisory_id, member in index["ids"].items():
            self._ids.setdefault(advisory_id, (ecosystem, member))

    def records_for(self, ecosystem, name):
        self._load(ecosystem)
        members = sorted(set(self._names[ecosystem].get(normalise(ecosystem, name), [])))
        return [json.loads(self._zips[ecosystem].read(m)) for m in members]

    def record(self, advisory_id):
        if advisory_id not in self._ids:
            for folder in sorted(self.dest.iterdir()) if self.dest.is_dir() else []:
                if (folder / "all.zip").is_file():
                    self._load(folder.name)
        if advisory_id not in self._ids:
            raise LookupError("advisory %s is not in the downloaded OSV exports" % advisory_id)
        ecosystem, member = self._ids[advisory_id]
        return json.loads(self._zips[ecosystem].read(member))


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    if len(args) < 3 or args[0] != "download":
        print(__doc__.strip(), file=sys.stderr)
        return 2
    download(args[1], args[2:])
    return 0


if __name__ == "__main__":
    sys.exit(main())
