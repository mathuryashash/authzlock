"""Agent artifacts cached per base commit SHA. A cached run makes zero model calls; replay needs no API key."""
import re
import shutil
from pathlib import Path


class NoCachedArtifacts(LookupError):
    pass


class ArtifactCache:
    def __init__(self, root: Path | str = ".authzlock/cache"):
        self.root = Path(root)

    def _dir(self, sha: str) -> Path:
        if not re.fullmatch(r"[0-9a-f]{6,40}", sha):
            raise ValueError(f"not a git sha: {sha!r}")
        return self.root / sha

    def has(self, sha: str) -> bool:
        return (self._dir(sha) / ".complete").exists()

    def replay(self, sha: str) -> Path:
        if not self.has(sha):
            raise NoCachedArtifacts(f"no cached agent artifacts for {sha}; run the agent on that base first")
        return self._dir(sha)

    def get_or_build(self, sha: str, generate) -> Path:
        d = self._dir(sha)
        if self.has(sha):
            return d
        tmp = d.with_name(d.name + ".tmp")
        shutil.rmtree(tmp, ignore_errors=True)
        tmp.mkdir(parents=True)
        try:
            generate(tmp)
        except BaseException:
            shutil.rmtree(tmp, ignore_errors=True)
            raise
        (tmp / ".complete").write_text(sha)
        shutil.rmtree(d, ignore_errors=True)
        tmp.rename(d)
        return d
