import os
import stat
import shutil
import tempfile
import time
from pathlib import Path
from urllib.parse import urlparse

from git import GitCommandError, Repo


class RepositoryError(Exception):
    """An expected repository validation or clone failure."""


class RepositoryService:
    """Validates, clones, and cleans up a mission's temporary repository."""

    def __init__(self, workspace_root: Path | None = None) -> None:
        configured_root = os.getenv("KAVACH_WORKSPACE_ROOT")
        self._workspace_root = workspace_root or (
            Path(configured_root) if configured_root else Path(tempfile.gettempdir()) / "kavach-ai-workspaces"
        )

    def clone(self, repository_url: str, mission_id: str) -> tuple[str, Path]:
        repository_name = self.validate_url(repository_url)
        destination = self._workspace_root / mission_id
        destination.parent.mkdir(parents=True, exist_ok=True)

        try:
            repository = Repo.clone_from(
                repository_url,
                destination,
                depth=1,
                single_branch=True,
                no_tags=True,
                env={"GIT_TERMINAL_PROMPT": "0"},
            )
            repository.close()
        except (GitCommandError, OSError) as error:
            self.cleanup(mission_id)
            raise RepositoryError("Kavach AI could not clone this repository. Confirm that it is public and accessible.") from error

        return repository_name, destination

    def cleanup(self, mission_id: str) -> None:
        destination = (self._workspace_root / mission_id).resolve()
        root = self._workspace_root.resolve()
        if root not in destination.parents:
            raise RepositoryError("Refusing to clean up an invalid workspace path.")
        if not destination.exists():
            return
        for attempt in range(5):
            try:
                shutil.rmtree(destination, onexc=self._remove_readonly)
                return
            except PermissionError:
                if attempt == 4:
                    raise
                time.sleep(0.25)

    @staticmethod
    def _remove_readonly(func: object, path: str, _: object) -> None:
        """Allow cleanup of read-only Git object files on Windows."""
        os.chmod(path, stat.S_IWRITE)
        func(path)  # type: ignore[operator]

    @staticmethod
    def validate_url(repository_url: str) -> str:
        """Validate the only repository source supported by the hackathon MVP."""
        parsed = urlparse(repository_url.strip())
        if parsed.scheme not in {"http", "https"} or parsed.netloc.lower() != "github.com":
            raise RepositoryError("Provide a public GitHub HTTPS repository URL.")

        path_parts = [part for part in parsed.path.split("/") if part]
        if len(path_parts) != 2:
            raise RepositoryError("Repository URLs must use the form https://github.com/owner/repository.")

        repository_name = path_parts[1].removesuffix(".git")
        if not repository_name:
            raise RepositoryError("Repository name is missing from the URL.")
        return repository_name
