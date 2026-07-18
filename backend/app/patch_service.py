from pathlib import Path

from app.models import PatchProposal


class PatchError(Exception):
    """A patch could not be safely validated or applied."""


class PatchService:
    """Applies an explicitly approved, exact source replacement within a workspace."""

    def apply(self, workspace: Path, proposal: PatchProposal) -> None:
        source_path = self.source_path(workspace, proposal.file_path)
        try:
            source = source_path.read_text(encoding="utf-8")
        except OSError as error:
            raise PatchError(f"Kavach could not read the proposed source file: {error}") from error

        before = proposal.patch_before.strip("\n")
        after = proposal.patch_after.strip("\n")
        if not before or not after:
            raise PatchError("The patch must include both the original and replacement code.")

        occurrences = source.count(before)
        if occurrences == 0:
            raise PatchError("The original code no longer matches this patch. Re-analyze the finding before applying it.")
        if occurrences > 1:
            raise PatchError("The proposed code occurs more than once, so Kavach will not choose a location automatically.")

        try:
            source_path.write_text(source.replace(before, after, 1), encoding="utf-8")
        except OSError as error:
            raise PatchError(f"Kavach could not write the proposed source file: {error}") from error

    @staticmethod
    def source_path(workspace: Path, file_path: str) -> Path:
        root = workspace.resolve()
        candidate = (root / file_path).resolve()
        try:
            candidate.relative_to(root)
        except ValueError as error:
            raise PatchError("The patch targets a file outside the mission workspace.") from error
        if not candidate.exists() or not candidate.is_file():
            raise PatchError("The patch target file is not available in the mission workspace.")
        return candidate
