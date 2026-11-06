"""Module responsable de l extraction des archives de mise a jour QF001."""
import os

class FirmwareUnpacker:
    def __init__(self, archive_path: str, extract_dir: str):
        self.archive_path = archive_path
        self.extract_dir = extract_dir

    def validate_archive(self) -> bool:
        return os.path.exists(self.archive_path)
