"""Module de debloating appliquant les regles metiers de nettoyage."""
from typing import List, Set

class Debloater:
    def __init__(self, blacklist: List[str], whitelist: List[str]):
        self.blacklist = set(blacklist)
        self.whitelist = set(whitelist)

    def filter_packages(self, installed_packages: List[str]) -> Set[str]:
        packages_to_remove = set()
        for pkg in installed_packages:
            if pkg in self.blacklist and pkg not in self.whitelist:
                packages_to_remove.add(pkg)
        return packages_to_remove
