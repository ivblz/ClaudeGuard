"""Copy the notices for dependencies shipped by the Windows build."""
from importlib.metadata import distribution
from pathlib import Path
import shutil
import sys


def copy_distribution_license(name, notices):
    package = distribution(name)
    license_names = package.metadata.get_all("License-File")
    target = notices / name
    target.mkdir()
    for license_name in license_names:
        for file in package.files:
            if file.name == license_name and file.parts[0].endswith(".dist-info"):
                shutil.copy2(package.locate_file(file), target / file.name)
                break
        else:
            raise FileNotFoundError(f"{name}: {license_name}")


def main():
    notices = Path(sys.argv[1])
    for name in ("Pillow", "pystray", "six", "PyInstaller", "packaging"):
        copy_distribution_license(name, notices)
    python_home = Path(sys.base_prefix)
    shutil.copy2(python_home / "LICENSE.txt", notices / "Python.txt")
    for license_file in (python_home / "tcl").glob("*/license.terms"):
        shutil.copy2(license_file, notices / f"{license_file.parent.name}.txt")


if __name__ == "__main__":
    main()
