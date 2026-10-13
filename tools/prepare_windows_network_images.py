import argparse
import struct
from pathlib import Path


def prepare(path, dry_run):
    with path.open("rb" if dry_run else "r+b") as image:
        if image.read(2) != b"MZ":
            raise ValueError(f"Not a Windows image: {path}")
        image.seek(0x3C)
        header = struct.unpack("<I", image.read(4))[0]
        image.seek(header)
        if image.read(4) != b"PE\0\0":
            raise ValueError(f"Invalid Windows image: {path}")
        image.seek(header + 22)
        characteristics = struct.unpack("<H", image.read(2))[0]
        if characteristics & 0x0800:
            return False
        if not dry_run:
            image.seek(header + 22)
            image.write(struct.pack("<H", characteristics | 0x0800))
        return True


def main():
    parser = argparse.ArgumentParser(description="Load generated Windows images from local swap when running on a network share.")
    parser.add_argument("runtime", type=Path)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    if not args.runtime.is_dir():
        parser.error("runtime must be an existing directory")
    root = args.runtime
    paths = sorted({*root.glob("*.exe"), *root.glob("*.dll"), *root.joinpath("libs").glob("*.prx"), *root.joinpath("libs").glob("*.dll"), *root.joinpath("app0").rglob("*.guest.prx")})
    changed = 0
    for path in paths:
        if prepare(path, args.dry_run):
            print(path.relative_to(root))
            changed += 1
    verb = "Would update" if args.dry_run else "Updated"
    print(f"{verb} {changed} of {len(paths)} Windows images with IMAGE_FILE_NET_RUN_FROM_SWAP.")


if __name__ == "__main__":
    main()
