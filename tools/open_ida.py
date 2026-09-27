import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_DIR = SCRIPT_DIR.parent
EXTRACTED_ROMS = (PROJECT_DIR / "references" / "extracted-roms").resolve()
IDA_EXE = Path(r"C:\Program Files\IDA Professional 9.0\ida.exe")
IDAT_EXE = Path(r"C:\Program Files\IDA Professional 9.0\idat.exe")
IDA_INIT_SCRIPT = SCRIPT_DIR / "ida_init_and_serve.py"
REGISTRY_DIR = Path.home() / ".ida-mcp" / "instances"

PE_EXTENSIONS = {".dll", ".exe"}


def assert_in_extracted_roms(p):
    resolved = Path(p).resolve()
    try:
        resolved.relative_to(EXTRACTED_ROMS)
    except ValueError:
        sys.stderr.write(
            f"\nERROR: refusing to open {resolved} in IDA.\n"
            f"Per CLAUDE.md, IDA only opens PEs under\n"
            f"  {EXTRACTED_ROMS}\n"
            f"That tree is produced by tools/extract_bundles.py from\n"
            f"each bundle's .nb0 / .bin; matching PDBs land next to\n"
            f"the modules automatically.\n"
            f"Never run IDA from build/ or bundled/.\n\n"
        )
        sys.exit(2)


def find_pe_files(directory, include_existing=False):
    """Find PE files in directory. Skip those with existing .i64 unless forced."""
    directory = Path(directory)
    files = []
    for f in sorted(directory.iterdir()):
        if f.suffix.lower() not in PE_EXTENSIONS:
            continue
        i64 = f.parent / (f.name + ".i64")
        if i64.exists() and not include_existing:
            continue
        files.append(f)
    return files


def is_already_open(pe_path):
    """Check if an IDA instance is already running for this exact PE file."""
    resolved = str(Path(pe_path).resolve()).lower().replace("/", "\\")
    if REGISTRY_DIR.is_dir():
        for f in REGISTRY_DIR.glob("*.json"):
            try:
                data = json.loads(f.read_text())
                instance_id = data.get("instance_id", "").lower().replace("/", "\\")
                if resolved == instance_id:
                    pid = data.get("pid")
                    result = subprocess.run(
                        ["tasklist", "/fi", f"pid eq {pid}", "/fo", "csv", "/nh"],
                        capture_output=True, text=True)
                    if str(pid) in result.stdout:
                        return data.get("port")
            except (json.JSONDecodeError, OSError):
                pass
    return None


def open_in_ida(pe_path, gui):
    pe_path = Path(pe_path).resolve()
    port = is_already_open(pe_path)
    if port:
        print(f"  ERROR: {pe_path.name} is already open in IDA (port {port})")
        sys.exit(1)
    print(f"  Opening: {pe_path.name}")
    args = [
        str(IDA_EXE if gui else IDAT_EXE),
        "-A",
        f"-S{IDA_INIT_SCRIPT}",
        str(pe_path),
    ]
    if gui:
        subprocess.Popen(args)
    else:
        subprocess.Popen(args,
                         creationflags=subprocess.CREATE_NO_WINDOW,
                         stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL)


def wait_for_registration(pe_path, timeout=120):
    """Wait until the IDA instance registers in ~/.ida-mcp/instances/."""
    resolved = str(Path(pe_path).resolve()).lower().replace("/", "\\")
    start = time.time()
    while time.time() - start < timeout:
        if REGISTRY_DIR.is_dir():
            for f in REGISTRY_DIR.glob("*.json"):
                try:
                    data = json.loads(f.read_text())
                    instance_id = data.get("instance_id", "").lower().replace("/", "\\")
                    if resolved == instance_id:
                        return data.get("port")
                except (json.JSONDecodeError, OSError):
                    pass
        time.sleep(2)
    return None


def main():
    parser = argparse.ArgumentParser(description="Open PE files in IDA (autonomous mode)")
    parser.add_argument("path", help="PE file or directory of PE files under references/extracted-roms/")
    parser.add_argument("--all", action="store_true",
                        help="Open ALL PEs, even those with existing .i64 databases")
    parser.add_argument("--wait", action="store_true",
                        help="Wait for analysis completion and server registration")
    parser.add_argument("--stagger", type=float, default=3.0,
                        help="Seconds between launching IDA instances (default: 3)")
    parser.add_argument("--gui", action="store_true",
                        help="Open the IDA window (default: headless idat.exe, no window)")
    args = parser.parse_args()

    exe = IDA_EXE if args.gui else IDAT_EXE
    if not exe.exists():
        print(f"ERROR: IDA not found at {exe}")
        sys.exit(1)

    target = Path(args.path)
    assert_in_extracted_roms(target)
    if target.is_file():
        files = [target]
    elif target.is_dir():
        files = find_pe_files(target, include_existing=args.all)
        if not files:
            print(f"No new PE files in {target}" +
                  (" (use --all to re-open existing)" if not args.all else ""))
            return
    else:
        print(f"ERROR: {target} not found")
        sys.exit(1)

    print(f"Opening {len(files)} file(s) in IDA (autonomous mode)...")
    for i, f in enumerate(files):
        open_in_ida(f, args.gui)
        if i < len(files) - 1:
            time.sleep(args.stagger)

    if args.wait:
        print(f"\nWaiting for IDA analysis and server registration...")
        for f in files:
            port = wait_for_registration(f)
            if port:
                print(f"  {f.name} -> port {port}")
            else:
                print(f"  {f.name} - timed out waiting for registration")

    print("\nIDA IS READY!")


if __name__ == "__main__":
    main()
