"""Create only deterministic, project-owned RC fixtures; preserve unexpected data."""
from pathlib import Path
import hashlib

root = Path(__file__).resolve().parent.parent / 'tests' / 'fixtures' / 'rc-alpha1'
root.mkdir(exist_ok=True)
block = b'Hinana Flow RC public boundary test\n'
for name, size in [('boundary-10000000.bin', 10_000_000), ('over-limit-10000001.bin', 10_000_001)]:
    expected = (block * ((size + len(block) - 1) // len(block)))[:size]
    target = root / name
    if target.exists():
        if target.is_symlink() or target.read_bytes() != expected:
            raise RuntimeError('Existing fixture differs; refusing overwrite')
    else:
        with target.open('xb') as stream:
            stream.write(expected)
    print(f'PASS public boundary fixture: {size} bytes; SHA-256 {hashlib.sha256(expected).hexdigest()}')
target = root / 'RC-public-document.txt'
expected = b'Hinana Flow Alpha 1 RC public document. No personal data.\n'
if target.exists():
    if target.is_symlink() or target.read_bytes() != expected:
        raise RuntimeError('Existing public document differs; refusing overwrite')
else:
    with target.open('xb') as stream:
        stream.write(expected)
