"""Dump type-7/8/9/14 blocks from an mxip .vol file + resolve hDatabase handles.
IDA: H_TO_HH 0x53690, LookupDBHandle 0x4A944, ReadRecord 0x77C5C."""
import struct, sys

if len(sys.argv) != 2:
    sys.exit("usage: dump_vol_records.py <mxip .vol file>")
path = sys.argv[1]
with open(path, 'rb') as f:
    data = f.read()

def r32(o): return struct.unpack_from('<I', data, o)[0]
def r16(o): return struct.unpack_from('<H', data, o)[0]

LOG_PAGE = 0x1000
HANDLE_TABLE = 0x1000  # master handle table, 4096 u32 entries
HEAP = 0x5000  # pStart

def h_to_hh(h):
    """Resolve a CE heap handle to (block_data_offset_in_file, backptr).
    IDA: H_TO_HH 0x53690.
    iMH = h / 0x400, iSH = h % 0x400.
    pHMaster[iMH] = offset from pStart to sub-handle table block header.
    sub-handle entry = pStart + pHMaster[iMH] + 12 + iSH*4."""
    iMH = h // 0x400
    iSH = h %  0x400
    master = r32(HANDLE_TABLE + iMH * 4)  # value is offset-from-pStart to subhand block header
    if iMH and master == 0:
        return None, None
    subhand_data = HEAP + master + 12
    entry = r32(subhand_data + iSH * 4)
    if not (entry & 1):
        return None, None
    data_off = HEAP + (entry & 0xFFFFFFC)
    # heap header is at data_off - 12; backptr at +8
    backptr = r32(data_off - 4)
    return data_off, backptr

# Walk all heap blocks
scan = HEAP
end  = len(data)
dbs_by_backptr = {}
records = []
while scan + 12 < end:
    hdr = r32(scan)
    typ = (hdr >> 28) & 0xF
    size = hdr & 0x0FFFFFFC
    free = hdr & 1
    backptr = r32(scan + 8)
    d = scan + 12
    if size == 0 or d + size > end:
        break
    if typ == 7 and not free:
        # DATABASE block
        name_chars = []
        for i in range(32):
            ch = r16(d + 8 + i*2)
            if ch == 0: break
            name_chars.append(chr(ch))
        name = ''.join(name_chars)
        dbs_by_backptr[backptr] = name
        print(f"@0x{scan:05X} type=7 (DATABASE) back=0x{backptr:08X} name='{name}' size={size}")
    elif typ == 8 and not free:
        hDatabase = r32(d)
        records.append((scan, size, backptr, hDatabase))
    elif typ == 14 and not free:
        print(f"@0x{scan:05X} type=14 back=0x{backptr:08X} size={size} firstdw=0x{r32(d):08X}")
    scan += 12 + size

print(f"\n{len(records)} RECORD blocks")
print("--- resolving hDatabase for each record ---")
dbhandle_seen = {}
for (off, size, backptr, hdb) in records[:5]:
    data_off, db_back = h_to_hh(hdb)
    if data_off is not None:
        dbhandle_seen[hdb] = db_back
        name = dbs_by_backptr.get(db_back, '?')
        print(f"record @0x{off:05X} back=0x{backptr:08X} hDb=0x{hdb:04X} -> "
              f"db_data_off=0x{data_off:05X} db_backptr=0x{db_back:08X} name='{name}'")
    else:
        print(f"record @0x{off:05X} back=0x{backptr:08X} hDb=0x{hdb:04X} -> UNRESOLVED")

# Count which db each of 37 records points to
from collections import Counter
c = Counter(hdb for (_, _, _, hdb) in records)
print(f"\nRecord hDb distribution: {dict(c)}")
for hdb, count in c.items():
    _, dbb = h_to_hh(hdb)
    print(f"  hDb=0x{hdb:04X} → db_backptr=0x{dbb:08X} name='{dbs_by_backptr.get(dbb, '?')}' ({count} records)")
