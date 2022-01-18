import re

def parse_mem_value_text(val_text):
    return list(map(lambda x: int(x, 16), val_text.split(" ")))

# 112f: 12b6 1617 r 4 0x40094008:7c6e5ef4 7c7c7c7c f45e5e7c 5e7f5e5e 5e115f 5e000400 687f7f5e 5e5e405e 5e5e5e5e 1002a2a ff2a2a2a 2a2a2a7f 2a2a2a2a 2a2a2a2a 2a2a2a2a 2b1b2a2a 20050e00 ffff1900 5e5f78ff 97979797 2a2a2a2a 2a2a2a2a 2a3a2a2a
ram_regex = re.compile(r"([0-9a-f]+): ([0-9a-f]+) ([0-9a-f]+) ([rw]) ([\d]) (0x[0-9a-f]+)\:(.*)")
def parse_ram_line(line):
    event_id, pc, lr, mode, size, address, val_text = ram_regex.match(line).groups()

    address = int(address, 16)
    event_id = int(event_id, 16)
    size = int(size)
    pc = int(pc, 16)
    lr = int(lr, 16)

    return event_id, pc, lr, mode, size, address, val_text

# 112f: 12b6 1617 r 4 64 4 0x40094008:7c6e5ef4 7c7c7c7c f45e5e7c 5e7f5e5e 5e115f 5e000400 687f7f5e 5e5e405e 5e5e5e5e 1002a2a ff2a2a2a 2a2a2a7f 2a2a2a2a 2a2a2a2a 2a2a2a2a 2b1b2a2a 20050e00 ffff1900 5e5f78ff 97979797 2a2a2a2a 2a2a2a2a 2a3a2a2a
mmio_regex = re.compile(r"([0-9a-f]+): ([0-9a-f]+) ([0-9a-f]+) ([rw]) ([\d]) (\d+) (\d+) (0x[0-9a-f]+)\:(.*)")
def parse_mmio_line(line):
    event_id, pc, lr, mode, orig_access_size, access_fuzz_ind, num_consumed_fuzz_bytes, address, val_text = mmio_regex.match(line).groups()

    address = int(address, 16)
    event_id = int(event_id, 16)
    orig_access_size = int(orig_access_size)
    access_fuzz_ind = int(access_fuzz_ind)
    num_consumed_fuzz_bytes = int(num_consumed_fuzz_bytes)
    pc = int(pc, 16)
    lr = int(lr, 16)

    return event_id, pc, lr, mode, orig_access_size, access_fuzz_ind, num_consumed_fuzz_bytes, address, val_text

# 0000 11c4 0
bb_regex = re.compile(r"([0-9a-f]+) ([0-9a-f]+) ([0-9]+)")
def parse_bb_line(line):
    event_id, pc, cnt = bb_regex.match(line).groups()

    event_id = int(event_id, 16)
    pc = int(pc, 16)
    cnt = int(cnt)

    return event_id, pc, cnt

def parse_bbl_set_line(line):
    return int(line, 16)

def parse_mmio_set_line(line):
    pc, addr, mode = line.split(" ")
    return (int(pc, 16), int(addr, 16), mode[0])

def _parse_file(filename, line_parser):
    try:
        with open(filename, "r") as f:
            return [line_parser(line) for line in f.readlines() if line]
    except FileNotFoundError:
        return []

def parse_mmio_trace(filename):
    return _parse_file(filename, parse_mmio_line)

def parse_mem_trace(filename):
    return _parse_file(filename, parse_ram_line)

def parse_bbl_trace(filename):
    return _parse_file(filename, parse_bb_line)

def parse_bbl_set(filename):
    return _parse_file(filename, parse_bbl_set_line)

def parse_mmio_set(filename):
    return _parse_file(filename, parse_mmio_set_line)

def _dump_file(entries, filename, line_dumper):
    with open(filename, "w") as f:
        f.write("\n".join(map(lambda entries: line_dumper(*entries), entries)))
        f.flush()

def dump_mmio_line(event_id, pc, lr, mode, orig_access_size, fuzz_offset, consumed_fuzz_size, address, value):
    pl = "{:04x}: {:x} {:x} {} {:d} {:d} {:d} 0x{:08x}:{:x}".format(event_id, pc, lr, mode, orig_access_size, fuzz_offset, consumed_fuzz_size, address, value)
    return pl

def dump_mmio_access_context_set_line(pc, address, access_type):
    return "{:x} {:x} {}".format(pc, address, access_type)

def dump_ram_line(event_id, pc, lr, mode, size, address, values):
    pl = "{:04x}: {:x} {:x} {} {:d} 0x{:08x}:{:x}".format(event_id, pc, lr, mode, size, address, values[0])

    for value in values[1:]:
        pl += " {:x}".format(value)

    return pl

def dump_bbl_set_line(bb_addr):
    return "{:x}".format(bb_addr)

def dump_bbl_line(event_id, bb_addr, count):
    return "{:04x} {:x} {:d}".format(event_id, bb_addr, count)

def dump_bbl_set_file(entries, filename):
    _dump_file(entries, filename, dump_bbl_set_line)

def dump_bbl_trace_file(entries, filename):
    _dump_file(entries, filename, dump_bbl_line)

def dump_ram_trace_file(entries, filename):
    _dump_file(entries, filename, dump_ram_line)

def dump_mmio_trace_file(entries, filename):
    _dump_file(entries, filename, dump_mmio_line)

def dump_mmio_set_file(entries, filename):
    _dump_file(entries, filename, dump_mmio_access_context_set_line)