# Manipulating Inputs

Quite frankly, manually manipulating inputs is not well supported by Fuzzware tooling at the time of writing, and as a consequence, it is very finicky. With that said, let us know if you would like to tinker in this direction and build proper input patching tooling!

An input to Fuzzware's emulator is basically a sequence of bytes which get consumed on-demand as firmware is executed. As the emulator behaves the same for a given input on every run, we can replay it to reproduce a given behavior. However, we do not know upfront how the bytes within the input file correspond to MMIO reads during firmware emulation.

## Generating an MMIO Trace
To figure out the mapping between input byte and MMIO read, we need to first generate an MMIO trace:

```
fuzzware emu --mmio-trace-out=mmio_trace.txt <path_to_input>
```

## Understanding the MMIO Trace

The resulting MMIO trace file `mmio_trace.txt` contains one entry for each MMIO access (read and write) that was performed during the emulation run for the given input file. Each line has the following structure:

```
# event_id, pc, lr, mode, orig_access_size, access_fuzz_ind, num_consumed_fuzz_bytes, address, val_text
```

As an example (taken from the `ARCH_PRO` target):

```
009e: e98 641 r 1 118 0 0x4000c014:1
009f: ea4 641 r 1 118 1 0x4000c000:43
00a0: e98 641 r 1 119 0 0x4000c014:1
```

The first line is interpreted in the following way: At `pc` address `0xe98` at which point `lr` had value `0x641`, a `read` operation on address `0x4000c014` was performed. The mmio access had a size of `1`, and the fuzzing input cursor was at position `118` (decimal) into the input file. For this MMIO access, no input was consumed (`0` bytes of fuzzing bytes consumed), and the value `1` got returned for the read.

Referring back to the MMIO model for this access, we find:
```
mmio_models:
  constant:
    pc_00000e98_mmio_4000c014:
      access_size: 0x1
      addr: 0x4000c014
      pc: 0xe98
      val: 0x1
```

This corresponds to what we would expect: Accesses from `pc=0xe98` to MMIO address `0x4000c014` return a constant value of `1`.

Looking at the second MMIO access, we find: At `pc` address `0xea4` at which point `lr` had value `0x641`, a `read` operation on address `0x4000c000` was performed. The mmio access had a size of `1`, and the fuzzing input cursor was at position `118` (decimal) into the input file. For this MMIO access, one byte of input was consumed, and the value `0x43` got returned for the read.

Once again, referring back to the MMIO model configuration, we find a model which fits the trace entry (`unmodeled ("identity model" in paper speech)` means consuming as much input as was requested):
```
  unmodeled:
    pc_00000ea4_mmio_4000c000:
      access_size: 0x1
      addr: 0x4000c000
      pc: 0xea4
```

From this excerpt of the input file, we see that byte `118` within the input file is returned for an access to address `0x4000c000` from `pc=0xea4`. Looking into what this corresponds in firmware code we find that this actually represents a serial input character.

## Patching the Input File

Based on this knowledge, we can now start patching input bytes at known offsets within the binary input file to change what values are read.

You can make sure by re-running the input in the emulator that the change you performed actually had the desired effect:

```
fuzzware emu --mmio-trace-out=mmio_trace_patched.txt <input_patched>
```

Diffing the two traces should now show that the given MMIO access changed according to your prediction.