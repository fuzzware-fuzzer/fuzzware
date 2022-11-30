# Triaging Crashes in Fuzzware

You set up a firmware image to fuzz test and were able to find crashes (these are located in `fuzzware-project/mainXXX/fuzzers/fuzzerY/crashes/id*`).

Here we want to talk about what nature of crashes to expect and how to make sense of a crashing input.

To find out about whether you found crashes, you can simply use bash:
```
ls fuzzware-project/main*/fuzzers/fuzzer*/crashes/id*
```

... or use the Fuzzware `genstats` util:
```
fuzzware genstats crashcontexts
```

# Types of Crashes to Expect

Due to the nature of how Fuzzware operates, triggering crashes does not need to mean that this represents a security issue. We experienced different types of crashes.

The first category of crashes stems from incomplete configurations and hardware behavior which cannot be caught by Fuzzware:

1. Crashes due to **memory mis-configuration**: It is possible that the board your target expects to run on has some custom MMIO region, for example a version information ROM / device ID page filled in the factory, or a vendor-specific device. These crashes typically occur very early on. These crashes can be remediated by updating your configuration and re-running the pipeline.
2. Crashes due to **broken assumptions about hardware behavior**: The hardware which the firmware code expects to interact with may have certain restrictions, such as upper bounds on the size of a radio frame. In these cases, firmware code may omit a size check as it *knows* as specific value to be bounded to a certain value. A prime example of this is a radio frame which is known to have its size limited to a maximum of `128`, but where a full byte is used as a size variable. Firmware code may use a full byte as a size variable and copy frame contents into a fixed-size buffer of `128` bytes. Fuzzware will not see this implicit assumptions (as checks in firmware code are missing) and at some point provide a size value of `128-255`, which will likely crash the firmware. In this case: Congratz, you have found the firmware not to behave correctly under a malicious device (which you consider a bug). However, as your attacker model probably does not include tinkering with hardware, you will have to make sure via code or configuration changes that the bounds are adhered to by Fuzzware.
3. Crashes due to **custom hardware behavior**: Fuzzware does not emulate peripheral state, and does not react to writes to MMIO regions. Firmware code, on the other hand, may make implicit assumptions about what its previous MMIO writes mean to a real device, e.g. about its interrupt behavior: While a given interrupt is enabled in the interrupt controller (NVIC), it may be disabled implicitly by the firmware by writing a certain value to an MMIO register of a peripheral. Fuzzware is unaware of such semantics: While raising interrupts, Fuzzware only considers the state of the interrupt controller, and raises any interrupt which has been activated in the interrupt controller itself. This is regardless of other custom contracts that firmware and hardware implicitly share, but Fuzzware does not know about (e.g., a custom enable/disable register for certain interrupts). This may lead to Fuzzware raising interrupts at unexpected times. This in turn might lead to a crash. Similarly, the firmware writing pointers to an MMIO register may assume a pointer to be read back in case the MMIO register is read later. Fuzzware's MMIO modeling is unable to catch this due to its local nature. While reading back the supposed pointer, firmware will consequently interpret fuzzing input as a pointer value, again resulting in a crash. Depending on the situation, you will need to make sure such conditions are not the reason for a crash, or configure your way around them manually.

The second category of crashes occurs during the initialization phase of firmware:

1. Crashes due to **improper handling of initialization errors**: Firmware developers may get away with not handling errors during the initialization thoroughly. This is because these failures happen infrequently in practice, and a device reset may solve the problem in a practical setting. However, the fuzzer will trigger all types of error conditions. In principle, this is good, especially when error conditions can be exploited by an attacker. However, having these error cases draw too much fuzzer attention can obstruct targeting legitimate functionality. So it is not uncommon for you to have to first make a firmware image robust enough so that you can reach deeper legitimate functionality to uncover bugs there. Here, you will want to iteratively fix initialization issues, either via configuration (e.g., setting `exit_at` configurations to make error cases less interesting or using a `boot` config), or by fixing such error in firmware code.

The third category of crashes is what we are typically most interested in. You may entirely skip the first two types of crashes for your own firmware image and configurations, but this will not always be true. When you are at this point, you will find:

1. Crashes due to **security-relevant bugs**: At this point you most likely found that the fuzzer is reaching some type of input processing function with fuzzer-controlled data and code coverage a bit deeper into input processing. A sign of a good bug in practice has been that the crash does not occur immediately. Here things become interesting from a remote attacker's security research perspective.

# Initial Crash Bucketing

As previously indicated, as a first step, we can identify whether there are any crashes by looking inside `fuzzware-project/mainXXX/fuzzers/fuzzerY/crashes/id*` within a project directory.

When crashes are present, we can use the Fuzzware `genstats` utility to pre-sort crashes.
```
fuzzware genstats crashcontexts
```
This will place a text file at `fuzzware-project/stats/crash_contexts.txt` which re-runs and buckets the inputs by `pc` / `lr` context. While neither means that crashes with the same context have the same root cause, nor that crashes with different crash contexts stem from different bugs, we can get an initial assessment of the variety of crashes and more easily pick representative inputs which stand out.

# Crash Coverage Search

We can search crashes by filtering their coverage via the `fuzzware cov --crashes` utility:
```
fuzzware cov --crashes <my_vuln_function>
```

In case we expect or found a root cause already, we may also want to find out whether there are crashing inputs that do not trigger certain coverage to find alternative crashes that might have a different root cause:

```
fuzzware cov --crashes --exclude <my_suspected_vuln>
```

# Analyzing a Specific Crashing Input

## Debug Log-Based Crash Analysis
To figure out what is going on for a given crashing input, we can replay that input with a set of diagnostic emulator arguments. Useful arguments include `-v` (printing the exit reason and final register state), `-t` (which prints function names for better orientation), and `-M` (which prints visited basic blocks and memory accesses to stdout).

```
fuzzware replay -M -t <path_to_crashing_input> > crash_log.txt
```

From here, we can analyze the crash location and memory writes, and hopefully track the issue back to its original corruption.

## Interactive Crash Analysis

We can also set breakpoints on a particular basic block (CAUTION: debugging currently works based on basic block hooks, so breakpoints at an instruction within a basic block will **not trigger**) function of interest and get dropped into a python shell with access to the unicorn object (the `uc` variable):

```
fuzzware replay <path_to_crashing_input> -b <my_basic_block_addr_or_symbol> 
```

When arriving at a breakpoint, we can look around by inspecting the register state as well as memory contents:
```
uc.regs
uc.regs.r0
uc.mem.u32(<addr>, <number_of_dwords>)
```

For example, to print the source buffer of a memcpy (assuming we configured `memcpy` as a symbol), we would do:
```
fuzzware replay <path_to_crashing_input> -b memcpy

uc.mem.u8(uc.regs.r1, uc.regs.r2)
```


## Configuring Target-Specific Debug Trace Hooks
If we suspect that an issue lies with a specific piece of functionality or API function, we can manually add tracing hooks to the target configuration. Fuzzware comes with some generic debug hooks to achieve this:

- `fuzzware_harness.user_hooks.generic.stdio.puts`
- `fuzzware_harness.user_hooks.generic.stdio.printf`
- `fuzzware_harness.user_hooks.debug.print_args_0`
- `fuzzware_harness.user_hooks.debug.print_args_1`
- `fuzzware_harness.user_hooks.debug.print_args_2`
- `fuzzware_harness.user_hooks.debug.print_args_3`

Taking an example for zephyr-os race conditions, we might want to monitor the three semaphore APIs `z_impl_k_sem_init`, `z_impl_k_sem_take`, and `z_impl_k_sem_give`.

```
handlers:
  z_impl_k_sem_init:
    do_return: false
    handler: fuzzware_harness.user_hooks.debug.print_args_3
  z_impl_k_sem_take:
    do_return: false
    handler: fuzzware_harness.user_hooks.debug.print_args_1
  z_impl_k_sem_give:
    do_return: false
    handler: fuzzware_harness.user_hooks.debug.print_args_1
```

**NOTE: Make sure to copy and modify the config.yml from the mainXXX directory that the given inputs belongs to. Otherwise, MMIO models will be missing/mismatching and the run will not replay as expected. For example, for the third main directory, create a backup and modify fuzzware-project/main003/config.yml. Once outside the fuzzware-project directory, you will also need to use the plain "fuzzware emu" utility instead of the "fuzzware replay" utility to run inputs for the given configuration.**

As an example, please refer to the [crashing POC of CVE-2021-3329](https://github.com/fuzzware-fuzzer/fuzzware-experiments/blob/main/03-fuzzing-new-targets/zephyr-os/prebuilt_samples/CVE-2021-3329/POC/config.yml) to see how these hooks can make understanding a given crash significantly simpler.

Also, for an example of a set of generic debug print hooks (do not use in the fuzzing configuration itself!), refer to [zephyr_debug_snippets.yml](https://github.com/fuzzware-fuzzer/fuzzware-experiments/blob/main/03-fuzzing-new-targets/zephyr-os/building/base_configs/zephyr_debug_snippets.yml) within the fuzzware-experiments repo.

## Scripting A Trace Analysis

Caution: This is not much of an actively used way for analyzing crashes, but making you aware of the possibility may be worth mentioning to the interested reader. It may also allow you get started on building some crash analysis tooling. In case you do build such tooling, make sure to let us know about it!

In case you prefer to write scripts to analyze traces, fuzzware provides some trace dumping and parsing utilities. For example, in case you would like to analyze a memory read/write trace, you could use:

```
fuzzware replay --ram-trace-out=ram_trace.txt <path_to_crashing_input>
```

And then parse this trace using a Python script (within the `fuzzware venv`):

```
from fuzzware_harness.tracing.serialization.parse_mem_trace

for event_id, pc, lr, mode, size, address, val_text in parse_mem_trace("ram_trace.txt"):
    # Perform some analysis here
    pass
```
