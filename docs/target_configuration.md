# Configuring a Firmware Sample

After building a firmware sample, we need to set it up for fuzzing initially. After some time fuzzing, analyzing coverage and the target's code itself, we may also revise the configuration and optimize it for optimal fuzzing performance.

In general, while many of the following configuration options are not strictly required to fuzz test a sample, stacking as many configurations as possible for a given target will improve fuzzing performance significantly. In the end, the more firmware-specific quirks and overhead we can get rid of, the more we can focus the fuzzer on the functionality we are interested in. This will translate into the firmware behaving more and more like an ordinary command-line tool under test, making the fuzzer all the more effective in a practical setting.

There are some configuration options which are not discussed here. Also refer to [fuzzware-emulator/README_config.yml](https://github.com/fuzzware-fuzzer/fuzzware-emulator/blob/main/README_config.yml) for additional options (and if you are really interested, the [code implementing the configuration parsing](https://github.com/fuzzware-fuzzer/fuzzware-emulator/blob/main/harness/fuzzware_harness/harness.py) in the emulator to make sure we did not miss anything important).

# Automated Configuration: fuzzware genconfig
To configure a firmware image, the `fuzzware genconfig` utility might be a good starting point. This will generate a configuration file with a best-effort memory map (for ELF files this will be derived from ELF sections and Cortex-M standard memory ranges) and run sample inputs to detect very early crashes in an effort to identify and configure custom MMIO ranges. **CAUTION: Do NOT use this generated configuration without manually verifying it. While the utility may work well for some cases, it will fail in others.**

One specific thing to watch out for here is memory ranges named in the following pattern: `dynamically_added_crash_region_*`. This shows that Fuzzware encountered very early crashes of the firmware images which it expected to contain custom MMIO ranges. While this may be the correct behavior, this region is not marked as an MMIO region (its name does not start with `mmio`) and accesses to it will not be fed fuzzing input, making it a RAM-like region. Verify such regions and see whether the assigned region signifies any errors in the configuration, and if the region is legitimate, decide whether this region should be an MMIO region. If it should be an MMIO region, rename it to be prefixed by `mmio`. Encountering such a region may also indicate a variety of different issues, such as that you are missing some ROM contents (like ROM code or factory-preset identification/hardware revision values), or that you are facing an aliased region of the main code flash.

# Manual Base Config
As also indicated in the [top-level README](../README.md), we can also create a configuration manually:

Find a detailed overview of configuration options in [fuzzware-emulator/README_config.yml](https://github.com/fuzzware-fuzzer/fuzzware-emulator/blob/main/README_config.yml).

At minimum, you will need a bare-metal firmware blob and know where it is located in memory. With this, you can setup a memory map. For a firmware blob `fw.bin` located at address `0x08000000` in ROM, a config located in a newly created `examples/my-fw` directory would look like this:
```
include:
    - ../configs/hw/cortexm_memory.yml
    # For optional interrupts
    - ./../configs/fuzzing/round_robin_interrupts.yml

memory_map:
    rom: 
        base_addr: 0x08000000
        size: 0x800000
        permissions: r-x
        file: ./fw.bin
```

# Optimizing Interrupt Behavior

A default, catch-all interrupt behavior is just raising one interrupt every 1000 basic blocks in a round-robin fashion. Refer to [fuzzware-emulator/README_config.yml](https://github.com/fuzzware-fuzzer/fuzzware-emulator/blob/main/README_config.yml) on the exact ways of how interrupts can be configured.

Depending on the architecture of your target code and the amount of knowledge you possess on it, you may apply more specific interrupt configurations, such as raising a specific interrupt when visiting a specific basic block, or letting the fuzzer decide based on fuzzing input which interrupt to trigger, instead of triggering all interrupt in a round-robin manner. Using fuzzing input to let the fuzzer decide about which interrupt to trigger leads to a tradeoff: On the one hand, it provides the fuzzer with more flexibility, but on the other hand it also forces more fuzzing input to be consumed.

You can also disable a given interrupt in case you know it is either irrelevant to what you want to fuzz, or it is actively harming firmware execution (such as a triggering watchdog timer). You can do this via the `disabled_irqs` configuration (again, refer to [fuzzware-emulator/README_config.yml](https://github.com/fuzzware-fuzzer/fuzzware-emulator/blob/main/README_config.yml) for details).

For an example of how we used triggering interrupts at the target OS'es idle loop, refer to the [fuzzware-experiment repo's CVE firmware setup](https://github.com/fuzzware-fuzzer/fuzzware-experiments/blob/main/03-fuzzing-new-targets/zephyr-os/building/base_configs/zephyr_default.yml).

# Optimizing Fuzzer Performance

## Shortcutting Function Execution
To optimize the fuzzer's performance, we want to maximize the time in which the fuzzer does meaningful things. This includes removing typical cycle-consuming fuzzing roadblocks (such as busy `delay` loops) and maybe avoiding the execution of output functions. We can do this via empty function hooks in the `handlers` config of `config.yml`:

```
handlers:
    # full config without implicit values
    delay:
        # address or symbol of the delay function
        addr: 0x123
        # this is the default value, but set in here for reference
        do_return: true
        # this is the default value, but set in here for reference
        handler: null
```

This will make Fuzzware inject a return instruction at the start of the `delay` function.

Making use of default assignments, this configuration can be shortened to the following:
```
handlers:
    # if no `addr` field is given, the name is used as a symbol
    delay:
```

Similar functions which you might want to cut short are things like sleeping, logging, unrelated initialization functionality, and the like.

The emulator also has limited support for built-in binary patching ways of assigning a return value while shortcutting function execution:
```
handlers:
    # Return 0
    my_useless_initialization_function_requiring_zero:
        handler: native.return_0x0
    # Return 1
    my_useless_initialization_function_requiring_nonzero:
        handler: native.return_0x1
    # And welcome to the dark side...
    my_useless_initialization_function_requiring_binary_patch:
        # manually patching "bx lr" as byte patch
        handler: native.inline_asm_7047
```

For examples of how we used this type of configuration to save CPU cycles while discovering the CVE's of the paper, refer to the [fuzzware-experiment repo's CVE firmware setup](https://github.com/fuzzware-fuzzer/fuzzware-experiments/blob/main/03-fuzzing-new-targets/zephyr-os/building/base_configs/zephyr_skips.yml) and its [crashing POC inputs](https://github.com/fuzzware-fuzzer/fuzzware-experiments/blob/main/03-fuzzing-new-targets/zephyr-os/prebuilt_samples/CVE-2021-3329/POC)

## Early Emulation Run Exits

In case we are (no longer) interested in executing things like error functions, we can manually configure the emulator to exit once specific basic blocks are visited. This is interesting for functions which catch errors, signify assertions, or attempt to reset the system:

```
exit_at:
    assert:
    my_non_existant_symbol: 0x12345
```

Again the philosophy here is that if we can avoid exiting specific functionality which we know not to be interested in, we can save precious CPU cycles, keep the fuzzer's attention away from useless code and keep it focussed on other functionality.

For examples of how we used this type of configuration to save CPU cycles while discovering the CVE's of the paper, refer to the [fuzzware-experiment repo's CVE firmware setup](https://github.com/fuzzware-fuzzer/fuzzware-experiments/blob/main/03-fuzzing-new-targets/zephyr-os/building/base_configs/zephyr_exits.yml) and its [crashing POC inputs](https://github.com/fuzzware-fuzzer/fuzzware-experiments/blob/main/03-fuzzing-new-targets/zephyr-os/prebuilt_samples/CVE-2021-3329/POC)

## Configuring the Boot Process

For some firmware samples, booting the firmware itself may be a complex process. In this case, we may want the fuzzer to find a valid booted state and afterwards just continue fuzzing from there. While entirely optional, supplying a valid boot configuration has two advantages:

1. Focus the fuzzer on actual input processing instead of finding different invalid boot sequences after a valid boot sequence has been found, which increases meaningful mutations.
2. Avoid re-running the boot process on every emulation run, which increases test case throughput / emulator performance.

Specifying a successful boot process can be achieved using a `boot` configuration in `config.yml`. We can define a valid boot state by specifying a set of basic blocks that need to be visited (basic block addresses which signal the success case of a given initialization function), as well as a set of basic blocks to avoid (code locations which indicate an initialization failure):

```
# Description of a successful boot process of the firmware image
boot:
  # A list of addresses required for a successful boot
  required:
    # An address (or symbol) in this list may indicate the if/else branch of a positive check
    - 0x0800052A
    # Or a function which activates a peripheral which is only called in case all checks were successful
    - activate_uart_peripheral
  # A list of addresses which indicate a failed boot
  avoid:
    # if/else branch of a failed check
    - 0x08000518
    # an error output function logging an error condition
    - log_error
  # Address at which the firmware is considered booted (successfully or unsuccessfully based on the previous config attributes)
  target: idle
```

The above is an extract from the configuration README in [fuzzware-emulator/README_config.yml](https://github.com/fuzzware-fuzzer/fuzzware-emulator/blob/main/README_config.yml).

This configuration is picked up by `fuzzware pipeline` which checks each new basic block coverage trace to identify a successfully booting input. After identifying such an input, it will then configure it as a prefix input with the emulator for all coming configuration iterations. This essentially sets a snapshot to start at with the emulator, such that emulation in the fuzzer will always start at the configured `target` location automatically.

# Manually Adjusting MMIO Models

This is a rather finicky option, but there may be situations where we find "useless" MMIO accesses to consume a lot of fuzzing input. In these situations we may want to get rid of the accesses by forcing an MMIO register to behave in a specific way that does not involve fuzzing input. The reason for MMIO modeling to assign a non-restrictive model may be manifold: The code may - in theory - differentiate between a whole range of options or the MMIO value is assigned to a global variable which might - in theory - be accessed later in firmware code. These reasons add uncertainty to the modeling mechanism, which makes it conservatively assign a non-restrictive model in some cases.

Assigning a fixed value to an MMIO read may restrict the firmware state space, which is bad in many cases (which is why MMIO modeling will not assign an overly restrictive model). However, being overly restrictive may be exactly what we want in specific situations. For example, this is true in case we know that always making firmware take a specific path helps the fuzzer achieve better coverage in a part of firmware code we care about. So we may as well assign a fixed value that makes firmware always take the code path we care about.

While this a bit of an expensive operation upfront (as a lot of full, non-native traces need to be generated), the `fuzzware genstats mmio-overhead-elim` utility can help you figure out which MMIO accesses consume most of the fuzzing input:

```
fuzzware genstats mmio-overhead-elim
```

This produces a yaml file `fuzzware-project/stats/mmio_overhead_elimination.yml` which contains data about fuzzing input consumption per MMIO model. Most importantly (in this use case), it also shows which models consume the largest amounts of data. These models may be worth checking out manually to make sure that they are actually meaningful to fuzzing progress. Having the fuzzer mutate meaningless inputs most of the time will not help it discover meaningful firmware behavior. In case a highly-used MMIO model is not actually contributing to code coverage, we may want to manually configure this MMIO access to be modeled in a restrictive way (for example, by assigning a `constant` model to the respective pc/mmio_addr access context).

The entry to search for within `fuzzware-project/stats/mmio_overhead_elimination.yml` is the `per_access_context` member with context entries that have a large `bytes_fuzzing_input` value assigned. After figuring out a fitting model type, you may manually assign an MMIO model according to [fuzzware-emulator/README_config.yml](https://github.com/fuzzware-fuzzer/fuzzware-emulator/blob/main/README_config.yml). Upon start, the pipeline will take these custom MMIO model configs into account and regard them as definitive, meaning that it will not compute its own model for it.
