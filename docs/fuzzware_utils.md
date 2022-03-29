# Fuzzware Utilities

Here we go into some of Fuzzware's utilities. Note that some of this duplicates with the other READMEs and not all utilities are covered exhaustively. For help on the different components of fuzzware, use the `fuzzware -h` command.

Running fuzzware typically means running the pipeline component (command `"fuzzware pipeline"` in a configured directory) which performs the job of fuzzing, looking at interesting traces and updating the emulator (with MMIO models) on the fly. Fuzzware will create a `fuzzware-project` directory next to your firmware image containing all the data upon which it operates.

To make sense of pipeline results (contents of a `fuzzware-project` directory), additional fuzzware utilities are used. Manual tasks on pipeline results include finding input files which trigger certain behaviors (`fuzzware cov`), analyzing firmware behavior for a specific crashing or non-crashing input (`fuzzware replay`). These other utilities are introduced later in this document.

Before trying to run fuzzware, make sure that everything has been installed *and that you are in the correct virtualenv* in case you are using a local setup rather than in docker. When fuzzing is involved, also make sure your system is set up for afl to agree with its environment (as root, on host):
```
echo core >/proc/sys/kernel/core_pattern
cd /sys/devices/system/cpu
echo performance | tee cpu*/cpufreq/scaling_governor
```

When running fuzzware directly on a host system, make sure to also execute everything in a virtualenv:
```
workon fuzzware
```

## Starting the Pipeline
The pipeline is what you want to be using whenever you start fuzzing a firmware image as it automatically manages fuzzing and model generation for you. It will generate the configurations and inputs that you can use to perform manual triaging and troubleshooting.

For a properly configured firmware image and when within the installed `fuzzware` docker container or the `fuzzware` virtualenv on your locally installed system, you can get started by simply navigating to a correctly configured target directory in [the examples subdirectory](../examples) and starting the pipeline with default arguments:

Using Docker:
```
./run_docker.sh ./examples fuzzware pipeline ./pw-recovery/ARCH_PRO
```

On your local host setup:
```
workon fuzzware && fuzzware pipeline ./examples/pw-recovery/ARCH_PRO
```
This will create a `fuzzware-project` subdirectory and start the full pipeline which handles fuzzing, modeling and configuration migrations automatically. The fuzzing results will be written to `examples/pw-recovery/ARCH_PRO/fuzzware-project` in both of the above cases:

- `fuzzware-project/mainXXX`: Emulator configuration iterations
- `fuzzware-project/mainXXX/fuzzers/fuzzerY`: Fuzzer directory for the given configuration
- `fuzzware-project/mainXXX/fuzzers/fuzzerY/queue`: Fuzzer inputs
- `fuzzware-project/mainXXX/fuzzers/fuzzerY/traces`: Pipeline-generated compact traces (detailed traces can be generated manually using `fuzzware replay` or `fuzzware emu`)

For more information on the results stored in the `fuzzware-project` directory, refer to the pipeline's README [fuzzware-pipeline/README.md](https://github.com/fuzzware-fuzzer/fuzzware-pipeline/blob/main/README.md).

There are situations where you might want to use a sub-component in isolation. This may be the case for troubleshooting, debugging, crash triaging and during fuzzware development. For a full list of supported commands, use:
```
fuzzware -h
```

## Coverage Analysis
As a means to more easily find inputs which lead to particular coverage, the `fuzzware cov` utility finds an input which contains a given basic block or symbol in its trace. This can be used to find an input to use with `fuzzware replay`.

To find an input file within the current project that reaches the `main` function, use:
```
fuzzware cov main
```

For a full list of options:
```
fuzzware cov -h
```

## Replaying Emulation Runs
Once the pipeline has been running for a while, you may be interested in what is actually going on in the configurations and the inputs (and maybe crashes) that it generated.

`fuzzware replay` can be used to easily reproduce single emulation runs for a pipeline-residing input file. It is a wrapper around `fuzzware emu` which automatically locates the correct configuration file and command-line arguments for an emulator configuration iteration. It allows you to re-run the emulation of a given input as it was executed within a fuzzer instance. To help you with the correct invocation and to reduce verbosity when compared to the raw `fuzzware emu` interface, it translates trace- to corresponding input file paths and resolves numeric input ids.

To replay an input or an input corresponding to a trace file for the first configuration iteration, use:
```
# By an input file
fuzzware replay fuzzware-project/main001/fuzzers/fuzzer1/queue/id:000000*
# By a trace file
fuzzware replay fuzzware-project/main001/fuzzers/fuzzer1/traces/bblset_id:000000*
```

To replay an input based on its id (here, the first input id `000000` is used) of the latest configuration iteration, run from within the project base directory:
```
fuzzware replay 0
```
You can also replay an input by just giving its name and fuzzware will find the exact path for you, as long as the input file name is unique.

Finally, to save an extra invocation of `fuzzware cov` to find a suitable input file, you can also have fuzzware find an input path which covers a specific address or symbol and replay it automatically for you. To replay the first input file reaching the `main` function, use:
```
fuzzware replay --covering main
```

You can provide the same additional arguments to the `replay` command as you would to the `emu` command as shown previously. Note that for projects containing multiple fuzzer instances this may become ambiguous for numeric ids. In that case, fuzzware will complain and you will need to add arguments or navigate to a deeper working directory inside the project.

For all replay-supported options, use:
```
fuzzware replay -h
```

## Raw Emulation Runs
The following code snippets assume that your current working directory is the firmware target directory (for the `Getting Started` examples, this would be `examples/pw-recovery/ARCH_PRO`).

For additional debugging output for the initial input:
```
fuzzware emu -c fuzzware-project/main001/config.yml --debug -t -M fuzzware-project/main001/fuzzers/fuzzer1/queue/id:000000,*
```

Re-run a crashing input to triage the crash:
```
fuzzware emu -c fuzzware-project/main001/config.yml fuzzware-project/main001/fuzzers/fuzzer1/crashes/id:000000,sig:11,XXXXX
```

Setting a breakpoint on a crashing input:
```
fuzzware emu -c fuzzware-project/main001/config.yml --debug -t -M --breakpoint 0x12345678 fuzzware-project/main001/fuzzers/fuzzer1/crashes/id:000000,*
```

To generate trace files for further analysis:
```
fuzzware emu -c fuzzware-project/main001/config.yml --bb-trace-out=bb_trace.txt --mmio-trace-out=mmio_trace.txt --ram-trace-out=ram_trace.txt fuzzware-project/main001/fuzzers/fuzzer1/crashes/id:000000,sig:11,XXXXX
```

For all emulator-supported options, use:
```
fuzzware emu -h
```

## Raw Fuzzing
This is likely not what you want to be doing during regular fuzzing (use `fuzzware pipeline` instead!), as no MMIO access modeling is performed and you are unable to make use of boot guidance by configuration (which is implemented by the pipeline component by inspecting traces and configuring the fuzzers to start from a valid booted state once one is found according to the configured specification).

That said, if you are confident in a configuration that you built or the pipeline built for you over time and which you are sure will not be updated anymore, you can also run a standalone fuzzer without modeling or other pipeline features.

You can run a standalone fuzzer (make sure you are in the correct virtualenv in local setups) in the following way:
```
# in a local setup: workon fuzzware
cd examples/pw-recovery/ARCH_PRO
fuzzware fuzz afl-output-dir
```

For a full list of options:
```
fuzzware fuzz -h
```

## Generating Statistics

To aggregate data on a given `fuzzware-project` directory, we can use `fuzzware genstats` to generate matrics about code coverage, how much time was spent on different types of pipeline jobs, the fuzzing input consumption of different MMIO models, and on the contexts in which crashes occured:

For a full list of options:
```
fuzzware genstats -h
```

## Generating Traces

By default, the pipeline component only generates set-based traces which are quick to compute and storage-light. However, Fuzzware's emulation component is also able to generate full traces. While taking longer to compute and taking up more disk space, these traces contain a full list of sequential trace events and can be parsed automatically. Generating such traces could be interesting for manually looking into firmware behavior or for scripting some trace-based analysis.

For a full list of options:
```
fuzzware gentraces -h
```