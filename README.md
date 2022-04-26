# Fuzzware
<p><a href="https://www.usenix.org/system/files/sec22summer_scharnowski.pdf"><img alt="Fuzzware thumbnail" align="right" width="200" src="https://user-images.githubusercontent.com/18148299/150141920-3f054255-2b73-41d2-aa11-27a1e42f5302.png"></a></p>

Fuzzware is a project for automated, self-configuring fuzzing of firmware images.

The idea of this project is to configure the memory ranges of an ARM Cortex-M3 / M4 firmware image, and start emulating / fuzzing the target without full device emulation. Fuzzware will figure out how MMIO values are used, configure models, and involve the fuzzer to provide hardware behavior which is not fully covered by MMIO models.

Our [paper](https://www.usenix.org/system/files/sec22summer_scharnowski.pdf) from USENIX Security '22 explains the system in more detail. For a demo, check out our [screen cast](https://asciinema.org/a/490160). 

The [fuzzware-experiments repository](https://github.com/fuzzware-fuzzer/fuzzware-experiments) contains the data sets, scripts, and documentation required to replicate our experiments.

## Quick Start
First install:
```
./build_docker.sh
```

Then run:
```
./run_docker.sh examples fuzzware pipeline --skip-afl-cpufreq pw-recovery/ARCH_PRO
```

## Repo Organization and Documents
Directories within this repository. For the experiments in our paper, as well as submodules.
| Directory | Description |
| --------- | ----------- |
| [docs](docs) | Documentation files (config optimizations, cov analysis, crash analysis). |
| [examples](examples) | Target firmware samples to test Fuzzware on. |
| [fuzzware-emulator](https://github.com/fuzzware-fuzzer/fuzzware-emulator) | The emulator which performs runs of a firmware for a given input file. |
| [modeling](modeling) | MMIO modeling (based on angr). |
| [fuzzware-pipeline](https://github.com/fuzzware-fuzzer/fuzzware-pipeline) | Orchestration between MMIO modeling and emulator. |
| [scripts](scripts) | Some helper scripts (e.g., gather basic blocks in IDB). |
| [fuzzware-experiments](https://github.com/fuzzware-fuzzer/fuzzware-experiments) | Pre-built images/config, crashing POCs/analyses, build scripts to re-run our experiments. |

To not let this document explode, we provide specific documentation in different places:

1. Firmware targets, build scripts, example crash analyses: [the fuzzware-experiments repo](https://github.com/fuzzware-fuzzer/fuzzware-experiments)
2. Fuzzware utilities documentation: `$ fuzzware -h`, and `$ fuzzware <util_name> -h`
3. Firmware configuration file format details: [fuzzware-emulator/README_config.yml](https://github.com/fuzzware-fuzzer/fuzzware-emulator/blob/main/README_config.yml)
4. Fuzzware project result directory structure: [fuzzware-pipeline/README.md](https://github.com/fuzzware-fuzzer/fuzzware-pipeline/blob/main/README.md)

## The Idea
At its core, Fuzzware works by plugging an instruction set emulator (currently: Unicorn Engine) to
a fuzzer (currently: afl / AFL++) and having the fuzzer supply inputs for all hardware accesses. Whenever hardware in Memory-Mapped (MMIO) registers is accessed, the value is served from fuzzing input.

"The fuzzer has no idea about how the hardware it is emulating is supposed to behave, so how can anything useful come out of this?" You might ask. There are different components to this:
1. Coverage feedback: While the fuzzer does not know anything about the hardware, it can try different inputs and see how the firmware code reacts to it - whatever inputs trigger meaningful firmware code coverage are likely to represent expected hardware behavior. The fuzzer can chase this code coverage by trial-and-error.
2. MMIO Access Modeling: Firmware typically performs a variety of hardware (MMIO) accesses. Many of those accesses are for status checking and housekeeping purposes. It turns out that a lot of those accesses are not meaningful to the overall firmware logic. This means a majority of **MMIO accesses can either be eliminated or condensed automatically**. Any MMIO access modeled this way takes away the need for the fuzzer to guess about hardware behavior.
3. Custom Configurations: The user can supply different pieces of optional configuration to modify firmware behavior (skip or replace logic with custom handlers, define when and which interrupts to trigger) and to guide the emulation to sane firmware states (by describing mandatory checkpoints and error functions to avoid during the boot process). This can focus fuzzing on interesting functionality in case we have a human in the loop.

## Fuzzware Components
Fuzzware is comprised of different components:

1. [Pipeline Component (fuzzware-pipeline)](https://github.com/fuzzware-fuzzer/fuzzware-pipeline): Integrated fuzzing and modeling. The pipeline component represents the glue between emulation and modeling. As the fuzzer/emulator finds new MMIO accesses during runs, the corresponding firmware states need to be forwarded to modeling. Similarly, the updated MMIO configurations produced during modeling need to be made available to the emulator. The Pipeline automates this cycle: It lets the emulator run, and pushes jobs for modeling newly observed MMIO accesses. It subsequently updates emulation with new models. The pipeline also implements additional features such as identifying successfully booted firmware states which are then automatically used for further fuzzing.
2. [Emulation Component (fuzzware-emulator)](https://github.com/fuzzware-fuzzer/fuzzware-emulator): Standalone single-input emulation runs. This component allows emulating a firmware image with a provided configuration for a particular input file. It handles the re-routing of fuzzing inputs to answer MMIO accesses as well as triggering interrupts and creating traces as well as state files for further processing. It also provides integration with a fuzzer (an AFL forkserver) for repeated emulation runs with different inputs.
3. [Modeling Component (/modeling)](modeling): Standalone modeling. This component generates MMIO access models for states exported by the emulation component. It does so by performing symbolic execution and analyzing what is happening to the accessed MMIO values. It outputs configuration snippets which can be fed back to the emulation component for improved emulation.

For more information on the different components, please refer to the corresponding component subdirectories and READMEs.

# Installation
There are two out-of-the-box ways to go about using Fuzzware: Native and Docker-based setups. For local development of Fuzzware itself, you may prefer a local setup while for using it, Docker may be the way to go.

After one of the installation options has been successful, Fuzzware should be available (within docker or the `fuzzware` virtualenv):

```
fuzzware -h
```

## Fuzzware in Docker
To build as Docker container:
```
./build_docker.sh
```

A docker image `"fuzzware"` is built which contains all the necessary binaries and python modules. To start fuzzing and emulation, a directory can be mapped into the container which contains firmware images and configurations. To run:

```
./run_docker.sh <my/path/to/targets/repository> [/bin/bash]
```

## Fuzzware on Host
For a local setup, your system will have to have a list of local tooling installed to handle building unicorn, setting up virtual environments and finally running different pipeline components. You can see how to set those dependencies up in the [Docker file](dockerfile). Without installing all the dependencies first, different steps of the installation process will complain and you will be able to install them one by one.

To install locally:
```
./install_local.sh
```

The script will set up two Python virtualenvs:
1. `fuzzware`: The virtualenv containing the local pipeline and emulator modules. This also includes the `fuzzware` executable which exposes different parts of the system.
2. `fuzzware-modeling`: The virtualenv used for performing symbolic execution-based MMIO access modeling. You should not try installing this without a virtualenv as `angr` is one of its dependencies.

To use Fuzzware from here, simply use the `fuzzware` virtualenv.
```
workon fuzzware
```

# Configuring Firmware Images For Fuzzing
Find a detailed overview of configuration options in [fuzzware-emulator/README_config.yml](https://github.com/fuzzware-fuzzer/fuzzware-emulator/blob/main/README_config.yml) and more in-depth documentation in [docs/
target_configuration.md](docs/target_configuration.md).

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
Alternatively, you may also try out the experimental `fuzzware genconfig` utility which creates a basic configuration based on an elf file (extracts the binary from the ELF file, parses sections, and creates an initial memory config).

This will get your firmware image up and running initially. There are additional configuration options to set which are specific to a firmware image and can support hardware features such as DMA, increase performance / decrease MMIO overhead, guide the firmware boot process, focus the fuzzer on specific interrupts, add introspection and debug symbols.

An inline-documentation of firmware image configuration features can be found in [the config README of the emulator](https://github.com/fuzzware-fuzzer/fuzzware-emulator/blob/main/README_config.yml). These configuration options allow you to configure different aspects concerning:
- Interrupt raising (When? Which? How often?)
- Firmware Boot guidance (snapshot state after boot is successful)
- Symbols
- Custom input regions (e.g. to feed input whenever a static DMA buffer is accessed)
- Custom code hooks (function replacement, providing input, corruption detection)

# Fuzzware Workflow

Workflow for fellow academics:

1. Configure your target image (don't blindly trust `fuzzware genconfig`)
2. Fuzz target: `fuzzware pipeline --run-for 24:00:00`
3. Collect coverage statistics: `fuzzware genstats coverage`
4. Find your coverage info in `fuzzware-project/stats`

If you want to get the best out of Fuzzware (as a human in the loop), you should prefer the following steps:

1. Build or obtain the target firmware image
2. Configure basic memory ranges: Create config manually or use `fuzzware genconfig` (works best with elf files, still take the output with a grain of salt and verify manually!)
3. Fuzz the target: `fuzzware pipeline`
4. Check coverage: `fuzzware cov`, `fuzzware cov -o cov.txt` and `fuzzware cov <target_function>`, `fuzzware replay --covering <target_function>`
5. Adapt the configuration: [fuzzware-emulator/README_config.yml](https://github.com/fuzzware-fuzzer/fuzzware-emulator/blob/main/README_config.yml) and fuzz again. If the image requires a rebuild, go to step 1. If the config needs adaption, goto step 3.
6. Once you are reasonably sure that meaningful functionality is reached in the current setup, it might make sense to scale up cores: `fuzzware pipeline -n 16`.
7. Check for crashes: `fuzzware genstats crashcontexts`
8. Replay and analyze crashes: `fuzzware replay -M -t mainXXX/fuzzers/fuzzerY/crashes/idZZZ`

There is a range of fuzzware utilities which we created that you may find useful along the way. The utils and their command-line arguments are documented in `fuzzware` itself:
```
fuzzware -h
```

For additional descriptions of different steps of the workflow, also check out
- How to [optimize the config](docs/target_configuration.md).
- How to [analyze coverage progress](docs/coverage_analysis.md).
- How to [analyze crashes](docs/crash_analysis.md).

# Troubleshooting
## Issues with Workers
In case issues with worker processes are indicated by the pipeline, refer to the project's `fuzzware-project/logs` directory for information on what made the worker processes unhappy.

## Inotify Limits
If you are running the pipeline with a large number of fuzzing processes, inotify instance limits may be reached. In this case, run (as root, on the host):
```
scripts/set_inotify_limits.sh
```

## Missing Local Dependencies
In case things are missing in your local setup, refer to [the dockerfile](dockerfile) to figure out which package you might have missed or use a docker setup.

## Too Recent Python Version (>=3.10)
We based our MMIO modeling component on angr version 8.19.10.30. We learned just before the publication of the prototype that this version of angr only supports Python versions lower than 3.10. We added a detection for this into the install scripts and let you install based on a previous version of Python using the environment variable `MODELING_VENV_PYTHON3`.

## Floating-Point Unit
As Fuzzware relies on Unicorn and unicorn does not support floating-point instructions, Cortex-M4f targets need to be compiled using a softfpu.

# Citing the Paper
In case you would like to cite Fuzzware, you may use the following BibTex entry:
```
@inproceedings {277252,
title = {Fuzzware: Using Precise {MMIO} Modeling for Effective Firmware Fuzzing},
booktitle = {31st USENIX Security Symposium (USENIX Security 22)},
year = {2022},
address = {Boston, MA},
url = {https://www.usenix.org/conference/usenixsecurity22/presentation/scharnowski},
publisher = {USENIX Association},
author={Scharnowski, Tobias and Bars, Nils and Schloegel, Moritz and Gustafson, Eric and Muench, Marius and Vigna, Giovanni and Kruegel, Christopher and Holz, Thorsten and Abbasi, Ali},
month = aug,
}
```

# Found Bugs? Let us know!
In case you found bugs using Fuzzware, feel free to let us know! :-)

# How to Contribute
As a researcher, time for coding is finite. This is why there are still TODOs which could make the Fuzzware implementation better (even if we had infinite time, there would always be more things to improve, of course). If you are interested, here are some sample projects to work on for hacking on Fuzzware:

1. **Upgrade angr version**: To make use of the newest features of angr and support Python in version >=3.10, we could upgrade the modeling code to use an up-to-date angr (while of course making sure that the angr APIs and its behavior have not changed in an unforseen way).
2. **Architecture Independence**: Currently, the Fuzzware code is rather tighly coupled with ARM / Cortex-M. We started uncoupling the modeling logic from the architecture (see [arch_specific](modeling/fuzzware_modeling/arch_specific)), but there is more work to be done to make Fuzzware applicable to other CPU architectures (e.g., ARM Cortex-R) or instruction set architectures (e.g., MIPS).
3. **CompCov**: Currently, Fuzzware does not make use of some AFL++ features such as compcov. This would be an opportunity to integrate some more such features into unicorn.
4. **Crash Analysis Tooling**: Currently, analyzing crashes is a largely manual task. However, Fuzzware contains code to generate and parse detailed traces, and to inject custom hooks during firmware emulation. Some more tooling based on traces and custom hooks could be created to easen the crash analysis process.
5. **Input Patching Tooling**: Currently, manually modifying existing inputs is a manual task and involves manually interpreting MMIO trace files to match file contents to MMIO accesses. With proper tooling, modifying inputs could be made much more convenient, making it practical to manually create seed inputs which trigger important coverage, or more easily craft a proof-of-concept exploit from a given crashing input. These could then be used as a starting point for the fuzzer.
6. **Refactoring**: When looking through the code you will certainly find grown pieces of code which could make use of cleanup and larger refactoring. To make your search easy, one such place is [naming_conventions.py](https://github.com/fuzzware-fuzzer/fuzzware-pipeline/blob/main/fuzzware_pipeline/naming_conventions.py). Prior to publication, we did some cleanup, but also dedicated extra time to adding more tooling functionality in the hopes that it makes Fuzzware more easy for people to use and get into, without having to use some of the bash ugliness that you get away with as the author of a tool. As coding time is limited for us, we appreciate any community efforts in making the code better.
