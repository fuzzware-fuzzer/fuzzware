# Documentation Files
The following files are meant to give you additional insight into how to use and deal with different stages of the Fuzzware workflow.

| File | Description |
| ---- | ----------- |
| [target_configuration.md](target_configuration.md) | Tipps on creating an initial config and most importantly, refining an existing configuration to get the most out of your fuzzing cycles |
| [coverage_analysis.md](coverage_analysis.md) | Given a `fuzzware-project` directory, figure out how the fuzzer is doing and where/why it gets stuck. |
| [crash_analysis.md](crash_analysis.md) | Checking for crashes, bucketing them, and analyzing their root cause. |
| [fuzzware_utils.md](fuzzware_utils.md) | An overview of some of the (other) Fuzzware tools and when they could be useful |
| [manipulating_inputs.md](manipulating_inputs.md) | How to understand and manipulate inputs on your own, if you really need to |
| [fuzzware-emulator/README_config.yml](https://github.com/fuzzware-fuzzer/fuzzware-emulator/blob/main/README_config.yml) | A pretty detailed (even if maybe not quite definitive) description of the config.yml syntax and supported options. |
| [fuzzware-pipeline/README.md](https://github.com/fuzzware-fuzzer/fuzzware-pipeline/blob/main/README_pipeline_architecture.md) | An overview of the how the pipeline component is implented. |

As always, you don't necessarily need to treat the code itself as a black box. Feel free to also check out the emulator- as well as the pipeline source code itself.