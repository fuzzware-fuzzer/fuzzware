# Analyzing Code Coverage

After freshly configuring a firmware image and fuzzing it, we are naturally interested in how the fuzzer is doing. Fuzzware provides the `fuzzware cov` utility to analyze code coverage over a given `fuzzware-project` directory. There are different levels of detail in which we want to gather information about the current coverage and we give some examples of how to use `fuzzware cov` command-line arguments to achieve different goals.

## Coverage Overview

To get an overview on coverage on stdout, we can simply use `fuzzware cov` without arguments.

```
fuzzware cov
```

This will print information on covered and non-covered functions and basic blocks to stdout.

For a machine-readable coverage format, we can also dump a file:

```
fuzzware cov --out cov.txt
```

This will dump a list of the covered basic blocks in hexadecimal ascii format to `cov.txt`. We can import this file in a coverage visualization such as [lighthouse](https://github.com/gaasedelen/lighthouse) (for IDA) or [dragondance](https://github.com/0ffffffffh/dragondance) (for Ghidra).

## Searching for Specific Coverage

It is likely that upon inspecting the coverage and looking at the firmware code ourselves, we are looking for inputs that actually cover a specific piece of functionality. To find an input that covers the `main` function, we can use:

```
fuzzware cov main
```

To cycle through some inputs, we can also use the `--skip-num` and `--num-matches` arguments to find multiple inputs that cover the functionality we are looking for.

We may also want to find some combination of coverage that we would like to find an input for. To achieve this, simply supply multiple symbols:

```
fuzzware cov my_init_function main
```

And if we identified some error cases (for example, in the firmware's initialization code), we may want to check whether there is an input which reaches certain functionality without previously viting another piece of code. This can be done using the `--exclude` argument:

```
fuzzware cov --exclude="my_init_failure_bb_1,my_init_failure_bb_2" my_init_function main
```

Which will try to find an input which leads to covering `my_init_function` and `main` without covering either `my_init_failure_bb_1` or `my_init_failure_bb_2`.

## Replaying Inputs

After we identified inputs which are worth investigating, we can re-run them in the emulator using the `fuzzware replay` utility (which accepts the same additional arguments as `fuzzware emu` does for extra debug output, setting breakpoints, generating traces, and the like. Refer to `fuzzware emu -h` for a full set of options).

```
fuzzware replay -t <path_to_input_file>
```

As a shortcut, the following also works to replay the first input that can be found which covers the `main` function:

```
fuzzware replay --covering main
```

From here, understanding the behavior of a given input works in the same way as understanding crashing inputs. Refer to [crash_analysis.md](crash_analysis.md) for more information.