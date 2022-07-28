import argparse
import yaml

from .fuzzware_utils.config import load_config_deep, update_config_file

# Hard timeout
DEFAULT_TIMEOUT = 600
# Part of time set aside for stepping
EXPLORATION_TIMEOUT_FACTOR = 0.75

def main():
    # Do the parsing up front as importing angr takes time
    parser = argparse.ArgumentParser(description="State restauration and MMIO access model identification")
    parser.add_argument('statefiles', type=str, help="Path to the file containing the base state to start symbolic execution from", nargs='+')
    parser.add_argument('-r', '--result_file_path', default=None, help="Path to text file to append the analysis results to")
    parser.add_argument('-c', '--model_config_path', default=None, help="Path to yml config file to update")
    parser.add_argument('-C', '--fuzzware-config', default=None, help="Path to fuzzware yml config file to extract mmio region(s)")
    parser.add_argument('-t', '--timeout', type=int, default=DEFAULT_TIMEOUT, help=f"Timeout (in seconds)")

    # Debugging and logging
    parser.add_argument('-i', '--interactive', default=False, action='store_true', help="Drop into interactive shell in specific spots")
    parser.add_argument('-m', '--manual-stepping', default=False, action='store_true', help="Step interactively")
    parser.add_argument('-d', '--debug', default=False, action='store_true', help="Enable debug level output")

    args = parser.parse_args()

    if args.fuzzware_config:
        args.fuzzware_config = load_config_deep(args.fuzzware_config)

    # Delay import to delay
    from .analyze_mmio import perform_analyses
    result_lines, model_entries = perform_analyses(args.statefiles, args.fuzzware_config, is_debug=args.debug, timeout=args.timeout)

    if args.model_config_path is not None:
        update_config_file(args.model_config_path, model_entries)

    if args.result_file_path is not None:
        with open(args.result_file_path, "w") as f:
            f.write("\n".join(result_lines))
    else:
        print("\n".join(result_lines))

if __name__ == '__main__':
    main()
