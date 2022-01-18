import copy
import logging
import os
import yaml
from os.path import isfile

l = logging.getLogger("persist_results")

def merge_model_conflict(model_type, existing_entry, new_entry):
    if model_type == "set":
        for val in new_entry['vals']:
            if val not in existing_entry['vals']:
                print("[Set Model Merging] Adding value {:x} to entry".format(val))
                existing_entry['vals'].append(val)
        existing_entry['vals'].sort()
        return True
    elif model_type == "bitextract":
        existing_entry['mask'] |= new_entry['mask']
        return True
    else:
        return False

def add_config_entries(existing_models, new_models):
    """
    Takes a list of newly created model entry maps and adds them to the existing modeling map
    new_models would look something like this:
    [
        {
            'passthrough': {
                pc_deadbeef_mmio_1234:
                    addr: 0x40012345
                    pc: 0x123
                    val: 0x20
            },
            'linear' : {
                ...
            }
        },
        {
            'passthrough': {
                ...
            },
            'constant': {
                ...
            }
        }
    ]

    @return True, if all merges were completed successfully
    """
    all_good = True
    for entry in new_models:
        for model_type, models in entry.items():
            for model_name, param_map in models.items():
                all_good = all_good and add_config_entry(existing_models, model_type, model_name, param_map)
    return all_good

def add_config_entry(existing_models, model_type, entry_name, param_map):
    if model_type not in existing_models:
        existing_models[model_type] = {}

    # entry_name, param_map = list(model_entry.items())[0]
    # Check for conflicting model assignments
    if entry_name in existing_models[model_type] and existing_models[model_type][entry_name] != param_map:
        print("[WARNING] got conflicting model assignments from different states")
        if 'conflicts' not in existing_models:
            existing_models['conflicts'] = {}
        if entry_name not in existing_models['conflicts']:
            existing_models['conflicts'][entry_name] = []
        if param_map not in existing_models['conflicts'][entry_name]:
            existing_models['conflicts'][entry_name].append(param_map)
        
        existing_entry = existing_models[model_type][entry_name]
        if existing_entry not in existing_models['conflicts'][entry_name]:
            existing_models['conflicts'][entry_name].append(copy.deepcopy(existing_entry))

        l.warning("Merging configs:\nExisting: {}\nConflicting: {}".format(existing_entry, param_map))
        if merge_model_conflict(model_type, existing_entry, param_map):
            l.warning("Successfully merged into {}".format(existing_entry))
            # existing_models[model_type][entry_name] = merged_model_entry
        else:
            l.warning("Merging failed, existing config kept.")
            return False
    else:
        existing_models[model_type][entry_name] = param_map
    
    return True

def load_config_shallow(config_filename):
    if isfile(config_filename):
        with open(config_filename, "r") as config_file:
            config_dict = yaml.safe_load(config_file.read())
        # print("loaded config: {}".format(config_dict))
    else:
        config_dict = {}
    if config_dict is None:
        config_dict = {}

    if 'mmio_models' not in config_dict:
        config_dict['mmio_models'] = {}

    return config_dict

def adjust_config_relative_paths(config, base_path):
    # "./"-prefixed paths to properly resolve relative to config snippet
    if 'memory_map' not in config:
        return

    for rname, region in config['memory_map'].items():
        if 'file' in region and region['file'].startswith("./"):
            region['file'] = os.path.join(os.path.dirname(base_path), region['file'])
            l.debug("Fixed up file path to '{}'".format(region['file']))

def resolve_config_includes(config, base_path):
    """
    Recursively resolves a config file, adjusting paths along
    the way
    """
    if 'include' in config:
        # Merge config files listed in 'include' in listed order
        # Root file gets priority
        newconfig = {}
        for f in config['include']:
            if not f.startswith("/"):
                # Make configs relative to the including config file
                cur_dir = os.path.dirname(base_path)
                f = os.path.abspath(os.path.join(cur_dir, f))

            l.info(f"\tIncluding configuration from {f}")
            with open(f, 'rb') as infile:
                other_config_snippet = yaml.load(infile, Loader=yaml.FullLoader)
            adjust_config_relative_paths(other_config_snippet, f)
            other_config_snippet = resolve_config_includes(other_config_snippet, f)
            _merge_dict(newconfig, other_config_snippet)
        _merge_dict(newconfig, config)
        config = newconfig
    return config

def resolve_config_file_pattern(config_dir_path, f):
    """
    Resolve the path pattern in a config to the actual file path
    """
    if not f.startswith("/"):
        f = os.path.join(config_dir_path, f)

    if '*' in f:
        candidates = directory_glob(f)
        if len(candidates) != 1:
            raise ValueError("Could not unambiguously find pattern '{}' matching paths: {}".format(f, candidates))

        f = candidates[0]

    return os.path.abspath(f)

def resolve_region_file_paths(config_file_path, config):
    """
    Updates the config map's 'memory_map' entry, resolving patterns
    and relative paths.
    """

    for rname, region in config['memory_map'].items():
        path = region.get('file')
        if path:
            region['file'] = resolve_config_file_pattern(os.path.dirname(config_file_path), path)
            l.info("Found path '{}' for pattern '{}'".format(region['file'], path))

def load_config_deep(path):
    if not os.path.isfile(path):
        return {}
    with open(path, 'rb') as infile:
        config = yaml.load(infile, Loader=yaml.FullLoader)
    if config is None:
        return {}
    return resolve_config_includes(config, path)

def merge_config_file_into(target_config_path, other_config_path):
    additional_config = load_config_shallow(other_config_path)
    update_config_file(target_config_path, [additional_config['mmio_models']])

def update_config_file(config_filename, model_entries):
    """
    Updates a config file in-place with a list of model config trees
    """

    l.debug("Adding config entries: {}".format(model_entries))

    config_dict = load_config_shallow(config_filename)

    success = add_config_entries(config_dict['mmio_models'], model_entries)

    write_yaml(config_filename, config_dict)

    return success

def write_yaml(path, config_map):
    # Use hex representation of numbers in generated yml file
    def hexint_presenter(dumper, data):
        return dumper.represent_int(hex(data))

    yaml.add_representer(int, hexint_presenter)
    with open(path, "w") as f:
        f.write(yaml.dump(config_map))
