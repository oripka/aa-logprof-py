import argparse
import re
from collections import defaultdict

def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Generate AppArmor profiles from audit logs.",
        usage="aa-logprof.py input_log output_profile [--ignore-dirs [IGNORE_DIRS ...]]"
    )
    parser.add_argument('input_log', help='The input audit log file.')
    parser.add_argument('output_profile', help='The output AppArmor profile filename.')
    parser.add_argument('--ignore-dirs', nargs='*', default=[],
                        help='Directories to wildcard in the generated profile.')
    return parser.parse_args()

def determine_transitions(data, exec_relations):
    for profile_string, targets in exec_relations.items():
        for path, permission, target_profile in targets:
            if target_profile and target_profile in data:
                # Apply Cx transition if the target profile exists
                data[profile_string]["file_logs"].add((path, permission, 'Cx', target_profile))
            else:
                # Regular exec without transition
                data[profile_string]["file_logs"].add((path, permission, 'x'))

def parse_log(lines, ignore_dirs):
    """
    Parse the audit.log lines to extract relevant file/capability accesses.
    We allow for ignoring or wildcarding entire directories to reduce noise.
    """
    data = defaultdict(lambda: defaultdict(set))
    exec_relations = defaultdict(list)
    
    for line in lines:
        profile_path = re.search(r"profile=\"([^\"]+)\"", line)
        target_profile_path = re.search(r"target=\"([^\"]+)\"", line)
        
        if profile_path:
            segments = tuple(profile_path.group(1).split('//'))
            profile_string = '//'.join(segments)
            
            # ---------------------
            # Handle capabilities
            # ---------------------
            if "capability" in line:
                caps = re.findall(r"\bcapname=[^\s]+", line)
                data[profile_string]["capability_logs"].update(cap.split('=')[1] for cap in caps)
            
            # ---------------------
            # Handle file accesses
            # ---------------------
            name_match = re.search(r"name=\"([^\"]+)\"", line)
            requested_mask_match = re.search(r"requested_mask=\"([^\"]+)\"", line)
            if name_match and requested_mask_match:
                path = name_match.group(1).strip()
                permission = requested_mask_match.group(1).strip()
                
                # Check if this path starts with any of the ignored directories
                for ignored_dir in ignore_dirs:
                    if path.startswith(ignored_dir):
                        # Replace it with a wildcard version
                        path = f"{ignored_dir}/**"
                        break

                if 'exec' in line:
                    target_profile = target_profile_path.group(1) if target_profile_path else None
                    exec_relations[profile_string].append((path, permission, target_profile))
                else:
                    data[profile_string]["file_logs"].add((path, permission))

    return data, exec_relations

def filter_paths(profile_content, profile_name=''):
    """
    filter_paths can optionally remove or replace certain lines with #include lines 
    for known abstractions. 
    """
    # Define prefixes to remove and their corresponding replacement lines
    replacements = {
        '/usr/lib/x86_64-linux-gnu/': '    #include <abstractions/base>\n',
        '/etc/ld.so.cache': '    #include <abstractions/base>\n',
        '/usr/lib/python': '    #include <abstractions/python>\n',
        '/usr/local/lib/php': '    #include <abstractions/php>\n',
        '/usr/local/etc/php': '    #include <abstractions/php>\n',
        '/usr/lib/apache2':  '    #include <abstractions/apache2-common>\n',
        '/etc/apache2':  '    #include <abstractions/apache2-common>\n'
    }
    
    headers_to_add = set()
    filtered_lines = []
    
    for line in profile_content:
        remove_line = False
        
        # Check if line should be replaced with an #include
        for prefix, replacement in replacements.items():
            if line.strip().startswith(prefix):
                headers_to_add.add(replacement)
                remove_line = True
                break
        
        if not remove_line:
            filtered_lines.append(line)
    
    # Insert the #include lines at the top
    result_lines = list(headers_to_add) + filtered_lines
    return "", result_lines

def compile_rules(log_dict):
    """
    Turn the logs in `log_dict` into actual AppArmor rules.
    """
    rules = []
    if "capability_logs" in log_dict:
        for cap in log_dict["capability_logs"]:
            rules.append(f'    capability {cap},\n')
    if "file_logs" in log_dict:
        for entry in log_dict["file_logs"]:
            # Check for exec transitions
            if len(entry) == 4:  # (path, permission, 'Cx', target_profile)
                path, permission, transition, target = entry
                rules.append(f'    {path} {transition} -> {target},\n')
            else:
                path, permission = entry[:2]
                # Possibly there's an operation in entry[2], but usually it's just path & permission
                if len(entry) > 2:
                    operation = entry[2]
                    rules.append(f'    {path} {operation},\n')
                else:
                    rules.append(f'    {path} {permission},\n')
    return rules

def create_apparmor_profile_from_dict(data):
    """
    Build the final AppArmor profiles from the parsed data.
    """
    content = [
        "#include <tunables/global>\n",
        "profile base flags=(attach_disconnected, mediate_deleted) {\n",
        "  #include <abstractions/base>\n"
    ]
    ordered_profiles = sorted(data.keys())  # Sort profiles alphabetically

    for profile_string in ordered_profiles:
        rules = compile_rules(data[profile_string])
        abstraction_line, filtered_rules = filter_paths(rules, profile_string)
        content.append(
            f"  profile {profile_string} flags=(enforce) {{\n"
            f"{abstraction_line}"
            f"{''.join(filtered_rules)}"
            "  }\n\n"  # Add a blank line after each profile block
        )
    
    content.append("}\n")
    return content

def main():
    args = parse_arguments()
    
    with open(args.input_log, 'r') as log_file:
        logs = log_file.readlines()
    
    data, exec_relations = parse_log(logs, args.ignore_dirs)
    determine_transitions(data, exec_relations)
    profile_content = create_apparmor_profile_from_dict(data)
    
    with open(args.output_profile, 'w') as file:
        file.writelines(profile_content)
    
    print(f"AppArmor profile generated and saved to {args.output_profile}")

if __name__ == "__main__":
    main()
