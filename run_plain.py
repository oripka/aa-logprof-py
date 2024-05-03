import argparse
import subprocess
import re
from collections import OrderedDict, defaultdict, Counter


# Example log entries for nested profiles
# type=AVC msg=audit(1712942187.872:24755): apparmor="ALLOWED" operation="open" profile="wordpress//null-/usr/local/bin/docker-entrypoint.sh//null-/usr/bin/bash//null-/usr/local/bin/apache2-foreground//null-/usr/sbin/apache2" name="/var/www/html/wp-includes/class-wp-list-util.php" pid=119534 comm="apache2" requested_mask="r" denied_mask="r" fsuid=33 ouid=33 FSUID="www-data" OUID="www-data"
# type=AVC msg=audit(1712942182.848:23946): apparmor="ALLOWED" operation="exec" profile="wordpress//null-/usr/sbin/service//null-/usr/bin/env//null-/etc/init.d/fail2ban//null-/usr/sbin/start-stop-daemon//null-/usr/bin/fail2ban-client" name="/usr/bin/fail2ban-server" pid=119498 comm="fail2ban-client" requested_mask="x" denied_mask="x" fsuid=0 ouid=0 target="wordpress//null-/usr/sbin/service//null-/usr/bin/env//null-/etc/init.d/fail2ban//null-/usr/sbin/start-stop-daemon//null-/usr/bin/fail2ban-client//null-/usr/bin/fail2ban-server" FSUID="root" OUID="root"

# Resulting profile example with nested profiles

#include <tunables/global>
# profile wpprofiling flags=(attach_disconnected, mediate_deleted) {
#   #include <abstractions/base>
#   allow /usr/bin/bash ix,
#   allow /usr/bin/dirname ix,
#   allow /usr/bin/mkdir ix,
#   allow /usr/sbin/nft ix,
#   /usr/sbin/apache2 Cx -> wp_apache,
#   allow /var/run/apache2/* rwlm,
#   profile wp_apache flags=(enforce) {
#       capability kill,
#       capability setgid,
#       capability setuid,
#       allow /var/www/html/** r,
#   }
# }

# Parse command line arguments
parser = argparse.ArgumentParser(description="Generate AppArmor profiles from audit logs.")
parser.add_argument('input_log', help='The input audit log file.')
parser.add_argument('output_profile', help='The output AppArmor profile filename.')
args = parser.parse_args()

def clear_logs(system_command="journalctl", logs="audit"):
    logfile = "audit/audit.log" if logs == "audit" else "kern.log"
    with open(f"/var/log/{logfile}", 'w') as f:
        f.truncate(0)

def collect_logs(profile_name, logfile):    
    try:
        with open(logfile, "r") as file:
            log_content = file.read()
    except Exception as e:
        return f"Error reading log file: {e}"
    return [line for line in log_content.split('\n') if profile_name in line]


def parse_log(lines):
    data = defaultdict(lambda: defaultdict(set))  # Nested dictionary with sets for each type of log
    
    for line in lines:
        profile_path = re.search(r"profile=\"([^\"]+)\"", line)
        if profile_path:
            profile_segments = tuple(profile_path.group(1).split('//'))
            if "capability" in line:
                caps = re.findall(r"\bcapname=[^\s]+", line)
                data[profile_segments]["capability_logs"].update(cap.split('=')[1] for cap in caps)
            if "operation" in line and "name" in line:
                name_match = re.search(r"name=\"([^\"]+)\"", line)
                requested_mask_match = re.search(r"requested_mask=\"([^\"]+)\"", line)
                if name_match and requested_mask_match:
                    data[profile_segments]["file_logs"].add(
                        (name_match.group(1).strip(), requested_mask_match.group(1).strip())
                    )
    return data

def compile_rules(log_dict, profile_name):
    rules = []
    if "capability_logs" in log_dict:
        for cap in log_dict["capability_logs"]:
            rules.append(f'    capability {cap},\n')
    if "file_logs" in log_dict:
        for path, permission in log_dict["file_logs"]:
            rules.append(f'    {path} {permission},\n')
    return rules



def create_apparmor_profile_from_dict(data):
    content = ["#include <tunables/global>\n", "profile base flags=(attach_disconnected, mediate_deleted) {\n", "  #include <abstractions/base>\n"]
    seen_rules = set()  # To track and avoid duplicate rules

    for profile_segments, logs in data.items():
        nested_profile_name = '//'.join(profile_segments)
        content.append(f"  profile {nested_profile_name} flags=(enforce) {{\n")
        rules = compile_rules(logs, nested_profile_name)  # Ensure compile_rules is defined

        # Filter and add only unique rules
        for rule in rules:
            if rule not in seen_rules:
                content.append(rule)
                seen_rules.add(rule)
        
        content.append("  }\n")
    
    content.append("}\n")
    return content



# Main execution
with open(args.input_log, 'r') as log_file:
    logs = log_file.readlines()
parsed = parse_log(logs)

print(parsed)

profile_lines = create_apparmor_profile_from_dict(parsed)
with open(args.output_profile, 'w') as file:
    file.writelines(profile_lines)
print(f"AppArmor profile generated and saved to {args.output_profile}")




# g_lines = glob_apparmor_profile(profile_lines, 1)


# with open(args.output_profile+"_glob", 'w') as file:
#     file.writelines(g_lines)
# print(f"AppArmor profile generated and saved to {g_lines}")
