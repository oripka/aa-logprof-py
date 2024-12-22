# Smart AppArmor Profile Generator

## Overview

This Python script automates the generation of AppArmor profiles from audit logs, focusing on features not typically handled by the stock aa-logprof tool. Unlike aa-logprof, this script can process logs **detailing subprocess activities**, which is particularly useful for **constraining processes within Docker containers**. It extracts necessary security information from these logs and outputs a tailored AppArmor profile, enhancing system security by defining specific resource access permissions for applications. Importantly, **it confines subprocesses using AppArmor local profiles**, allowing for fine-grained control over application behavior.

## Prerequisites

- Python 3.x  
- AppArmor utilities installed on your Linux distribution (`apparmor_parser`, `aa-status`, etc.)

## Installation

No installation is required other than having Python and AppArmor on your system. You can run the script directly from the command line.

## Usage

1. **Basic Usage**  
   Provide the input log file and the output profile file name as command-line arguments:
   ```bash
   python3 aa-logprof.py /path/to/audit.log /path/to/output.profile
   ```

2. **Optional: Ignoring Directories**  
   If you have certain directories (e.g., Plex libraries) that produce a huge number of file paths, you can reduce noise by wildcarding them:
   ```bash
   python3 aa-logprof.py --ignore-dirs /usr/lib/plex /var/lib/plex \
       /path/to/audit.log /path/to/output.profile
   ```
   - **What it does:** All file paths that begin with any directory listed under `--ignore-dirs` are collapsed into a single rule, for example `/usr/lib/plex/** r,` instead of hundreds of lines referencing individual files.

### Arguments

- `input_log`: The path to the audit log file you want to process.
- `output_profile`: The desired filename for the generated AppArmor profile.
- `--ignore-dirs`: One or more directories that you’d like to wildcard in the profile. Any files accessed under these directories will be consolidated into a single rule.

## How It Works

1. **Parsing Logs**  
   The script reads the provided audit log, identifying security-related entries such as capabilities and file access permissions.

2. **Determining Executions**  
   It identifies execution transitions within the logs to handle profiles correctly when applications execute other binaries.

3. **Filtering and Compiling Rules**  
   - The script can **ignore or wildcard** common directories (using `--ignore-dirs`) to avoid bloating your profile.  
   - It also includes necessary AppArmor abstractions based on accessed resources (e.g., Python, Apache, PHP libraries).

4. **Profile Generation**  
   Finally, it compiles all extracted data into a valid AppArmor profile and writes it to the specified output file.

## Output

The script outputs a `.profile` (or similarly named) file that is ready to be used with AppArmor. This profile contains all the necessary rules derived from the audit logs to restrict application behaviors according to the observed activities.

## Docker Support

The script effectively handles audit logs from Docker containers, tracking subprocesses and their security configurations. This feature is crucial for deploying secure containers in production environments, ensuring that Dockerized applications comply with strict security policies. The use of local profiles for subprocesses enhances the precision of security constraints, enabling detailed management of permissions at the subprocess level.

### Example Docker Run

```bash
apparmor_parser -r -W example/smart_profile
docker run --rm -it --security-opt apparmor=smart_profile wordpress
```

![](./aa-logprof-py-white.png)

## KEV List

![](./kev.png)

With the recent surge in command injections being exploited in the wild, like those highlighted in the latest vulnerability list by CISA, I felt compelled to contribute a solution.

## Auditing using AppArmor

```bash
apt install apparmor-utils auditd -y
aa-status
echo "" > /var/log/audit/audit.log
```

Load base profile:

```bash
cp examples/base_profile /etc/apparmor.d/base_profile
apparmor_parser -r -W /etc/apparmor.d/base_profile
aa-complain /etc/apparmor.d/base_profile
```

Start your container:

```bash
docker run --name wordpress -p 8080:80 -d --security-opt apparmor=base_profile wordpress
```

## Note

- Ensure that the audit logs provided contain detailed information for accurate profile generation. Incomplete or non-detailed logs may result in less effective security profiles.
- By default, the script handles **file access** and **capabilities**. If you need network rules or other advanced AppArmor constraints, you can extend the script to parse those events in the audit log.
- Learn more about [Local Profiles](https://documentation.suse.com/sles/12-SP5/html/SLES-all/cha-apparmor-profiles.html#sec-apparmor-profiles-types-local).