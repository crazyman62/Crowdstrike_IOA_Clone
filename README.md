# IOA Clone v3 - CrowdStrike Custom IOA Management Script

## Overview

This Python script leverages the CrowdStrike Falcon API via the `falconpy` SDK to manage Custom Indicators of Attack (IOAs) within a Falcon tenant, including specific functionality for Managed Security Service Providers (MSSPs) managing multiple child tenants.

It allows users to list accessible child CIDs, list Custom IOA rule groups in the parent tenant, replicate rules from source groups to a target group in child tenants (or the source tenant), and delete specific rule groups.

## Features

* **List Child CIDs:** For MSSP environments, lists all accessible child Customer IDs (CIDs) and their associated names.
* **List Parent IOAs:** Lists Custom IOA rule groups present in the parent (source) tenant. Can be filtered by name.
* **Replicate Rules:** Copies rules from specified source rule groups (either filtered by name or all groups) into a *single, pre-existing* target rule group in one or more target CIDs (or the source tenant).
    * Attempts to enable replicated rules after creation.
    * Skips rules that already exist by name in the target group.
    * Requires the target rule group to exist beforehand.
* **Delete Rule Groups:** Deletes specified Custom IOA rule groups by their IDs in one or more target CIDs (or the source tenant).
* **MSSP Targeting:** Actions (replication, deletion) can be targeted at:
    * Specific child CIDs (comma-separated list).
    * All accessible child CIDs.
    * The source tenant itself (if no MSSP flags are used).
* **Filtering:** Source rule groups for listing or replication can be filtered by name.
* **Colored Output:** Uses terminal color codes for better readability (can be disabled).
* **Flexible Table Formatting:** Output tables can be formatted using various `tabulate` styles.

## Requirements

* **Python 3.x**
* **CrowdStrike Falcon API Credentials:**
    * Client ID
    * Client Secret
    * Appropriate API Scopes (e.g., Custom IOA: Read/Write, Flight Control: Read)
* **Python Libraries:**
    * `falconpy`
    * `tabulate`

## Installation

1.  **Clone or download the script:** `IOA Clone v3.py`
2.  **Install required libraries:**
    ```bash
    pip install crowdstrike-falconpy tabulate
    ```

## Authentication

The script requires CrowdStrike Falcon API credentials (Client ID and Secret) provided via command-line arguments (`-k` and `-s`). Ensure the API key has the necessary permissions for the actions you intend to perform (reading/writing Custom IOAs, reading Flight Control information for MSSP).

## Usage

The script is run from the command line. Use `-h` or `--help` to see all available options.

```bash
python "IOA Clone v3.py" -k YOUR_CLIENT_ID -s YOUR_CLIENT_SECRET [ACTION] [MODIFIERS] [MSSP_TARGETS] [OPTIONS]
Core Arguments:-k FALCON_CLIENT_ID, --falcon_client_id FALCON_CLIENT_ID: (Required) CrowdStrike Falcon API Client ID.-s FALCON_CLIENT_SECRET, --falcon_client_secret FALCON_CLIENT_SECRET: (Required) CrowdStrike Falcon API Client Secret.-b BASE_URL, --base_url BASE_URL: CrowdStrike API Base URL (e.g., 'us-1', 'us-2'). Default: 'auto'.-n, --nocolor: Disable color output.-t TABLE_FORMAT, --table_format TABLE_FORMAT: Tabular display format. Default: 'fancy_grid'.-f FILTER, --filter FILTER: String to filter SOURCE rule groups by name (used with --replicate_rules, --list_parent_ioas).Actions (Choose ONE):--list_cids: List all accessible child CIDs and their names.--list_parent_ioas: List Custom IOA groups in the parent tenant (use -f to filter).-r, --replicate_rules: Replicate rules from filtered (-f) source groups into a pre-existing target group. Requires --target_group_name.--replicate_all_parent_rules: Replicate rules from ALL source groups into a pre-existing target group. Requires --target_group_name.-d, --delete_group: Delete specified rule group IDs in the target tenant(s). Requires --delete_ids.--delete_ids DELETE_IDS: Comma-separated list of rule group IDs to delete (required for --delete_group).Action Modifiers:--target_group_name TARGET_GROUP_NAME: Name of the PRE-EXISTING target rule group in child CIDs (Required for --replicate_rules and --replicate_all_parent_rules).MSSP Arguments (Target Specification - Mutually Exclusive):-m MANAGED_TARGETS, --managed_targets MANAGED_TARGETS: Comma-separated list of specific target child CIDs for actions.--all_cids: Target ALL accessible child CIDs for actions.(If neither -m nor --all_cids is used, actions like deletion will apply to the source tenant where the API key originates).ExamplesList all accessible Child CIDs:python "IOA Clone v3.py" -k YOUR_ID -s YOUR_SECRET --list_cids
List Parent IOA groups containing "MyRules" in their name:python "IOA Clone v3.py" -k YOUR_ID -s YOUR_SECRET --list_parent_ioas -f "MyRules"
Replicate rules from parent groups named "Source Group A" into the existing group "Target Replicated Rules" in specific child CIDs:python "IOA Clone v3.py" -k YOUR_ID -s YOUR_SECRET \
    -r -f "Source Group A" \
    --target_group_name "Target Replicated Rules" \
    -m child_cid_1,child_cid_2
Replicate rules from ALL parent groups into the existing group "Master Rule Set" in ALL child CIDs:python "IOA Clone v3.py" -k YOUR_ID -s YOUR_SECRET \
    --replicate_all_parent_rules \
    --target_group_name "Master Rule Set" \
    --all_cids
Delete rule groups with specific IDs in the source tenant:python "IOA Clone v3.py" -k YOUR_ID -s YOUR_SECRET \
    -d --delete_ids "group_id_abc,group_id_xyz"
Delete rule groups with specific IDs in ALL child CIDs:python "IOA Clone v3.py" -k YOUR_ID -s YOUR_SECRET \
    -d --delete_ids "group_id_to_purge" \
    --all_cids
Important NotesReplication Target: The --replicate_rules and --replicate_all_parent_rules actions require the target rule group specified by --target_group_name to already exist in the target CID(s). The script does not create the target group.Rule Enabling: The script attempts to enable replicated rules immediately after creation. Failures during the enable step are reported but do not stop the overall process. Rules might remain disabled if the enable API call fails (e.g., due to transient API issues or permission problems).Error Handling: The script includes basic error handling for API calls and argument parsing, but thorough testing in your environment is recommended.API Limits: Be mindful of CrowdStrike API rate limits, especially when targeting many child CIDs (--all_cids) or replicating a large number of rules.Debugging: The script includes debug=True and verbose=True in the SDK initialization (open_sdk). This will print detailed API request/response information, which is useful for troubleshooting but should ideally be turned off (`
