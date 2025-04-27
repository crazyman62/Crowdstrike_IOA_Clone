# CrowdStrike Custom IOA Management Script

## Purpose

This Python script facilitates the management of CrowdStrike Custom Indicators of Attack (IOA) rules, particularly within a Managed Security Service Provider (MSSP) environment involving a parent tenant and multiple child tenants (CIDs). It allows for listing, replicating, updating, and deleting IOA rule groups and rules between tenants.

## Features

* **List Child CIDs:** Discover and list all child CIDs accessible via the provided API key.
* **List IOA Groups:** List Custom IOA rule groups in the parent tenant, with optional name filtering.
* **Replicate/Update Rules:**
    * Copy rules from specified source groups (or all groups) in the parent tenant to a **pre-existing** target rule group in one or more child tenants (or the source tenant itself).
    * **Update Existing Rules:** If a rule with the same name (case-insensitive, ignoring leading/trailing whitespace) already exists in the target group, the script will update it to match the source rule's attributes (description, severity, fields, enabled status, etc.).
    * **Create New Rules:** If a rule does not exist in the target group, it will be created.
    * **Enablement Handling:** Newly created rules are initially disabled. If the corresponding source rule was enabled, the script attempts a second API call to enable the new rule in the target.
    * **Single Rule Targeting:** Option to replicate/update only a single, specific rule by name (`--rule_name`) from the source groups.
* **Delete Rule Groups:** Delete specified rule group IDs from target tenants (child CIDs or the source tenant).
* **MSSP Targeting:**
    * Target specific child CIDs using a comma-separated list (`-m`).
    * Target all accessible child CIDs (`--all_cids`).
* **Cross-Platform Color Output:** Provides colored terminal output for readability on Linux, macOS, and Windows (CMD/PowerShell), using the `colorama` library. Can be disabled with `--nocolor`.
* **Modular Structure:** Code is split into logical modules (`ioa_utils.py`, `ioa_replication.py`, `ioa_deletion.py`, `ioa_main.py`) for better organization and maintainability.

## File Structure

* `ioa_main.py`: The main executable script. Handles argument parsing and orchestrates actions.
* `ioa_utils.py`: Contains shared utility functions (SDK setup, listing, display, color, summary tracking, etc.) and classes.
* `ioa_replication.py`: Contains the core logic for replicating and updating rules between tenants.
* `ioa_deletion.py`: Contains the logic for deleting rule groups.

## Prerequisites

* **Python 3.x**
* **Required Python Libraries:**
    * `crowdstrike-falconpy`: The CrowdStrike Falcon SDK for Python.
    * `tabulate`: For displaying information in tables.
    * `colorama`: For cross-platform terminal color support.
* **CrowdStrike API Credentials:**
    * Client ID and Client Secret for an API key in your **parent** CrowdStrike tenant.
    * **Required API Scopes:**
        * **Flight Control (MSSP):** `mssp:read` (To list and manage child CIDs)
        * **Custom IOA Rules:**
            * `custom-ioa:read` (Required for **both** parent and any target child CIDs you interact with)
            * `custom-ioa:write` (Required for the **parent tenant** if deleting groups there, and for **any target child CIDs** where you will replicate/update rules or delete groups)
        * *Crucially, ensure the API key has the necessary `custom-ioa:read` and `custom-ioa:write` permissions assigned specifically for the child CIDs you intend to target.*

## Setup

1.  **Place Files:** Ensure all four Python files (`ioa_main.py`, `ioa_utils.py`, `ioa_replication.py`, `ioa_deletion.py`) are in the same directory.
2.  **Install Libraries:** Open your terminal or command prompt and run:
    ```bash
    pip install crowdstrike-falconpy tabulate colorama
    ```
3.  **API Key:** Obtain your API Client ID and Secret from the CrowdStrike Falcon console (API Clients and Keys section) and ensure it has the required permissions mentioned above.

## Usage

Run the main script from your terminal using `python ioa_main.py` followed by the necessary arguments.

```bash
python ioa_main.py -k YOUR_CLIENT_ID -s YOUR_CLIENT_SECRET [ACTION] [OPTIONS...]
Required Arguments:-k YOUR_CLIENT_ID, --falcon_client_id YOUR_CLIENT_ID: Your CrowdStrike API Client ID.-s YOUR_CLIENT_SECRET, --falcon_client_secret YOUR_CLIENT_SECRET: Your CrowdStrike API Client Secret.Actions (Choose ONE):--list_cids: List accessible child CIDs and their names.--list_parent_ioas: List Custom IOA groups in the parent tenant.Use with -f "Filter String" to filter groups by name.-r, --replicate_rules: Replicate/update rules from source to target. Requires --target_group_name. Requires either -f "Group Filter" or --rule_name "Rule Name".--replicate_all_parent_rules: Replicate/update rules from ALL source groups to target. Requires --target_group_name. Cannot be used with --rule_name.-d, --delete_group: Delete rule groups in the target(s). Requires --delete_ids.--delete_ids "ID1,ID2,...": Comma-separated list of rule group IDs to delete.Common Options:-b BASE_URL, --base_url BASE_URL: CrowdStrike API base URL (e.g., us-1, us-2, eu-1, https://api.crowdstrike.com). Default: auto. Use the full URL if auto doesn't work.-n, --nocolor: Disable colored terminal output.-t TABLE_FORMAT, --table_format TABLE_FORMAT: Format for table output (e.g., fancy_grid, simple, github). Default: fancy_grid.-f "GROUP_FILTER": Filter source rule groups by name (used with --list_parent_ioas, --replicate_rules).--rule_name "RULE_NAME": Target a single rule by name for replication/update (used with --replicate_rules).--target_group_name "TARGET_GROUP_NAME": Name of the pre-existing target rule group in the child/source tenant where rules will be replicated/updated. Required for replication actions.-m TARGET_CIDS, --managed_targets TARGET_CIDS: Comma-separated list of specific child CIDs to target for replication or deletion.--all_cids: Target ALL accessible child CIDs for replication or deletion.Examples:List all accessible child CIDs:python ioa_main.py -k ID -s SECRET --list_cids
List parent IOA groups containing "Windows" in the name:python ioa_main.py -k ID -s SECRET --list_parent_ioas -f "Windows"
Replicate/Update all rules from parent groups matching "ACME" into the "Consolidated Child IOAs" group in ALL child CIDs:python ioa_main.py -k ID -s SECRET -f "ACME" --replicate_rules --target_group_name "Consolidated Child IOAs" --all_cids
Replicate/Update a single rule named "Suspicious PowerShell" (assuming it's in a source group matching filter "Custom") into the "Child-Win-IOAs" group in specific child CIDs:python ioa_main.py -k ID -s SECRET -f "Custom" --rule_name "Suspicious PowerShell" --replicate_rules --target_group_name "Child-Win-IOAs" -m CHILD_CID_1,CHILD_CID_2
Replicate/Update ALL rules from ALL parent groups into the "Migrated IOAs" group in the source tenant (use with caution):python ioa_main.py -k ID -s SECRET --replicate_all_parent_rules --target_group_name "Migrated IOAs"
Delete rule groups "group_id_1" and "group_id_2" from ALL child CIDs:python ioa_main.py -k ID -s SECRET -d --delete_ids "group_id_1,group_id_2" --all_cids
Important NotesTarget Group Must Exist: When replicating/updating rules (-r or --replicate_all_parent_rules), the group specified by --target_group_name must already exist in the target tenant(s). This script does not create the target group.API Rate Limits: Be mindful of CrowdStrike API rate limits, especially when targeting --all_cids with many rules or children. The script processes CIDs sequentially.Error Handling: The script includes basic error handling, but review the output carefully, especially the final summary, for any reported API errors or failures.Permissions: Double-check that your API key has the necessary permissions scopes assigned for all tenants (parent and children) you intend to interact with. Lack of custom-ioa:read in a child CID is