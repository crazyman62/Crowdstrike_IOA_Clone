import sys
import json
import time # Import time for potential delays if needed
from argparse import ArgumentParser, RawTextHelpFormatter, Action
# Import necessary FalconPy services
from falconpy import CustomIOA, FlightControl, PreventionPolicies
# Re-import tabulate for formatted output
from tabulate import tabulate

# --- Color Class (Reintroduced for display functions) ---
class Color:
    """Class to represent the text color codes used for terminal output."""
    PURPLE = "\033[95m"; CYAN = "\033[96m"; DARKCYAN = "\033[36m"
    MAGENTA = "\033[35m"; BLUE = "\033[34m"; LIGHTBLUE = "\033[94m"
    GREEN = "\033[32m"; LIGHTGREEN = "\033[92m"; LIGHTYELLOW = "\033[93m"
    YELLOW = "\033[33m"; RED = "\033[31m"; LIGHTRED = "\033[91m"
    BOLD = "\033[1m"; UNDERLINE = "\033[4m"; END = "\033[0m"

# --- Argument Parser Action for Mutually Exclusive Groups ---
class MutuallyExclusiveAction(Action):
    """Custom argparse action for mutually exclusive flags."""
    # Use a unique name unlikely to clash with user arguments
    _ACTION_GROUP_TRACKER_NAME = '_mutually_exclusive_action_group_tracker'

    def __init__(self, option_strings, dest, nargs=None, **kwargs):
        # 'dest' is now the specific action name (e.g., 'replicate_rules')
        if nargs is not None:
            raise ValueError("nargs not allowed")
        super().__init__(option_strings, dest, nargs=0, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        action_group_tracker = getattr(namespace, self._ACTION_GROUP_TRACKER_NAME, None)

        # Initialize tracker if first time
        if action_group_tracker is None:
            action_group_tracker = set()
            setattr(namespace, self._ACTION_GROUP_TRACKER_NAME, action_group_tracker)

        # Check for conflicts
        # If the tracker exists and contains an action different from the current one
        if action_group_tracker and self.dest not in action_group_tracker:
            conflicting_options = ', '.join('--' + opt.replace('_', '-') for opt in action_group_tracker)
            raise parser.error(f"argument {option_string}: not allowed with argument {conflicting_options}")

        # Add this action to the tracker and set its flag to True
        action_group_tracker.add(self.dest)
        setattr(namespace, self.dest, True)


# --- Argument Parsing ---
def consume_arguments():
    """Consume and validate command-line arguments."""
    parser = ArgumentParser(description="List, Replicate IOA Rules, or Delete Rule Groups.",
                            formatter_class=RawTextHelpFormatter)
    # Core arguments
    parser.add_argument("-n", "--nocolor", help="Disable color output", action="store_true", default=False)
    parser.add_argument("-b", "--base_url", help="CrowdStrike API Base URL (e.g., 'us-1', 'us-2'). Default: 'auto'", default="auto")
    parser.add_argument("-t", "--table_format", help="Tabular display format for listings. Default: 'fancy_grid'", default="fancy_grid")
    parser.add_argument("-f", "--filter", help="String to filter SOURCE rule groups by name (used with --replicate_rules, --list_parent_ioas)", default=None)

    # --- Actions (Mutually Exclusive) ---
    action_group = parser.add_argument_group("actions (choose one)")
    # Listing Actions
    # Use dest= explicitly to match the desired attribute name
    action_group.add_argument("--list_cids", help="List all accessible child CIDs and their names.", action=MutuallyExclusiveAction, dest='list_cids', default=False)
    action_group.add_argument("--list_parent_ioas", help="List Custom IOA groups in the parent tenant (use -f to filter).", action=MutuallyExclusiveAction, dest='list_parent_ioas', default=False)
    # Modification Actions
    action_group.add_argument("-r", "--replicate_rules", help="Replicate rules from filtered source groups into a pre-existing target group (attempts to enable rules).", action=MutuallyExclusiveAction, dest='replicate_rules', default=False)
    action_group.add_argument("--replicate_all_parent_rules", help="Replicate rules from ALL source groups into a pre-existing target group (attempts to enable rules).", action=MutuallyExclusiveAction, dest='replicate_all_parent_rules', default=False)
    action_group.add_argument("-d", "--delete_group", help="Delete specified rule group IDs in the target tenant(s)", action=MutuallyExclusiveAction, dest='delete_group', default=False)
    action_group.add_argument("--delete_ids", help="Comma-separated list of rule group IDs to delete (required for --delete_group)", default=None)

    # --- Action Modifiers ---
    mod_group = parser.add_argument_group("action modifiers")
    # Target Group Name (Required for Replicate Rules actions)
    mod_group.add_argument("--target_group_name", help="Name of the PRE-EXISTING target rule group in child CIDs (Required for --replicate_rules and --replicate_all_parent_rules).", default=None)
    # Policy assignment might be added back later if enabling rules works
    # mod_group.add_argument("--assign_to_policy", help="Assign the target group to the specified prevention policy.", action="store_true", default=False)
    # mod_group.add_argument("--policy_name", help="Name of the Prevention Policy to assign the target group to. Default: 'Phase 3 - optimal protection'", default="Phase 3 - optimal protection")

    # --- MSSP Arguments (Mutually Exclusive Target Specification) ---
    mssp_group = parser.add_argument_group("mssp arguments (target specification)")
    mssp_target_group = mssp_group.add_mutually_exclusive_group()
    mssp_target_group.add_argument("-m", "--managed_targets", help="Comma-separated list of specific target child CIDs for actions.", default=None)
    mssp_target_group.add_argument("--all_cids", help="Target ALL accessible child CIDs for actions.", action="store_true", default=False)

    # Required
    req = parser.add_argument_group("required arguments")
    req.add_argument("-k", "--falcon_client_id", help="CrowdStrike Falcon API Client ID", required=True)
    req.add_argument("-s", "--falcon_client_secret", help="CrowdStrike Falcon API Client Secret", required=True)

    parsed_args = parser.parse_args()

    # Ensure action flags exist using getattr with default False (safer)
    # This handles the case where NO action flag is provided on the command line
    # The MutuallyExclusiveAction should have already set the correct one to True if specified.
    parsed_args.list_cids = getattr(parsed_args, 'list_cids', False)
    parsed_args.list_parent_ioas = getattr(parsed_args, 'list_parent_ioas', False)
    parsed_args.replicate_rules = getattr(parsed_args, 'replicate_rules', False)
    parsed_args.replicate_all_parent_rules = getattr(parsed_args, 'replicate_all_parent_rules', False)
    parsed_args.delete_group = getattr(parsed_args, 'delete_group', False)


    # Post-parsing validation (Now uses the correctly set attributes)
    if parsed_args.replicate_rules and not parsed_args.filter:
        parser.error("-f/--filter is required when using --replicate_rules.")
    if (parsed_args.replicate_rules or parsed_args.replicate_all_parent_rules) and not parsed_args.target_group_name:
        parser.error("--target_group_name is required when using --replicate_rules or --replicate_all_parent_rules.")
    if parsed_args.delete_group and not parsed_args.delete_ids:
         parser.error("--delete_ids is required when using --delete_group.")

    # Check if any action was selected if not just listing
    if not any([parsed_args.list_cids, parsed_args.list_parent_ioas, parsed_args.replicate_rules, parsed_args.replicate_all_parent_rules, parsed_args.delete_group]):
         print("Warning: No action specified. Use --list_cids, --list_parent_ioas, --replicate_rules, --replicate_all_parent_rules, or --delete_group.")

    return parsed_args

# --- SDK Initialization ---
def open_sdk(client_id: str, client_secret: str, base: str, service: str, member_cid: str = None):
    """Creates an instance of a specified FalconPy Service Class."""
    init_params = {"client_id": client_id, "client_secret": client_secret, "base_url": base}
    if member_cid: init_params["member_cid"] = member_cid
    try:
        ServiceClass = getattr(__import__('falconpy', fromlist=[service]), service)
        print(f"  Initializing {service} SDK for {'CID ' + member_cid if member_cid else 'source tenant'}...")
        # Enable detailed debugging for falconpy to see raw requests/responses
        # Set debug=False and verbose=False for production use
        sdk_instance = ServiceClass(**init_params, debug=True, verbose=True)
        print(f"  {service} SDK initialized successfully.")
        return sdk_instance
    except (ImportError, AttributeError):
        print(f"Fatal Error: Invalid FalconPy service: '{service}'.")
        sys.exit(1)
    except Exception as e:
        print(f"Fatal Error: Failed to initialize Falcon {service} SDK: {e}")
        sys.exit(1)

def open_mssp(client_id: str, client_secret: str, base: str):
    """Creates an instance of the Flight Control Service Class."""
    try:
        mssp_sdk = FlightControl(client_id=client_id, client_secret=client_secret, base_url=base)
        return mssp_sdk
    except Exception as e:
        print(f"Fatal Error: Failed to initialize Flight Control SDK: {e}")
        sys.exit(1)

# --- Helper Functions ---
def chunk_long_description(desc, col_width) -> str:
    """Chunks a long string by delimiting with CR based upon column length."""
    if not isinstance(desc, str): return ""
    desc_chunks = []; current_line = ""
    for word in desc.split():
        word = word.strip();
        if not word: continue
        if len(word) > col_width:
            if current_line: desc_chunks.append(current_line); current_line = ""
            for i in range(0, len(word), col_width): desc_chunks.append(word[i:i+col_width])
        elif len(current_line) + len(word) + (1 if current_line else 0) > col_width:
            if current_line: desc_chunks.append(current_line)
            current_line = word
        else: current_line += (" " + word) if current_line else word
    if current_line: desc_chunks.append(current_line)
    return "\n".join(desc_chunks)

def monochrome():
    """Disables color output by setting color codes to empty strings."""
    global Color # Ensure we modify the global class
    attrs = [a for a in dir(Color) if not a.startswith('__')]
    for attr in attrs:
        setattr(Color, attr, "")

# --- Core Logic Functions ---
def get_ioa_list(sdk: CustomIOA, filter_string: str = None):
    """Returns the list of IOA rule groups based upon the provided filter."""
    parameters = {"limit": 500}
    # If filter_string is provided, use it. Otherwise, get all groups.
    if filter_string:
        safe_filter = filter_string.replace("'", "\\'")
        parameters["filter"] = f"name:*'*{safe_filter}*'"
        print(f"  Querying rule groups using filter: {parameters['filter']}...")
    else:
        print("  Querying all rule groups (no filter)...")

    try:
        response = sdk.query_rule_groups_full(parameters=parameters)
        if response.get("status_code", 500) // 100 != 2:
             print(f"  Warning: API query for rule groups returned status {response.get('status_code', 'N/A')}.")
             if "errors" in response.get("body", {}):
                 for error in response["body"]["errors"]: print(f"    API Error: {error.get('message', 'Unknown error')}")
             return {"body": {"resources": []}, "status_code": response.get("status_code", 500), "errors": response.get("body", {}).get("errors")}
        all_resources = response.get("body", {}).get("resources", [])
        print(f"  Found {len(all_resources)} matching rule group(s).")
        return response
    except Exception as e:
        print(f"  Error during API call in get_ioa_list: {e}")
        return {"body": {"resources": []}, "status_code": 500, "errors": [{"message": str(e)}]}

def display_ioas(matches: dict, table_format: str):
    """Displays the IOA listing in tabular format."""
    # This function is reintroduced for --list_parent_ioas
    global Color # Use global Color class
    banner = [f"{Color.MAGENTA} _______ _     _ _______ _______  _____  _______    _____  _____  _______ ", "|       |     | |______   |   |     | |   |   |    |     | |     | |_____| ", f"|_____  |_____| ______|   |   |_____| |___|___|    |_____| |_____| |       |{Color.END}\n"]
    headers = {"name": f"{Color.BOLD}Custom IOA Name / ID / Comment{Color.END}", "description": f"{Color.BOLD}Description{Color.END}", "platform": f"{Color.BOLD}Platform / Status / Version{Color.END}", "rules": f"{Color.BOLD}Rules (Name / Version){Color.END}"}
    ioas = []
    resources = matches.get("body", {}).get("resources", [])
    if isinstance(resources, list):
        for match in resources:
            if not isinstance(match, dict): print(f"{Color.YELLOW}Warning: Skipping invalid item in resources list.{Color.END}"); continue
            ioa = {}; name_comment = f"\n{match.get('comment', '')}" if match.get('comment') else ""
            ioa["name"] = f"{match.get('name', 'N/A')}\n{Color.CYAN}{match.get('id', 'N/A')}{Color.END}{name_comment}"
            ioa["description"] = chunk_long_description(match.get("description", ""), 40)
            enabled = f"{Color.GREEN}Enabled{Color.END}" if match.get("enabled", False) else f"{Color.LIGHTRED}Disabled{Color.END}"
            platform_list = [f"{str(match.get('platform', 'N/A')).upper()}", f"{enabled}", f"Ver: {Color.BOLD}{match.get('version', 'N/A')}{Color.END}"]
            ioa["platform"] = "\n".join(platform_list)
            rules_list = match.get("rules", [])
            if isinstance(rules_list, list):
                 rules_display = [f"{rule.get('name', 'N/A')} ({rule.get('instance_version', 'N/A')})" for rule in rules_list if isinstance(rule, dict)]
                 ioa["rules"] = "\n".join(rules_display) if rules_display else f"{Color.YELLOW}No rules found.{Color.END}"
            else: ioa["rules"] = f"{Color.YELLOW}Invalid 'rules' format.{Color.END}"
            ioas.append(ioa)
    if not ioas:
        if matches.get("errors"): print(f"{Color.YELLOW}Could not display rule groups due to previous API errors.{Color.END}")
        else: fail = [f"\n{Color.BOLD}{Color.YELLOW}_  _ ____ _ _  _ ____ ____ _  _ _  _ ___ ____", r"|\ | |  | | |\ | | __ |___ |\/| |  | |   |__]", fr"| \| |__| | | \| |__] |___ |  | |__| |___ |__]{Color.END}"]; print("\n".join(fail)); print(f"{Color.YELLOW}No matching rule groups found.{Color.END}")
    else: print("\n".join(banner)); print(tabulate(ioas, headers=headers, tablefmt=table_format, disable_numparse=True))


def get_child_cid_details(mssp_sdk: FlightControl) -> dict:
    """Queries and returns a dictionary mapping accessible child CIDs to their names."""
    print("Querying for accessible children CIDs...")
    all_child_cids = []; offset = None; limit = 500
    kid_detail = {}
    while True: # Basic pagination loop
        params = {"limit": limit};
        if offset: params["offset"] = offset
        try: kid_lookup = mssp_sdk.query_children(**params)
        except Exception as e: print(f"Error querying children CIDs: {e}"); break
        if kid_lookup.get("status_code", 500) // 100 == 2:
            resources = kid_lookup.get("body", {}).get("resources", []);
            if not resources: break
            all_child_cids.extend(resources)
            if len(resources) < limit: break # Assume last page if less than limit returned
            offset = (offset + limit) if offset else limit # Basic offset increment
        else: print(f"Error querying children: {kid_lookup.get('body', {}).get('errors', 'Unknown')}"); break
    print(f"Discovered {len(all_child_cids)} potential children CIDs.")

    if all_child_cids:
        print("Fetching details for discovered children..."); child_details_list = []; chunk_size = 100
        for i in range(0, len(all_child_cids), chunk_size):
            chunk_ids = all_child_cids[i:i + chunk_size]
            try:
                child_detail_response = mssp_sdk.get_children(ids=chunk_ids)
                if child_detail_response.get("status_code", 500) // 100 == 2: child_details_list.extend(child_detail_response.get("body", {}).get("resources", []))
                else: print(f"Warning: Failed get_children chunk {i//chunk_size + 1}.")
            except Exception as e: print(f"Error fetching children chunk {i//chunk_size + 1}: {e}")
        for child in child_details_list: cid = child.get("child_cid"); name = child.get("name", "Unknown"); kid_detail[cid] = name
        print(f"Fetched details for {len(kid_detail)} children.")
    else: print(f"No children CIDs found/accessible.")
    return kid_detail

def display_child_cids(cid_details: dict, table_format: str):
    """Displays Child CIDs and Names in a table."""
    global Color
    if not cid_details:
        print("\nNo accessible child CIDs found to display.")
        return
    print("\n--- Accessible Child CIDs ---")
    headers = {"cid": f"{Color.BOLD}Child CID{Color.END}", "name": f"{Color.BOLD}Child Name{Color.END}"}
    data = [{"cid": cid, "name": name} for cid, name in cid_details.items()]
    print(tabulate(data, headers=headers, tablefmt=table_format))
    print("----------------------------")

def get_target_group_details(target_ioa_api: CustomIOA, target_group_id: str):
    """Helper function to get the details of a specific rule group by ID."""
    try:
        response = target_ioa_api.get_rule_groups(ids=[target_group_id])
        if response.get("status_code", 500) // 100 == 2:
            resources = response.get("body", {}).get("resources", [])
            if resources:
                return resources[0] # Return the first (and should be only) group details
            else:
                print(f"  Warning: get_rule_groups for ID {target_group_id} returned no resources.")
                return None
        else:
            print(f"  Warning: Failed get_rule_groups for ID {target_group_id}. Status: {response.get('status_code')}")
            return None
    except Exception as e:
        print(f"  Error in get_target_group_details for ID {target_group_id}: {e}")
        return None


def replicate_rules_to_target_group(source_ioa_rules: dict, target_cid: str, target_group_name: str):
    """
    Replicates rules from source groups into a single pre-existing target group.
    Creates rules as DISABLED, then attempts to enable them using the correct payload structure.
    Skips rules that already exist by name in the target group.
    Refreshes target group details after rule creation to get the latest version for the enable call.
    """
    global args # Access global args object
    target_ioa_api = None

    try:
        target_ioa_api = open_sdk(args.falcon_client_id, args.falcon_client_secret, args.base_url, "CustomIOA", member_cid=target_cid)
    except Exception as e: return {"body": {"resources": []}, "status_code": 500, "errors": [{"message": str(e)}]}

    source_resources = source_ioa_rules.get("body", {}).get("resources", [])
    if not isinstance(source_resources, list) or not source_resources:
        print(f"Warning: No valid source rule groups provided to process.")
        return get_ioa_list(target_ioa_api, f"name:'{target_group_name}'") # Return target group details if possible

    print(f"Attempting to replicate rules into target group '{target_group_name}' in CID {target_cid}...")

    # --- Find the PRE-EXISTING Target Group ---
    target_group_id = None
    initial_target_group_details = None # Store initial details
    try:
        fql_filter = f"name:'{target_group_name.replace('\'', '\\\'')}'"
        print(f"  Finding target group '{target_group_name}'...")
        existing_group_check = target_ioa_api.query_rule_groups_full(filter=fql_filter)
        if existing_group_check.get("status_code", 500) // 100 == 2:
            existing_details_list = existing_group_check.get("body", {}).get("resources", [])
            if existing_details_list:
                initial_target_group_details = existing_details_list[0] # Store the initial details
                target_group_id = initial_target_group_details.get("id")
                initial_target_group_version = initial_target_group_details.get("version") # Get the initial group version
                if len(existing_details_list) > 1: print(f"  Warning: Found multiple groups named '{target_group_name}'. Using first ID: {target_group_id}.")
                print(f"  Found target group ID: {target_group_id} (Initial Version: {initial_target_group_version}).")
            else:
                print(f"  Error: Target group '{target_group_name}' not found in CID {target_cid}. Rules cannot be replicated.")
                return get_ioa_list(target_ioa_api, None) # Return empty list or current state
        else:
            print(f"  Warning: Failed query for target group. Status: {existing_group_check.get('status_code', 'N/A')}.")
            return get_ioa_list(target_ioa_api, None)
    except Exception as e:
        print(f"  Error finding target group: {e}."); return get_ioa_list(target_ioa_api, None)

    # Exit if target group wasn't found
    if not target_group_id:
         print(f"  Error: Could not retrieve target group ID. Aborting replication for this CID.")
         return get_ioa_list(target_ioa_api, None)

    # --- Get Existing Rules in Target Group for Duplicate Check ---
    existing_target_rule_names = set()
    try:
        print(f"  Querying existing rules in target group {target_group_id}...")
        # Use query_rules and get_rules with correct limit
        query_rules_resp = target_ioa_api.query_rules(filter=f"rulegroup_id:'{target_group_id}'", limit=500) # Query for IDs first (limit 500)
        if query_rules_resp.get("status_code", 500) // 100 == 2:
            rule_ids = query_rules_resp.get("body", {}).get("resources", [])
            if rule_ids:
                print(f"    Found {len(rule_ids)} existing rule IDs. Fetching details...")
                # Fetch details in chunks if necessary (get_rules limit is often 500)
                chunk_size = 500
                all_rule_details = []
                for i in range(0, len(rule_ids), chunk_size):
                    id_chunk = rule_ids[i:i+chunk_size]
                    get_rules_resp = target_ioa_api.get_rules(ids=id_chunk) # Get details by ID
                    if get_rules_resp.get("status_code", 500) // 100 == 2:
                        all_rule_details.extend(get_rules_resp.get("body", {}).get("resources", []))
                    else:
                        print(f"    Warning: Failed to get details for rule ID chunk. Status: {get_rules_resp.get('status_code')}")
                # Populate the set of names
                for rule in all_rule_details:
                    if rule.get("name"):
                        existing_target_rule_names.add(rule["name"])
                print(f"  Found {len(existing_target_rule_names)} existing rules with names in target group.")
            else:
                print("    No existing rules found in target group.")
        else:
             print(f"  Warning: Failed to query existing rule IDs in target group. Status: {query_rules_resp.get('status_code')}. Duplicate check might be incomplete.")
    except Exception as e:
        print(f"  Warning: Error querying existing rules: {e}. Duplicate check might be incomplete.")


    # --- Iterate Source Groups and Replicate Rules ---
    rules_processed = 0; rules_replicated = 0; rules_skipped_duplicate = 0; rules_skipped_missing_data = 0; rules_failed_creation = 0
    rules_enabled_success = 0; rules_enabled_fail = 0 # Counters for enabling attempts

    for source_group in source_resources:
        source_group_name = source_group.get('name', 'Unknown Source Group')
        source_rules = source_group.get("rules", [])
        if not isinstance(source_rules, list) or not source_rules:
            print(f"  Skipping source group '{source_group_name}': No rules found or invalid format.")
            continue

        print(f"  Processing {len(source_rules)} rules from source group '{source_group_name}'...")
        for rule in source_rules:
            rules_processed += 1
            rule_name = rule.get("name")
            if not rule_name:
                print("      Skipping rule: Missing name in source data.")
                rules_skipped_missing_data += 1
                continue

            # --- Check for duplicates in the target group ---
            if rule_name in existing_target_rule_names:
                print(f"      Skipping rule '{rule_name}': Already exists in target group {target_group_id}.")
                rules_skipped_duplicate += 1
                continue

            # --- Construct payload to create the rule in the target group ---
            # Create rule DISABLED first, then attempt to enable
            rule_body = {
                "description": rule.get("description", ""),
                "disposition_id": rule.get("disposition_id"),
                "comment": f"Replicated from source rule ID: {rule.get('id', 'N/A')} in group '{source_group_name}'",
                "field_values": rule.get("field_values", []),
                "pattern_severity": rule.get("pattern_severity"),
                "name": rule_name, # Use original name
                "rulegroup_id": target_group_id, # Assign to the target group
                "ruletype_id": rule.get("ruletype_id"),
                "enabled": False # *** Create rule as DISABLED initially ***
            }
            # Basic validation
            required = ["disposition_id", "field_values", "pattern_severity", "name", "rulegroup_id", "ruletype_id"]
            missing = [f for f in required if rule_body.get(f) is None or (isinstance(rule_body.get(f), list) and not rule_body.get(f))]
            if missing:
                print(f"      Skipping rule '{rule_name}': Missing required fields: {', '.join(missing)}")
                rules_skipped_missing_data += 1; continue

            # Attempt to create the rule
            print(f"      Attempting to replicate rule '{rule_name}' (as disabled)...")
            new_rule_id = None
            new_rule_version = None
            new_rule_details = None # Store full details
            try:
                rule_create_resp = target_ioa_api.create_rule(body=rule_body)
                # More robust check of create_rule response
                if (rule_create_resp.get("status_code", 500) in [200, 201] and
                        isinstance(rule_create_resp.get("body", {}).get("resources"), list) and
                        rule_create_resp["body"]["resources"]):

                    new_rule_details = rule_create_resp["body"]["resources"][0]
                    # Use instance_id as the rule ID
                    new_rule_id = new_rule_details.get("instance_id") # Changed from "id"
                    # Use instance_version as the rule version
                    new_rule_version = new_rule_details.get("instance_version") # Changed from "version"

                    if new_rule_id and new_rule_version is not None:
                        print(f"      Successfully replicated rule '{rule_name}' (ID: {new_rule_id}, Version: {new_rule_version}).")
                        rules_replicated += 1
                        existing_target_rule_names.add(rule_name) # Add to set to prevent duplicates within the same run

                        # Refresh target group details to get potentially updated version
                        print(f"          Refreshing target group details for {target_group_id}...")
                        # Optional: Add a small delay if needed
                        # time.sleep(1)
                        refreshed_target_group_details = get_target_group_details(target_ioa_api, target_group_id)
                        current_target_group_version = None
                        if refreshed_target_group_details:
                            current_target_group_version = refreshed_target_group_details.get("version")
                            print(f"          Refreshed target group version: {current_target_group_version}")
                        else:
                            print(f"          Warning: Failed to refresh target group details. Cannot attempt enable for rule {new_rule_id}.")
                            rules_enabled_fail += 1
                            continue # Skip enabling attempt if refresh failed

                        # --- Attempt to ENABLE the newly created rule using the REFRESHED group version ---
                        print(f"          Attempting to enable rule '{rule_name}' (ID: {new_rule_id}, Version: {new_rule_version}) using group version {current_target_group_version}...")

                        # Construct the inner rule update payload
                        update_rule_payload = {
                            "instance_id": new_rule_id, # Use the rule's instance ID
                            "rulegroup_version": int(current_target_group_version), # Use the REFRESHED GROUP's version
                            "enabled": True, # The change
                            # Include other required fields based on schema
                            "name": rule_name,
                            "description": rule_body["description"],
                            "disposition_id": rule_body["disposition_id"],
                            "field_values": rule_body["field_values"],
                            "pattern_severity": rule_body["pattern_severity"]
                        }
                        # Remove None values just in case
                        update_rule_payload_clean = {k: v for k, v in update_rule_payload.items() if v is not None}

                        # *** START FIX: Construct the TOP-LEVEL body according to Swagger ***
                        update_body = {
                            "comment": f"Enabling rule {rule_name} post-replication via script.",
                            "rulegroup_id": target_group_id, # Add the group ID here
                            "rulegroup_version": int(current_target_group_version), # Add the group version here
                            "rule_updates": [update_rule_payload_clean] # The list of rule modifications
                        }
                        # *** END FIX ***

                        # Check required fields within the inner rule update object
                        required_rule_fields = ["instance_id", "rulegroup_version", "enabled", "name", "description", "disposition_id", "field_values", "pattern_severity"]
                        missing_rule_fields = [f for f in required_rule_fields if f not in update_rule_payload_clean]

                        if missing_rule_fields:
                            print(f"          Cannot enable rule: Missing fields for inner update payload: {', '.join(missing_rule_fields)}.")
                            rules_enabled_fail += 1
                        else:
                            try:
                                # Use update_rules (plural) and pass the structured body
                                print(f"            Sending update_rules request body: {json.dumps(update_body, indent=2)}") # Debug log before sending
                                update_rule_resp = target_ioa_api.update_rules(
                                    body=update_body
                                )
                                if update_rule_resp.get("status_code", 500) // 100 == 2:
                                    print(f"          Rule {new_rule_id} enabled successfully.")
                                    rules_enabled_success += 1
                                else:
                                    errors = update_rule_resp.get("body", {}).get("errors", [{}]); error_msg = errors[0].get("message", "Unknown")
                                    print(f"          Failed rule enable. Status: {update_rule_resp.get('status_code')}, Error: {error_msg}")
                                    # Request body already printed before sending
                                    print(f"            Response Body: {json.dumps(update_rule_resp.get('body', {}), indent=2)}") # Debug log
                                    rules_enabled_fail += 1
                            except Exception as e_update:
                                print(f"          Error calling update_rules for enabling: {e_update}")
                                rules_enabled_fail += 1
                    else:
                        # This block now catches the case where create succeeded (200/201) but didn't return expected resources
                        print(f"      Failed replicating rule '{rule_name}': Create successful but could not get ID/Version from response.")
                        print(f"        Response Body: {json.dumps(rule_create_resp.get('body', {}), indent=2)}")
                        rules_failed_creation += 1
                else:
                    # This block catches cases where create failed (e.g., 4xx/5xx status)
                    errors = rule_create_resp.get("body", {}).get("errors", [{}]); error_msg = errors[0].get("message", "Unknown")
                    print(f"      Failed replicating rule '{rule_name}'. Status: {rule_create_resp.get('status_code')}, Error: {error_msg}")
                    rules_failed_creation += 1
            except Exception as e_create:
                print(f"      Error calling create_rule for '{rule_name}': {e_create}")
                rules_failed_creation += 1

    # --- Print Summary ---
    print(f"\n--- Rule Replication Summary for CID {target_cid} (Target Group: {target_group_name} / {target_group_id}) ---")
    print(f"Source Groups Processed:   {len(source_resources)}")
    print(f"Total Rules Processed:     {rules_processed}")
    print(f"Rules Replicated:          {rules_replicated}")
    print(f"Rules Skipped (Duplicate): {rules_skipped_duplicate}")
    print(f"Rules Skipped (Missing):   {rules_skipped_missing_data}")
    print(f"Rules Failed Replication:  {rules_failed_creation}")
    print(f"Rules Enabled Success:     {rules_enabled_success}") # Count successful enable attempts
    print(f"Rules Enabled Fail:        {rules_enabled_fail}")    # Count failed enable attempts
    print("------------------------------------")

    print(f"\nRetrieving final list of rule groups from target CID: {target_cid}")
    # Optionally filter just for the target group to show its final state
    return get_ioa_list(target_ioa_api, filter_string=f"id:'{target_group_id}'")


def delete_ioas(sdk: CustomIOA, ids_to_delete: str, filter_string: str = None):
    """Deletes specified IOA rule groups."""
    id_list = [item.strip() for item in ids_to_delete.split(",") if item.strip()]
    if not id_list: print(f"Warning: No valid rule group IDs provided for deletion."); return get_ioa_list(sdk, filter_string)
    print(f"Attempting to delete {len(id_list)} rule group(s): {', '.join(id_list)}")
    try: delete_result = sdk.delete_rule_groups(ids=id_list)
    except Exception as e: print(f"Error calling delete_rule_groups API: {e}"); return get_ioa_list(sdk, filter_string)
    status_code = delete_result.get("status_code")
    if status_code is not None and status_code // 100 == 2: print(f"\nSuccessfully requested deletion for {len(id_list)} rule group(s).")
    else: print(f"\nError during deletion request. Status: {status_code if status_code else 'N/A'}")
    if "body" in delete_result and isinstance(delete_result["body"].get("errors"), list) and delete_result["body"]["errors"]:
        print(f"Deletion Errors Reported:")
        for error in delete_result["body"]["errors"]: print(f"  Code: {error.get('code', 'N/A')}, Message: {error.get('message', 'Unknown')}, ID: {error.get('id', '')}")
    elif status_code is not None and status_code // 100 != 2 and "body" not in delete_result.get("body", {}).get("errors", []): print(f"  Response Body: {json.dumps(delete_result.get('body', 'No body'), indent=2)}")
    print(f"\nRetrieving updated list of rule groups...")
    return get_ioa_list(sdk, filter_string) # Return potentially filtered list after delete


# --- Main Execution Block ---
if __name__ == "__main__":
    args = consume_arguments()
    if args.nocolor: monochrome() # Call function to disable color

    # --- SDK Initialization (Source Tenant) ---
    print("Connecting to source Falcon tenant...")
    falcon_ioa_source = open_sdk(args.falcon_client_id, args.falcon_client_secret, args.base_url, "CustomIOA")
    print("Testing source tenant connection..."); test_conn = falcon_ioa_source.query_rule_types(limit=1)
    if test_conn.get("status_code", 500) // 100 != 2: print(f"Error connecting to source tenant (Custom IOA: Read)."); sys.exit(1)
    print(f"Source connection successful.")

    # --- List Parent IOAs Action ---
    if args.list_parent_ioas:
        print("\n--- Listing Parent Tenant IOA Groups ---")
        parent_ioas = get_ioa_list(falcon_ioa_source, args.filter)
        display_ioas(parent_ioas, args.table_format) # Use display function
        print("--- Parent IOA Listing Complete ---")
        sys.exit(0) # Exit after listing

    # --- List Child CIDs Action ---
    if args.list_cids:
        print("\n--- Listing Child CIDs ---")
        mssp_sdk = open_mssp(args.falcon_client_id, args.falcon_client_secret, args.base_url)
        child_details = get_child_cid_details(mssp_sdk)
        display_child_cids(child_details, args.table_format) # Use display function
        print("--- Child CID Listing Complete ---")
        sys.exit(0) # Exit after listing

    # --- Initial IOA Rule Retrieval (Source Tenant) ---
    ioa_rules = {"body": {"resources": []}} # Default
    # Retrieve source rules if replicating (either filtered or all)
    if args.replicate_rules or args.replicate_all_parent_rules:
        source_filter = args.filter if args.replicate_rules else None # Use filter only for specific replication
        print(f"\nRetrieving source IOA rule groups {'matching filter: \"' + args.filter + '\"' if source_filter else '(all groups)'}...")
        ioa_rules = get_ioa_list(falcon_ioa_source, source_filter)
        if ioa_rules.get("status_code", 500) // 100 != 2: print(f"Fatal Error: Could not retrieve rule groups from source. Exiting."); sys.exit(1)
        initial_rule_count = len(ioa_rules.get("body", {}).get("resources", []))
        print(f"Found {initial_rule_count} source groups.")
        if initial_rule_count == 0: print(f"Warning: No source groups found. No rules will be replicated.")

    # --- MSSP Child Handling ---
    DO_MSSP = False; kid_detail = {}; target_cids_for_actions = []
    # Perform detection only if needed (-m or --all_cids specified)
    if args.managed_targets or args.all_cids:
        print("\n--- MSSP Target Handling ---")
        mssp_sdk = open_mssp(args.falcon_client_id, args.falcon_client_secret, args.base_url)
        kid_detail = get_child_cid_details(mssp_sdk) # Use helper function

        if args.all_cids:
            target_cids_for_actions = list(kid_detail.keys())
            print(f"Using all {len(target_cids_for_actions)} detected child CIDs as targets.")
            if target_cids_for_actions: DO_MSSP = True
        elif args.managed_targets:
            user_targets = [cid.strip() for cid in args.managed_targets.split(",") if cid.strip()]
            print(f"Validating {len(user_targets)} specified target CID(s)...")
            for target in user_targets:
                if target in kid_detail: target_cids_for_actions.append(target); print(f"  - Validated: {target} ({kid_detail[target]})")
                else: print(f"  - Warning: Target CID '{target}' not found/accessible. Skipping.")
            if target_cids_for_actions: DO_MSSP = True; print(f"Proceeding with actions on {len(target_cids_for_actions)} validated target CIDs.")
            else: print(f"Warning: None of the specified target CIDs validated. No MSSP actions possible.")
        print("--- End MSSP Target Handling ---")

    # --- Action Execution ---
    final_source_rules_state = ioa_rules # Default

    # Replicate Rules Action (either filtered or all)
    if args.replicate_rules or args.replicate_all_parent_rules:
        action_verb = "Replicate Rules"
        if initial_rule_count == 0:
            print(f"\n--- Skipping {action_verb} Operation (No source rules found) ---")
        elif DO_MSSP: # Target specific or all CIDs
            if target_cids_for_actions:
                print(f"\n--- Starting {action_verb} Operation on {len(target_cids_for_actions)} Child Tenant(s) ---")
                for target_cid in target_cids_for_actions:
                    child_name = f" ({kid_detail.get(target_cid, '')})"
                    print(f"\n===== {action_verb} in Target CID: {target_cid}{child_name} ====")
                    # Call the refactored function
                    replicate_rules_to_target_group(ioa_rules, target_cid, args.target_group_name)
                    print(f"===== Finished {action_verb} for CID: {target_cid}{child_name} ====")
            else: print(f"\nSkipping MSSP {action_verb} operation (no validated targets).")
        else: # Non-MSSP Action (Source Tenant)
            print(f"\n--- Starting {action_verb} Operation within Source Tenant ---")
            # Replicating rules from source to source doesn't make sense without a different target group name
            print("Warning: Rule replication within the same tenant requires a different target group name specified via --target_group_name.")
            # processed_results = replicate_rules_to_target_group(ioa_rules, None, args.target_group_name)
            # final_source_rules_state = processed_results # Update source state
        print(f"--- {action_verb} Operation Complete ---")

    # Delete Action
    if args.delete_group:
        delete_ids = args.delete_ids.strip() if args.delete_ids else None
        if not delete_ids: print(f"\n--- Skipping Delete Operation (No IDs via --delete_ids) ---")
        elif DO_MSSP: # Target specific or all CIDs
            if target_cids_for_actions:
                print(f"\n--- Starting Delete Operation in {len(target_cids_for_actions)} Child Tenant(s) ---")
                print(f"Note: Deleting specified IDs in ALL targeted CIDs.")
                for target_cid in target_cids_for_actions:
                    child_name = f" ({kid_detail.get(target_cid, '')})"
                    print(f"\n===== Deleting in Target CID: {target_cid}{child_name} ====")
                    try:
                        target_delete_api = open_sdk(args.falcon_client_id, args.falcon_client_secret, args.base_url, "CustomIOA", member_cid=target_cid)
                        delete_ioas(target_delete_api, delete_ids, args.filter) # Display happens inside
                        print(f"===== Finished Deletion for CID: {target_cid}{child_name} ====")
                    except Exception as e: print(f"Error during delete for CID {target_cid}: {e}")
            else: print(f"\nSkipping MSSP delete operation (no validated targets).")
        else: # Non-MSSP Delete
            print(f"\n--- Starting Delete Operation in Source Tenant ---")
            deleted_results = delete_ioas(falcon_ioa_source, delete_ids, args.filter)
            final_source_rules_state = deleted_results # Update source state
        print(f"--- Delete Operation Complete ---")

    # --- Final Output (Optional - List final state) ---
    # Commented out by default to reduce noise, uncomment if needed
    # print("\n--- Final State ---")
    # action_taken = args.replicate_rules or args.replicate_all_parent_rules or args.delete_group # Adjusted actions
    # if not action_taken and not args.list_cids and not args.list_parent_ioas: # Show if no action taken
    #      print(f"Listing Final IOA Rule Groups (Source Tenant - No Action Taken):")
    #      display_ioas(final_source_rules_state, args.table_format) # Show initial state

    print("\nScript finished.")
