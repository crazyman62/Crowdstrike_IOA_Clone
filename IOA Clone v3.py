# Import necessary modules
import sys
import json
import time # Import time for potential delays if needed
import os
import platform
from argparse import ArgumentParser, RawTextHelpFormatter, Action

# Import necessary FalconPy services
try:
    from falconpy import CustomIOA, FlightControl
except ImportError as e:
    print("Error: Required library 'crowdstrike-falconpy' not found.")
    print("Please install it using: pip install crowdstrike-falconpy")
    sys.exit(1)

# Import tabulate for formatted output
try:
    from tabulate import tabulate
except ImportError as e:
    print("Error: Required library 'tabulate' not found.")
    print("Please install it using: pip install tabulate")
    sys.exit(1)

# Import colorama for cross-platform color support
try:
    import colorama
except ImportError as e:
    print("Error: Required library 'colorama' not found.")
    print("Please install it using: pip install colorama")
    sys.exit(1)


# --- Global Summary Tracker ---
class ExecutionSummary:
    """Class to hold overall summary statistics for the script run."""
    def __init__(self):
        self.total_cids_processed = 0
        self.cids_with_errors = set()
        self.total_rules_processed = 0
        self.total_rules_created = 0
        self.total_rules_updated = 0
        self.total_rules_enabled_after_create = 0 # New counter
        self.total_rules_enable_failed = 0      # New counter
        self.total_rules_skipped_missing_data = 0
        self.total_rules_failed_creation = 0
        self.total_rules_failed_update = 0
        self.total_groups_deleted = 0
        self.total_groups_delete_failed = 0
        self.target_group_details = {} # Store details like {cid_key: {group_id: '...', group_name: '...'}}

    def update_cid_summary(self, cid, results):
        """Update overall summary from a single CID's processing results."""
        if not isinstance(results, dict):
            print(f"DEBUG: Invalid results type for CID {cid}: {type(results)}")
            return

        self.total_cids_processed += 1
        cid_key = cid if cid else "Source Tenant" # Use "Source Tenant" as key if cid is None
        if results.get("errors"):
            self.cids_with_errors.add(cid_key)
        self.total_rules_processed += results.get("processed", 0)
        self.total_rules_created += results.get("created", 0)
        self.total_rules_updated += results.get("updated", 0)
        self.total_rules_enabled_after_create += results.get("enabled_after_create", 0) # Add new count
        self.total_rules_enable_failed += results.get("enable_failed", 0)            # Add new count
        self.total_rules_skipped_missing_data += results.get("skipped_missing_data", 0)
        self.total_rules_failed_creation += results.get("failed_creation", 0)
        self.total_rules_failed_update += results.get("failed_update", 0)
        # Store target group info if available
        if "target_group_id" in results and results.get("target_group_id"):
             self.target_group_details[cid_key] = {
                "group_id": results.get("target_group_id"),
                "group_name": results.get("target_group_name")
            }


    def update_delete_summary(self, cid, delete_results):
        """Update overall summary from a single CID's deletion results."""
        if not isinstance(delete_results, dict):
            print(f"DEBUG: Invalid delete_results type for CID {cid}: {type(delete_results)}")
            return

        cid_key = cid if cid else "Source Tenant"
        self.total_groups_deleted += delete_results.get("deleted_count", 0)
        self.total_groups_delete_failed += delete_results.get("failed_count", 0)
        if delete_results.get("errors"):
             self.cids_with_errors.add(cid_key)


    def print_summary(self):
        """Prints the final aggregated summary of the script execution."""
        global Color # Use global Color class for formatting
        print(f"\n{Color.BOLD}--- Overall Execution Summary ---{Color.END}")
        print(f"Total CIDs/Tenants Processed: {self.total_cids_processed}")
        if self.cids_with_errors:
             # Sort the set for consistent output order
             sorted_errors = sorted(list(self.cids_with_errors))
             print(f"{Color.RED}CIDs/Tenants with Errors during processing:{Color.END} {', '.join(sorted_errors)}")

        print(f"\n{Color.UNDERLINE}Rule Operations Summary:{Color.END}")
        print(f"  Total Rules Processed (from source): {self.total_rules_processed}")
        print(f"  {Color.GREEN}Rules Created in Target(s):{Color.END}        {self.total_rules_created}")
        print(f"  {Color.LIGHTGREEN}Rules Enabled (after create):{Color.END}    {self.total_rules_enabled_after_create}") # New line
        print(f"  {Color.CYAN}Rules Updated in Target(s):{Color.END}        {self.total_rules_updated}")
        print(f"  {Color.YELLOW}Rules Skipped (Missing Data):{Color.END}    {self.total_rules_skipped_missing_data}")
        print(f"  {Color.RED}Rules Failed Creation:{Color.END}           {self.total_rules_failed_creation}")
        print(f"  {Color.RED}Rules Failed Update:{Color.END}             {self.total_rules_failed_update}")
        print(f"  {Color.LIGHTRED}Rules Failed Enable (after create):{Color.END}{self.total_rules_enable_failed}") # New line

        if self.total_groups_deleted > 0 or self.total_groups_delete_failed > 0:
            print(f"\n{Color.UNDERLINE}Rule Group Deletion Summary:{Color.END}")
            print(f"  {Color.GREEN}Rule Groups Deleted Successfully:{Color.END} {self.total_groups_deleted}")
            print(f"  {Color.RED}Rule Groups Failed Deletion:{Color.END}    {self.total_groups_delete_failed}")

        if self.target_group_details:
             print(f"\n{Color.UNDERLINE}Target Group Information:{Color.END}")
             # Sort by CID/Tenant key for consistent output
             for cid_key, details in sorted(self.target_group_details.items()):
                 cid_display = f"CID {Color.DARKCYAN}{cid_key}{Color.END}" if cid_key != "Source Tenant" else f"{Color.MAGENTA}Source Tenant{Color.END}"
                 print(f"  {cid_display}: Target Group '{details['group_name']}' (ID: {details['group_id']})")

        print(f"{Color.BOLD}--- End of Summary ---{Color.END}")


# Initialize global summary object
summary_tracker = ExecutionSummary()


# --- Color Handling (using colorama) ---
class BaseColor:
    """Base class for color codes."""
    # ANSI codes - colorama will translate them on Windows
    PURPLE = "\033[95m"; CYAN = "\033[96m"; DARKCYAN = "\033[36m"
    MAGENTA = "\033[35m"; BLUE = "\033[34m"; LIGHTBLUE = "\033[94m"
    GREEN = "\033[32m"; LIGHTGREEN = "\033[92m"; LIGHTYELLOW = "\033[93m"
    YELLOW = "\033[33m"; RED = "\033[31m"; LIGHTRED = "\033[91m"
    BOLD = "\033[1m"; UNDERLINE = "\033[4m"; END = "\033[0m"

class NoColor:
    """Class to disable color codes by providing empty strings."""
    PURPLE = ""; CYAN = ""; DARKCYAN = ""
    MAGENTA = ""; BLUE = ""; LIGHTBLUE = ""
    GREEN = ""; LIGHTGREEN = ""; LIGHTYELLOW = ""
    YELLOW = ""; RED = ""; LIGHTRED = ""
    BOLD = ""; UNDERLINE = ""; END = ""

# --- Global Color Object ---
Color = BaseColor() # Placeholder, initialized after arg parsing

def initialize_colors(nocolor_arg):
    """Sets the global Color object based --nocolor arg."""
    global Color
    if nocolor_arg:
        print("Color output disabled via --nocolor argument.")
        Color = NoColor()
        # colorama.deinit() # Not strictly necessary, but good practice
    else:
        # Initialize colorama. autoreset=True adds END automatically after each color print.
        # Let's keep explicit END for complex strings and consistency.
        colorama.init(autoreset=False)
        Color = BaseColor() # Use standard ANSI codes
        print("Color output enabled (using colorama for cross-platform support).")


# --- Argument Parser Action for Mutually Exclusive Groups ---
class MutuallyExclusiveAction(Action):
    """Custom argparse action for mutually exclusive flags."""
    _ACTION_GROUP_TRACKER_NAME = '_mutually_exclusive_action_group_tracker'

    def __init__(self, option_strings, dest, nargs=None, **kwargs):
        if nargs is not None: raise ValueError("nargs not allowed")
        super().__init__(option_strings, dest, nargs=0, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        action_group_tracker = getattr(namespace, self._ACTION_GROUP_TRACKER_NAME, None)
        if action_group_tracker is None:
            action_group_tracker = set()
            setattr(namespace, self._ACTION_GROUP_TRACKER_NAME, action_group_tracker)
        # Check for conflicts
        if action_group_tracker and self.dest not in action_group_tracker:
            conflicting_options = ', '.join('--' + opt.replace('_', '-') for opt in action_group_tracker)
            parser.error(f"argument {option_string}: not allowed with argument {conflicting_options}")
        # Add this action to the tracker and set its flag to True
        action_group_tracker.add(self.dest)
        setattr(namespace, self.dest, True)


# --- Argument Parsing ---
def consume_arguments():
    """Consume and validate command-line arguments."""
    parser = ArgumentParser(description="List, Replicate/Update IOA Rules, or Delete Rule Groups between parent and child CIDs.",
                            formatter_class=RawTextHelpFormatter)
    # Core arguments
    parser.add_argument("-n", "--nocolor", help="Force disable color output", action="store_true", default=False)
    parser.add_argument("-b", "--base_url", help="CrowdStrike API Base URL (e.g., 'us-1', 'us-2'). Default: 'auto'", default="auto")
    parser.add_argument("-t", "--table_format", help="Tabular display format for listings. Default: 'fancy_grid'", default="fancy_grid")

    # --- Filters (Apply to Source/Parent) ---
    filter_group = parser.add_argument_group("source filters (for --list_parent_ioas, --replicate_rules)")
    filter_exclusive_group = filter_group.add_mutually_exclusive_group()
    filter_exclusive_group.add_argument("-f", "--filter", help="String to filter SOURCE rule groups by name.", default=None)
    filter_exclusive_group.add_argument("--rule_name", help="Filter for a SINGLE rule name within source groups (used with --replicate_rules).", default=None)

    # --- Actions (Mutually Exclusive) ---
    action_group = parser.add_argument_group("actions (choose one)")
    action_group.add_argument("--list_cids", help="List all accessible child CIDs and their names.", action=MutuallyExclusiveAction, dest='list_cids', default=False)
    action_group.add_argument("--list_parent_ioas", help="List Custom IOA groups in the parent tenant (use -f to filter).", action=MutuallyExclusiveAction, dest='list_parent_ioas', default=False)
    action_group.add_argument("-r", "--replicate_rules", help="Replicate/Update rules from filtered/single source rule into a target group.", action=MutuallyExclusiveAction, dest='replicate_rules', default=False)
    action_group.add_argument("--replicate_all_parent_rules", help="Replicate/Update rules from ALL source groups into a target group.", action=MutuallyExclusiveAction, dest='replicate_all_parent_rules', default=False)
    action_group.add_argument("-d", "--delete_group", help="Delete specified rule group IDs in the target tenant(s)", action=MutuallyExclusiveAction, dest='delete_group', default=False)
    action_group.add_argument("--delete_ids", help="Comma-separated list of rule group IDs to delete (required for --delete_group)", default=None)

    # --- Action Modifiers ---
    mod_group = parser.add_argument_group("action modifiers")
    mod_group.add_argument("--target_group_name", help="Name of the PRE-EXISTING target rule group in child CIDs (Required for replication actions).", default=None)

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

    # Initialize action flags safely
    parsed_args.list_cids = getattr(parsed_args, 'list_cids', False)
    parsed_args.list_parent_ioas = getattr(parsed_args, 'list_parent_ioas', False)
    parsed_args.replicate_rules = getattr(parsed_args, 'replicate_rules', False)
    parsed_args.replicate_all_parent_rules = getattr(parsed_args, 'replicate_all_parent_rules', False)
    parsed_args.delete_group = getattr(parsed_args, 'delete_group', False)

    # Post-parsing validation
    if parsed_args.replicate_rules and not (parsed_args.filter or parsed_args.rule_name):
        parser.error("-f/--filter OR --rule_name is required when using --replicate_rules.")
    if parsed_args.replicate_all_parent_rules and parsed_args.rule_name:
         parser.error("--rule_name cannot be used with --replicate_all_parent_rules.")
    if (parsed_args.replicate_rules or parsed_args.replicate_all_parent_rules) and not parsed_args.target_group_name:
        parser.error("--target_group_name is required when using --replicate_rules or --replicate_all_parent_rules.")
    if parsed_args.delete_group and not parsed_args.delete_ids:
         parser.error("--delete_ids is required when using --delete_group.")
    # Ensure an action or listing is specified
    if not any([parsed_args.list_cids, parsed_args.list_parent_ioas, parsed_args.replicate_rules, parsed_args.replicate_all_parent_rules, parsed_args.delete_group]):
         parser.error("No action specified. Choose one: --list_cids, --list_parent_ioas, --replicate_rules, --replicate_all_parent_rules, or --delete_group.")

    return parsed_args

# --- SDK Initialization ---
def open_sdk(client_id: str, client_secret: str, base: str, service: str, member_cid: str = None):
    """Creates an instance of a specified FalconPy Service Class."""
    global Color
    init_params = {"client_id": client_id, "client_secret": client_secret, "base_url": base}
    if member_cid: init_params["member_cid"] = member_cid
    try:
        ServiceClass = getattr(__import__('falconpy', fromlist=[service]), service)
        cid_str = f" for CID {Color.DARKCYAN}{member_cid}{Color.END}" if member_cid else f" for {Color.MAGENTA}source tenant{Color.END}"
        print(f"  Initializing {Color.BOLD}{service}{Color.END} SDK{cid_str}...")
        # Reduce verbosity for production, enable for debugging
        sdk_instance = ServiceClass(**init_params, debug=False, verbose=False)
        return sdk_instance
    except (ImportError, AttributeError):
        # Should have been caught by initial imports, but safety check
        print(f"{Color.RED}Fatal Error: Invalid FalconPy service: '{service}'.{Color.END}")
        sys.exit(1)
    except Exception as e:
        print(f"{Color.RED}Fatal Error: Failed to initialize Falcon {service} SDK: {e}{Color.END}")
        sys.exit(1)


def open_mssp(client_id: str, client_secret: str, base: str):
    """Creates an instance of the Flight Control Service Class."""
    global Color
    try:
        print(f"  Initializing {Color.BOLD}FlightControl{Color.END} SDK...")
        mssp_sdk = FlightControl(client_id=client_id, client_secret=client_secret, base_url=base, debug=False, verbose=False)
        return mssp_sdk
    except Exception as e:
        print(f"{Color.RED}Fatal Error: Failed to initialize Flight Control SDK: {e}{Color.END}")
        sys.exit(1)

# --- Helper Functions ---
def chunk_long_description(desc, col_width) -> str:
    """Chunks a long string by delimiting with CR based upon column length."""
    if not isinstance(desc, str): return ""
    desc_chunks = []; current_line = ""
    for word in desc.split():
        word = word.strip();
        if not word: continue
        # Handle very long words
        while len(word) > col_width:
            if current_line: desc_chunks.append(current_line) # Add previous line first
            desc_chunks.append(word[:col_width])
            word = word[col_width:]
            current_line = "" # Reset current line after breaking long word
        # Handle normal words
        if len(current_line) + len(word) + (1 if current_line else 0) > col_width:
            if current_line: desc_chunks.append(current_line)
            current_line = word
        else:
            current_line += (" " + word) if current_line else word
    if current_line: desc_chunks.append(current_line)
    return "\n".join(desc_chunks)

# --- Core Logic Functions ---
def get_ioa_list(sdk: CustomIOA, filter_string: str = None):
    """Returns the list of IOA rule groups based upon the provided filter."""
    global Color
    parameters = {"limit": 500} # Max limit per query
    if filter_string:
        safe_filter = filter_string.replace("'", "\\'")
        parameters["filter"] = f"name:*'*{safe_filter}*'"
        print(f"  Querying rule groups using filter: {parameters['filter']}...")
    else:
        print("  Querying all rule groups (no filter)...")

    all_resources = []
    parameters["offset"] = 0
    while True:
        try:
            response = sdk.query_rule_groups_full(parameters=parameters)
            status_code = response.get("status_code", 500)
            body = response.get("body", {})

            if status_code // 100 != 2:
                 print(f"  {Color.YELLOW}Warning: API query for rule groups returned status {status_code}.{Color.END}")
                 errors = body.get("errors", [{"message": "Unknown API error"}])
                 for error in errors: print(f"    {Color.RED}API Error: {error.get('message', 'Unknown error')}{Color.END}")
                 return {"body": {"resources": []}, "status_code": status_code, "errors": errors}

            resources = body.get("resources", [])
            all_resources.extend(resources)

            meta = body.get("meta", {}).get("pagination", {})
            total = meta.get("total", len(all_resources))
            limit = meta.get("limit", 500)
            offset = meta.get("offset", parameters["offset"]) # API returns current offset

            if not resources or len(all_resources) >= total:
                break # Exit if no more resources or we have fetched the total reported

            parameters["offset"] = offset + limit # Prepare for next page

        except Exception as e:
            print(f"  {Color.RED}Error during API call in get_ioa_list: {e}{Color.END}")
            return {"body": {"resources": []}, "status_code": 500, "errors": [{"message": str(e)}]}

    print(f"  {Color.GREEN}Found {len(all_resources)} matching rule group(s).{Color.END}")
    return {"body": {"resources": all_resources}, "status_code": 200, "errors": None}


def display_ioas(matches: dict, table_format: str):
    """Displays the IOA listing in tabular format."""
    global Color
    banner = [f"{Color.MAGENTA}===================================================", f"              Custom IOA Rule Groups", f"==================================================={Color.END}\n"]
    headers = {"name": f"{Color.BOLD}Group Name / ID / Comment{Color.END}", "description": f"{Color.BOLD}Description{Color.END}", "platform": f"{Color.BOLD}Platform / Status / Version{Color.END}", "rules": f"{Color.BOLD}Rules (Name / Status / Ver){Color.END}"}
    ioas = []
    resources = matches.get("body", {}).get("resources", [])
    if isinstance(resources, list):
        sorted_resources = sorted(resources, key=lambda x: x.get('name', '').lower() if isinstance(x, dict) else '')
        for match in sorted_resources:
            if not isinstance(match, dict): print(f"{Color.YELLOW}Warning: Skipping invalid item in resources list.{Color.END}"); continue
            ioa = {}; name_comment = f"\n{Color.DARKCYAN}{match.get('comment', '')}{Color.END}" if match.get('comment') else ""
            ioa["name"] = f"{match.get('name', 'N/A')}\n{Color.CYAN}{match.get('id', 'N/A')}{Color.END}{name_comment}"
            ioa["description"] = chunk_long_description(match.get("description", ""), 40)
            group_enabled = f"{Color.GREEN}Enabled{Color.END}" if match.get("enabled", False) else f"{Color.LIGHTRED}Disabled{Color.END}"
            platform_list = [f"{str(match.get('platform', 'N/A')).upper()}", f"{group_enabled}", f"Ver: {Color.BOLD}{match.get('version', 'N/A')}{Color.END}"]
            ioa["platform"] = "\n".join(platform_list)
            rules_list = match.get("rules", [])
            if isinstance(rules_list, list):
                 sorted_rules = sorted(rules_list, key=lambda x: x.get('name', '').lower() if isinstance(x, dict) else '')
                 rules_display = []
                 for rule in sorted_rules:
                     if isinstance(rule, dict):
                         rule_enabled = f"{Color.GREEN}E{Color.END}" if rule.get("enabled") else f"{Color.RED}D{Color.END}" # Short status E/D
                         rules_display.append(f"{rule.get('name', 'N/A')} ({rule_enabled}/v{rule.get('instance_version', 'N/A')})")
                 ioa["rules"] = "\n".join(rules_display) if rules_display else f"{Color.YELLOW}No rules found.{Color.END}"
            else: ioa["rules"] = f"{Color.YELLOW}Invalid 'rules' format.{Color.END}"
            ioas.append(ioa)
    if not ioas:
        if matches.get("errors"): print(f"{Color.YELLOW}Could not display rule groups due to previous API errors.{Color.END}")
        else: print(f"\n{Color.YELLOW}--- No matching rule groups found ---{Color.END}\n")
    else: print("\n".join(banner)); print(tabulate(ioas, headers=headers, tablefmt=table_format, disable_numparse=True))


def get_child_cid_details(mssp_sdk: FlightControl) -> dict:
    """Queries and returns a dictionary mapping accessible child CIDs to their names."""
    global Color
    print(f"Querying for accessible children CIDs using {Color.BOLD}FlightControl{Color.END} SDK...")
    all_child_cids = []; offset = None; limit = 500
    kid_detail = {}
    while True:
        params = {"limit": limit};
        if offset: params["offset"] = offset
        try:
            kid_lookup = mssp_sdk.query_children(**params)
            status_code = kid_lookup.get("status_code", 500)
            body = kid_lookup.get("body", {})

            if status_code // 100 == 2:
                resources = body.get("resources", []);
                if not resources: break
                all_child_cids.extend(resources)
                meta = body.get("meta", {}).get("pagination", {})
                total = meta.get("total")
                current_offset = meta.get("offset", offset if offset is not None else 0)
                if total is not None and (current_offset + limit >= total): break
                if len(resources) < limit: break
                offset = current_offset + limit
            else:
                error_msg = "Unknown API error"
                if body.get("errors"): error_msg = body["errors"][0].get("message", error_msg)
                print(f"{Color.RED}Error querying children CIDs: {error_msg} (Status: {status_code}){Color.END}");
                break
        except Exception as e:
            print(f"{Color.RED}Exception querying children CIDs: {e}{Color.END}")
            break

    print(f"Discovered {len(all_child_cids)} potential children CIDs.")

    if all_child_cids:
        print("Fetching details for discovered children..."); child_details_list = []; chunk_size = 100
        for i in range(0, len(all_child_cids), chunk_size):
            chunk_ids = all_child_cids[i:i + chunk_size]
            try:
                child_detail_response = mssp_sdk.get_children(ids=chunk_ids)
                if child_detail_response.get("status_code", 500) // 100 == 2:
                    child_details_list.extend(child_detail_response.get("body", {}).get("resources", []))
                else:
                    error_msg = "Unknown API error"
                    if child_detail_response.get("body", {}).get("errors"):
                        error_msg = child_detail_response["body"]["errors"][0].get("message", error_msg)
                    print(f"{Color.YELLOW}Warning: Failed get_children chunk {i//chunk_size + 1}. Status: {child_detail_response.get('status_code', 'N/A')}, Error: {error_msg}{Color.END}")
            except Exception as e: print(f"{Color.RED}Error fetching children chunk {i//chunk_size + 1}: {e}{Color.END}")

        for child in child_details_list:
            cid = child.get("child_cid"); name = child.get("name", "Unknown")
            if cid: kid_detail[cid] = name

        print(f"{Color.GREEN}Fetched details for {len(kid_detail)} children.{Color.END}")
    else: print(f"{Color.YELLOW}No children CIDs found/accessible.{Color.END}")
    return kid_detail


def display_child_cids(cid_details: dict, table_format: str):
    """Displays Child CIDs and Names in a table."""
    global Color
    if not cid_details:
        print("\nNo accessible child CIDs found to display.")
        return
    print(f"\n--- {Color.BOLD}Accessible Child CIDs{Color.END} ---")
    headers = {"cid": f"{Color.BOLD}Child CID{Color.END}", "name": f"{Color.BOLD}Child Name{Color.END}"}
    data = [{"cid": cid, "name": name} for cid, name in sorted(cid_details.items(), key=lambda item: item[1].lower())]
    print(tabulate(data, headers=headers, tablefmt=table_format))
    print(f"--- Total: {len(data)} ---")


def get_target_group_details(target_ioa_api: CustomIOA, target_group_id: str):
    """Helper function to get the details of a specific rule group by ID."""
    global Color
    try:
        response = target_ioa_api.get_rule_groups(ids=[target_group_id])
        if response.get("status_code", 500) // 100 == 2:
            resources = response.get("body", {}).get("resources", [])
            if resources: return resources[0]
            else:
                print(f"  {Color.YELLOW}Warning: get_rule_groups for ID {target_group_id} returned no resources.{Color.END}")
                return None
        else:
            err_msg = "Unknown API error"
            if response.get("body", {}).get("errors"): err_msg = response["body"]["errors"][0].get("message", err_msg)
            print(f"  {Color.YELLOW}Warning: Failed get_rule_groups for ID {target_group_id}. Status: {response.get('status_code')}. Error: {err_msg}{Color.END}")
            return None
    except Exception as e:
        print(f"  {Color.RED}Error in get_target_group_details for ID {target_group_id}: {e}{Color.END}")
        return None


def replicate_or_update_rules_to_target(source_ioa_rules: dict, target_cid: str, target_group_name: str, specific_rule_name: str = None):
    """
    Replicates or Updates rules from source groups into a single pre-existing target group.
    Creates new rules as disabled, then enables them if the source was enabled.
    Updates existing rules directly.
    Returns a dictionary with summary counts for the processed CID.
    """
    global args, Color
    target_ioa_api = None
    # Initialize summary for this CID
    cid_summary = {
        "processed": 0, "created": 0, "updated": 0, "enabled_after_create": 0, "enable_failed": 0,
        "skipped_missing_data": 0, "failed_creation": 0, "failed_update": 0,
        "errors": [], "target_group_id": None, "target_group_name": target_group_name
    }

    # Open SDK for the target CID (or source if target_cid is None)
    try:
        target_ioa_api = open_sdk(args.falcon_client_id, args.falcon_client_secret, args.base_url, "CustomIOA", member_cid=target_cid)
        if not target_ioa_api: raise Exception("SDK Initialization failed")
    except Exception as e:
        target_desc = f"CID {target_cid}" if target_cid else "Source Tenant"
        print(f"{Color.RED}Error: Could not initialize SDK for target {target_desc}. Skipping... Error: {e}{Color.END}")
        cid_summary["errors"].append(f"Failed to initialize SDK: {e}")
        return cid_summary

    source_resources = source_ioa_rules.get("body", {}).get("resources", [])
    if not isinstance(source_resources, list) or not source_resources:
        target_desc = f"CID {target_cid}" if target_cid else "Source Tenant"
        print(f"{Color.YELLOW}Warning: No valid source rule groups provided to process for {target_desc}.{Color.END}")
        cid_summary["errors"].append("No valid source rule groups provided.")
        return cid_summary

    action = "Update" if specific_rule_name else "Replicate/Update"
    target_desc = f"CID {Color.DARKCYAN}{target_cid}{Color.END}" if target_cid else f"{Color.MAGENTA}Source Tenant{Color.END}"
    print(f"Attempting to {action} rules into target group '{Color.CYAN}{target_group_name}{Color.END}' in {target_desc}...")
    if specific_rule_name:
        print(f"  Targeting specific rule: '{Color.LIGHTBLUE}{specific_rule_name}{Color.END}'")

    # --- Find the PRE-EXISTING Target Group ---
    target_group_id = None
    initial_target_group_details = None
    target_group_version = None # Track the current version for updates
    try:
        safe_group_name = target_group_name.replace("'", "\\'")
        fql_filter = f"name:'{safe_group_name}'"
        print(f"  Finding target group using filter: {fql_filter}...")
        existing_group_check = target_ioa_api.query_rule_groups_full(filter=fql_filter, limit=2)
        status_code_find = existing_group_check.get("status_code", 500)
        body_find = existing_group_check.get("body", {})

        if status_code_find // 100 == 2:
            existing_details_list = body_find.get("resources", [])
            if existing_details_list:
                if len(existing_details_list) > 1:
                    print(f"  {Color.YELLOW}Warning: Found multiple groups named '{target_group_name}'. Using first match ID: {existing_details_list[0].get('id')}.{Color.END}")
                initial_target_group_details = existing_details_list[0]
                target_group_id = initial_target_group_details.get("id")
                target_group_version = initial_target_group_details.get("version") # Get initial version
                cid_summary["target_group_id"] = target_group_id
                if not target_group_id or target_group_version is None:
                     raise ValueError(f"Found group '{target_group_name}' but ID or version is missing.")
                print(f"  {Color.GREEN}Found target group ID: {target_group_id} (Initial Version: {target_group_version}).{Color.END}")
            else:
                print(f"  {Color.RED}Error: Target group '{target_group_name}' not found in {target_desc}. Rules cannot be processed.{Color.END}")
                cid_summary["errors"].append(f"Target group '{target_group_name}' not found.")
                return cid_summary
        else:
            err_msg = "Unknown API error"
            if body_find.get("errors"): err_msg = body_find["errors"][0].get("message", err_msg)
            print(f"  {Color.RED}Warning: Failed query for target group '{target_group_name}'. Status: {status_code_find}. Error: {err_msg}{Color.END}")
            cid_summary["errors"].append(f"API Error finding target group: {err_msg}")
            return cid_summary
    except Exception as e:
        print(f"  {Color.RED}Error finding target group '{target_group_name}': {e}.{Color.END}");
        cid_summary["errors"].append(f"Exception finding target group: {e}")
        return cid_summary

    # --- Get Existing Rules in Target Group (Name -> Details Mapping) ---
    existing_target_rules = {} # Map name to full rule details
    try:
        print(f"  Querying existing rules in target group {target_group_id} for comparison...")
        all_rule_details = []
        offset = None; limit = 500
        while True:
            params = {"filter": f"rulegroup_id:'{target_group_id}'", "limit": limit}
            if offset: params["offset"] = offset
            query_rules_resp = target_ioa_api.query_rules(**params)
            query_status = query_rules_resp.get("status_code", 500)
            query_body = query_rules_resp.get("body", {})

            if query_status // 100 == 2:
                rule_ids = query_body.get("resources", [])
                if not rule_ids: break
                # Fetch details in chunks
                chunk_size = 500
                for i in range(0, len(rule_ids), chunk_size):
                    id_chunk = rule_ids[i:i+chunk_size]
                    get_rules_resp = target_ioa_api.get_rules(ids=id_chunk)
                    if get_rules_resp.get("status_code", 500) // 100 == 2:
                        all_rule_details.extend(get_rules_resp.get("body", {}).get("resources", []))
                    else:
                        print(f"    {Color.YELLOW}Warning: Failed to get details for rule ID chunk. Status: {get_rules_resp.get('status_code')}{Color.END}")
                # Pagination for query_rules
                meta = query_body.get("meta", {}).get("pagination", {})
                total = meta.get("total")
                current_offset = meta.get("offset", offset if offset is not None else 0)
                if total is not None and (current_offset + limit >= total): break
                offset = current_offset + limit
            else:
                 err_msg = "Unknown API error"
                 if query_body.get("errors"): err_msg = query_body["errors"][0].get("message", err_msg)
                 print(f"  {Color.YELLOW}Warning: Failed to query existing rule IDs. Status: {query_status}. Error: {err_msg}. Update/duplicate check might be incomplete.{Color.END}")
                 break
    except Exception as e:
        print(f"  {Color.RED}Warning: Error querying existing rules: {e}. Update/duplicate check might be incomplete.{Color.END}")

    # Populate the map
    for rule in all_rule_details:
        if isinstance(rule, dict) and rule.get("name"):
            existing_target_rules[rule["name"]] = rule
    print(f"  Found {len(existing_target_rules)} existing rules with names in target group '{target_group_name}'.")


    # --- Iterate Source Groups and Process Rules ---
    print(f"  Processing rules from source...")
    rules_processed_in_cid = 0
    for source_group in source_resources:
        source_group_name = source_group.get('name', 'Unknown Source Group')
        source_rules = source_group.get("rules", [])
        if not isinstance(source_rules, list) or not source_rules: continue

        for rule in source_rules:
            if not isinstance(rule, dict): continue

            rules_processed_in_cid += 1
            cid_summary["processed"] += 1
            rule_name = rule.get("name")
            source_rule_enabled = rule.get("enabled", False) # Get source enabled status

            # Filter for specific rule name if requested
            if specific_rule_name and rule_name != specific_rule_name:
                continue

            if not rule_name:
                print(f"      {Color.YELLOW}Skipping rule (Source Group: {source_group_name}): Missing name.{Color.END}")
                cid_summary["skipped_missing_data"] += 1
                continue

            # Construct Base Payload
            rule_payload_base = {
                "description": rule.get("description", ""),
                "disposition_id": rule.get("disposition_id"),
                "comment": f"Source Rule Instance ID: {rule.get('instance_id', 'N/A')} | Source Group: '{source_group_name}'",
                "field_values": rule.get("field_values", []),
                "pattern_severity": rule.get("pattern_severity"),
                "name": rule_name,
                "rulegroup_id": target_group_id,
                "ruletype_id": rule.get("ruletype_id"),
                # Enabled status handled differently for create vs update
            }

            # Basic validation (common fields)
            required_common = ["disposition_id", "field_values", "pattern_severity", "name", "rulegroup_id", "ruletype_id"]
            missing = [f for f in required_common if rule_payload_base.get(f) is None]
            if not isinstance(rule_payload_base.get("field_values"), list):
                 missing.append("field_values (must be list)")
            if missing:
                print(f"      {Color.YELLOW}Skipping rule '{rule_name}': Missing/Invalid required fields: {', '.join(missing)}{Color.END}")
                cid_summary["skipped_missing_data"] += 1; continue

            # Check if rule exists in target
            existing_rule_details = existing_target_rules.get(rule_name)

            # --- UPDATE PATH ---
            if existing_rule_details:
                target_rule_instance_id = existing_rule_details.get("instance_id")
                # Refresh group version if needed (if last operation invalidated it)
                if target_group_version is None:
                    print(f"        Refreshing target group {target_group_id} details for version...")
                    refreshed_group_details = get_target_group_details(target_ioa_api, target_group_id)
                    if not refreshed_group_details or refreshed_group_details.get("version") is None:
                        print(f"      {Color.RED}Error: Cannot update rule '{rule_name}'. Failed to refresh target group version.{Color.END}")
                        cid_summary["failed_update"] += 1
                        continue
                    target_group_version = int(refreshed_group_details.get("version"))
                    print(f"        Using target group version: {target_group_version}")

                print(f"      Rule '{Color.CYAN}{rule_name}{Color.END}' exists. Attempting update (Source Enabled: {source_rule_enabled})...")

                if not target_rule_instance_id:
                     print(f"      {Color.RED}Error: Cannot update rule '{rule_name}'. Existing rule missing 'instance_id'.{Color.END}")
                     cid_summary["failed_update"] += 1; target_group_version = None; continue

                # Construct update payload - includes enabled status from source
                update_rule_payload = {
                    **rule_payload_base, # Include base fields
                    "instance_id": target_rule_instance_id,
                    "rulegroup_version": int(target_group_version),
                    "enabled": source_rule_enabled, # Update enabled status directly
                    "comment": rule_payload_base["comment"] + " (Updated)" # Add note
                }
                update_rule_payload_clean = {k: v for k, v in update_rule_payload.items() if v is not None}

                # Construct top-level body
                update_body = {
                    "comment": f"Updating rule '{rule_name}' via script.",
                    "rulegroup_id": target_group_id,
                    "rulegroup_version": int(target_group_version),
                    "rule_updates": [update_rule_payload_clean]
                }

                # Validate required fields for update
                required_update = ["instance_id", "rulegroup_version", "name", "description", "disposition_id", "field_values", "pattern_severity", "enabled"]
                missing_update = [f for f in required_update if f not in update_rule_payload_clean]
                if missing_update:
                    print(f"      {Color.RED}Error: Cannot update rule '{rule_name}'. Missing fields for API payload: {', '.join(missing_update)}.{Color.END}")
                    cid_summary["failed_update"] += 1; target_group_version = None; continue

                try:
                    update_rule_resp = target_ioa_api.update_rules(body=update_body)
                    update_status = update_rule_resp.get("status_code", 500)
                    update_resp_body = update_rule_resp.get("body", {})

                    if update_status // 100 == 2:
                        print(f"      {Color.GREEN}Successfully updated rule '{rule_name}'.{Color.END}")
                        cid_summary["updated"] += 1
                        # Update cached group version from response
                        resources = update_resp_body.get("resources", [])
                        if resources and isinstance(resources[0], dict) and resources[0].get("rulegroup_version") is not None:
                           new_group_version = int(resources[0].get("rulegroup_version"))
                           if target_group_version != new_group_version:
                                print(f"        Target group version incremented to: {new_group_version}")
                                target_group_version = new_group_version
                        else: target_group_version = None # Invalidate cache if version not returned
                    else:
                        errors = update_resp_body.get("errors", [{"message":"Unknown error"}]); error_msg = errors[0].get("message", "Unknown")
                        print(f"      {Color.RED}Failed rule update for '{rule_name}'. Status: {update_status}, Error: {error_msg}{Color.END}")
                        cid_summary["failed_update"] += 1; target_group_version = None # Invalidate cache on error
                except Exception as e_update:
                    print(f"      {Color.RED}Exception calling update_rules for '{rule_name}': {e_update}{Color.END}")
                    cid_summary["failed_update"] += 1; target_group_version = None # Invalidate cache

            # --- CREATE PATH ---
            else:
                print(f"      Rule '{Color.GREEN}{rule_name}{Color.END}' not found. Attempting to create (as disabled)...")
                # Create rule with enabled: false
                create_rule_payload = {
                    **rule_payload_base,
                    "enabled": False # <<< Always create disabled
                }
                create_rule_payload_clean = {k: v for k, v in create_rule_payload.items() if v is not None}

                try:
                    rule_create_resp = target_ioa_api.create_rule(body=create_rule_payload_clean)
                    create_status = rule_create_resp.get("status_code", 500)
                    create_resp_body = rule_create_resp.get("body", {})

                    if create_status in [200, 201]:
                         resources = create_resp_body.get("resources", [])
                         if isinstance(resources, list) and resources:
                            new_rule_details = resources[0]
                            new_rule_id = new_rule_details.get("instance_id")
                            new_rule_version = new_rule_details.get("instance_version") # Rule version
                            new_group_version_from_create = new_rule_details.get("rulegroup_version") # Group version after create

                            if new_rule_id is not None and new_rule_version is not None:
                                print(f"      {Color.GREEN}Successfully created rule '{rule_name}' (ID: {new_rule_id}) as disabled.{Color.END}")
                                cid_summary["created"] += 1
                                # Add created rule to local cache
                                existing_target_rules[rule_name] = new_rule_details
                                # Update cached group version
                                if new_group_version_from_create is not None:
                                    new_group_version_int = int(new_group_version_from_create)
                                    if target_group_version != new_group_version_int:
                                        print(f"        Target group version is now: {new_group_version_int}")
                                        target_group_version = new_group_version_int
                                else: target_group_version = None # Invalidate if not returned

                                # --- Attempt to ENABLE if source was enabled ---
                                if source_rule_enabled:
                                    print(f"        Source rule was enabled. Attempting to enable new rule {new_rule_id}...")
                                    # Need the LATEST group version for the enable update
                                    if target_group_version is None:
                                        print(f"          Refreshing target group {target_group_id} details for version...")
                                        refreshed_group_details_for_enable = get_target_group_details(target_ioa_api, target_group_id)
                                        if not refreshed_group_details_for_enable or refreshed_group_details_for_enable.get("version") is None:
                                            print(f"        {Color.RED}Error: Cannot enable rule '{rule_name}'. Failed to refresh target group version after create.{Color.END}")
                                            cid_summary["enable_failed"] += 1
                                            continue # Skip enable attempt for this rule
                                        target_group_version = int(refreshed_group_details_for_enable.get("version"))
                                        print(f"          Using target group version: {target_group_version}")

                                    # Construct enable payload (minimal update)
                                    enable_rule_payload = {
                                        "instance_id": new_rule_id,
                                        "rulegroup_version": int(target_group_version),
                                        "enabled": True,
                                        # Need other required fields for update_rules payload
                                        "name": rule_name, # Use original name
                                        "description": create_rule_payload_clean["description"],
                                        "disposition_id": create_rule_payload_clean["disposition_id"],
                                        "field_values": create_rule_payload_clean["field_values"],
                                        "pattern_severity": create_rule_payload_clean["pattern_severity"],
                                    }
                                    enable_body = {
                                        "comment": f"Enabling rule '{rule_name}' after creation via script.",
                                        "rulegroup_id": target_group_id,
                                        "rulegroup_version": int(target_group_version),
                                        "rule_updates": [enable_rule_payload]
                                    }

                                    try:
                                        enable_resp = target_ioa_api.update_rules(body=enable_body)
                                        enable_status = enable_resp.get("status_code", 500)
                                        enable_resp_body = enable_resp.get("body", {})
                                        if enable_status // 100 == 2:
                                            print(f"        {Color.GREEN}Successfully enabled rule '{rule_name}'.{Color.END}")
                                            cid_summary["enabled_after_create"] += 1
                                            # Update cached group version from response
                                            enable_resources = enable_resp_body.get("resources", [])
                                            if enable_resources and isinstance(enable_resources[0], dict) and enable_resources[0].get("rulegroup_version") is not None:
                                                final_group_version = int(enable_resources[0].get("rulegroup_version"))
                                                if target_group_version != final_group_version:
                                                    print(f"          Target group version incremented to: {final_group_version}")
                                                    target_group_version = final_group_version
                                            else: target_group_version = None # Invalidate
                                        else:
                                            errors = enable_resp_body.get("errors", [{"message":"Unknown error"}]); error_msg = errors[0].get("message", "Unknown")
                                            print(f"        {Color.RED}Failed to enable rule '{rule_name}'. Status: {enable_status}, Error: {error_msg}{Color.END}")
                                            cid_summary["enable_failed"] += 1; target_group_version = None # Invalidate
                                    except Exception as e_enable:
                                        print(f"        {Color.RED}Exception calling update_rules for enabling '{rule_name}': {e_enable}{Color.END}")
                                        cid_summary["enable_failed"] += 1; target_group_version = None # Invalidate
                                else:
                                     print(f"        Source rule was disabled. Rule '{rule_name}' created as disabled.{Color.END}")

                            else:
                                print(f"      {Color.RED}Failed creating rule '{rule_name}': Create status OK but couldn't get ID/Version.{Color.END}")
                                print(f"        Response Body: {json.dumps(create_resp_body, indent=2)}")
                                cid_summary["failed_creation"] += 1; target_group_version = None
                         else:
                            print(f"      {Color.RED}Failed creating rule '{rule_name}': Create status OK ({create_status}) but no resource details found.{Color.END}")
                            print(f"        Response Body: {json.dumps(create_resp_body, indent=2)}")
                            cid_summary["failed_creation"] += 1; target_group_version = None
                    else:
                        errors = create_resp_body.get("errors", [{"message":"Unknown error"}]); error_msg = errors[0].get("message", "Unknown")
                        print(f"      {Color.RED}Failed creating rule '{rule_name}'. Status: {create_status}, Error: {error_msg}{Color.END}")
                        cid_summary["failed_creation"] += 1; target_group_version = None
                except Exception as e_create:
                    print(f"      {Color.RED}Exception calling create_rule for '{rule_name}': {e_create}{Color.END}")
                    cid_summary["failed_creation"] += 1; target_group_version = None

            # --- End of Create/Update block ---

            # If specific rule processed, break loops
            if specific_rule_name and rule_name == specific_rule_name:
                 print(f"    Finished processing specific rule '{specific_rule_name}'.")
                 break # Exit inner rule loop

        # If specific rule processed, break outer group loop too
        if specific_rule_name and rule_name == specific_rule_name:
             break

    # --- End of rule processing for this CID ---
    print(f"\n--- {action} Summary for {target_desc} (Target Group: {target_group_name} / {target_group_id}) ---")
    print(f"Rules Processed:              {rules_processed_in_cid}")
    print(f"{Color.GREEN}Rules Created (as disabled):{Color.END}  {cid_summary['created']}")
    print(f"{Color.LIGHTGREEN}Rules Enabled (after create):{Color.END} {cid_summary['enabled_after_create']}")
    print(f"{Color.CYAN}Rules Updated:{Color.END}              {cid_summary['updated']}")
    print(f"{Color.YELLOW}Rules Skipped (Missing Data):{Color.END} {cid_summary['skipped_missing_data']}")
    print(f"{Color.RED}Rules Failed Creation:{Color.END}      {cid_summary['failed_creation']}")
    print(f"{Color.RED}Rules Failed Update:{Color.END}        {cid_summary['failed_update']}")
    print(f"{Color.LIGHTRED}Rules Failed Enable:{Color.END}        {cid_summary['enable_failed']}")
    if cid_summary['errors']:
        print(f"{Color.RED}CID-Level Errors:{Color.END}")
        for err in cid_summary['errors']: print(f"  - {err}")
    print("---------------------------------------------------------")

    return cid_summary


def delete_ioas(sdk: CustomIOA, ids_to_delete: str):
    """Deletes specified IOA rule groups and returns counts."""
    global Color
    delete_summary = {"deleted_count": 0, "failed_count": 0, "errors": []}
    id_list = [item.strip() for item in ids_to_delete.split(",") if item.strip()]
    if not id_list:
        print(f"{Color.YELLOW}Warning: No valid rule group IDs provided for deletion.{Color.END}")
        delete_summary["errors"].append({"message": "No valid IDs provided for deletion"})
        return delete_summary

    print(f"Attempting to delete {len(id_list)} rule group(s): {', '.join(id_list)}")
    try:
        delete_result = sdk.delete_rule_groups(ids=id_list, comment="Deleting rule groups via script.")
        status_code = delete_result.get("status_code")
        body = delete_result.get("body", {})
        errors = body.get("errors", [])
        meta = body.get("meta", {})
        # FalconPy might parse counts into meta, otherwise infer from errors
        deleted_count_meta = meta.get("deleted_count", None)
        failed_count_meta = meta.get("failed_count", None)

        if status_code is not None and status_code // 100 == 2:
            if deleted_count_meta is not None:
                 delete_summary["deleted_count"] = deleted_count_meta
                 delete_summary["failed_count"] = failed_count_meta if failed_count_meta is not None else (len(id_list) - deleted_count_meta)
            else: # Fallback: Infer from errors list
                failed_ids_from_errors = set(e.get('id') for e in errors if e.get('id'))
                delete_summary["failed_count"] = len(failed_ids_from_errors)
                delete_summary["deleted_count"] = len(id_list) - len(failed_ids_from_errors)

            if delete_summary["failed_count"] > 0:
                print(f"{Color.YELLOW}Deletion request partially successful.{Color.END}")
                print(f"  {Color.GREEN}Successfully deleted: {delete_summary['deleted_count']}{Color.END}")
                print(f"  {Color.RED}Failed to delete: {delete_summary['failed_count']}{Color.END}")
                if errors:
                    print(f"  {Color.RED}Reported Errors:{Color.END}")
                    for error in errors: print(f"    - ID: {error.get('id', 'N/A')}, Code: {error.get('code', 'N/A')}, Message: {error.get('message', 'Unknown')}")
                    delete_summary["errors"] = errors
            else:
                 print(f"{Color.GREEN}Successfully requested deletion for all {delete_summary['deleted_count']} rule group(s).{Color.END}")
        else: # Status code indicates failure
            print(f"{Color.RED}Error during deletion request. Status: {status_code if status_code else 'N/A'}{Color.END}")
            delete_summary["failed_count"] = len(id_list); delete_summary["deleted_count"] = 0
            if errors:
                print(f"{Color.RED}Deletion Errors Reported:{Color.END}")
                for error in errors: print(f"  Code: {error.get('code', 'N/A')}, Message: {error.get('message', 'Unknown')}, ID: {error.get('id', '')}")
                delete_summary["errors"] = errors
            else:
                 err_msg = f"Deletion API call failed with status {status_code}"
                 print(f"  {err_msg}"); delete_summary["errors"].append({"message": err_msg, "status_code": status_code})
    except Exception as e:
        print(f"{Color.RED}Exception calling delete_rule_groups API: {e}{Color.END}")
        delete_summary["failed_count"] = len(id_list); delete_summary["deleted_count"] = 0
        delete_summary["errors"].append({"message": f"Exception during delete: {e}"})

    return delete_summary


# --- Main Execution Block ---
if __name__ == "__main__":
    start_time = time.time()
    args = consume_arguments()
    # Initialize colors AFTER parsing args (respects --nocolor)
    initialize_colors(args.nocolor)

    print(f"{Color.BOLD}Starting IOA Rule Management Script...{Color.END}")

    # --- SDK Initialization (Source Tenant) ---
    print(f"\n{Color.UNDERLINE}Connecting to Source Tenant{Color.END}")
    falcon_ioa_source = open_sdk(args.falcon_client_id, args.falcon_client_secret, args.base_url, "CustomIOA")
    print(f"{Color.GREEN}Source SDK initialized.{Color.END}")

    # --- List Parent IOAs Action ---
    if args.list_parent_ioas:
        print(f"\n{Color.BOLD}--- Listing Parent Tenant IOA Groups ---{Color.END}")
        parent_ioas = get_ioa_list(falcon_ioa_source, args.filter)
        display_ioas(parent_ioas, args.table_format)
        print(f"\n{Color.BOLD}--- Parent IOA Listing Complete ---{Color.END}")
        sys.exit(0)

    # --- List Child CIDs Action ---
    if args.list_cids:
        print(f"\n{Color.BOLD}--- Listing Child CIDs ---{Color.END}")
        mssp_sdk_flight = open_mssp(args.falcon_client_id, args.falcon_client_secret, args.base_url)
        child_details = get_child_cid_details(mssp_sdk_flight)
        display_child_cids(child_details, args.table_format)
        print(f"\n{Color.BOLD}--- Child CID Listing Complete ---{Color.END}")
        sys.exit(0)

    # --- Initial IOA Rule Retrieval (Source Tenant) ---
    ioa_rules_source_data = {"body": {"resources": []}, "status_code": 0, "errors": None}
    if args.replicate_rules or args.replicate_all_parent_rules:
        source_filter_str = args.filter
        print(f"\n{Color.UNDERLINE}Retrieving Source IOA Rule Groups{Color.END}")
        print(f"Filter: {'All Groups' if not source_filter_str else f'Group name contains *{source_filter_str}*'}")
        ioa_rules_source_data = get_ioa_list(falcon_ioa_source, source_filter_str)
        if ioa_rules_source_data.get("status_code", 500) // 100 != 2:
            print(f"{Color.RED}Fatal Error: Could not retrieve rule groups from source. Exiting.{Color.END}")
            if ioa_rules_source_data.get("errors"):
                 for err in ioa_rules_source_data["errors"]: print(f"  - {err.get('message')}")
            sys.exit(1)
        initial_group_count = len(ioa_rules_source_data.get("body", {}).get("resources", []))
        print(f"Found {initial_group_count} source groups to process rules from.")
        if initial_group_count == 0:
            print(f"{Color.YELLOW}Warning: No source groups found matching filter. No rules will be replicated/updated.{Color.END}")
            if args.rule_name:
                 print(f"{Color.YELLOW}  Ensure the group containing rule '{args.rule_name}' matches the filter '{source_filter_str}' if provided.{Color.END}")

    # --- MSSP Child Handling ---
    DO_MSSP = False; kid_detail = {}; target_cids_for_actions = []
    if args.managed_targets or args.all_cids:
        print(f"\n{Color.UNDERLINE}MSSP Target Handling{Color.END}")
        mssp_sdk_flight = open_mssp(args.falcon_client_id, args.falcon_client_secret, args.base_url)
        kid_detail = get_child_cid_details(mssp_sdk_flight)

        if not kid_detail:
            print(f"{Color.YELLOW}No accessible child CIDs found. Cannot perform MSSP actions.{Color.END}")
        elif args.all_cids:
            target_cids_for_actions = sorted(list(kid_detail.keys()))
            print(f"Targeting all {Color.BOLD}{len(target_cids_for_actions)}{Color.END} detected child CIDs.")
            if target_cids_for_actions: DO_MSSP = True
        elif args.managed_targets:
            user_targets = [cid.strip() for cid in args.managed_targets.split(",") if cid.strip()]
            print(f"Validating {len(user_targets)} specified target CID(s)...")
            valid_targets = []
            invalid_targets = []
            normalized_user_targets = {t.split('-')[0].lower(): t for t in user_targets}
            normalized_kid_details = {c.split('-')[0].lower(): (c, name) for c, name in kid_detail.items()}
            validated_cids_map = {}

            for norm_user_cid, orig_user_cid in normalized_user_targets.items():
                if norm_user_cid in normalized_kid_details:
                    actual_cid, name = normalized_kid_details[norm_user_cid]
                    validated_cids_map[norm_user_cid] = actual_cid
                    print(f"  - {Color.GREEN}Validated:{Color.END} {actual_cid} ({name})")
                else:
                    invalid_targets.append(orig_user_cid)
                    print(f"  - {Color.RED}Not Found/Accessible:{Color.END} {orig_user_cid}")

            target_cids_for_actions = sorted([validated_cids_map[norm_cid] for norm_cid in validated_cids_map])

            if target_cids_for_actions:
                DO_MSSP = True
                print(f"{Color.GREEN}Proceeding with actions on {len(target_cids_for_actions)} validated target CIDs.{Color.END}")
            if invalid_targets:
                 print(f"{Color.YELLOW}Warning: {len(invalid_targets)} specified target CIDs could not be validated/accessed: {', '.join(invalid_targets)}{Color.END}")
            if not DO_MSSP:
                print(f"{Color.YELLOW}Warning: None of the specified target CIDs validated. No MSSP actions will be performed.{Color.END}")

    # --- Action Execution ---
    # Replicate/Update Rules Action
    if args.replicate_rules or args.replicate_all_parent_rules:
        action_verb = "Replicate/Update Rules"
        source_rule_groups = ioa_rules_source_data.get("body", {}).get("resources", [])
        should_skip_replication = False
        if not (args.replicate_rules or args.replicate_all_parent_rules): should_skip_replication = True
        elif not args.target_group_name: print(f"\n{Color.RED}--- Skipping {action_verb} Operation (--target_group_name required) ---{Color.END}"); should_skip_replication = True
        elif not source_rule_groups and not args.rule_name: print(f"\n{Color.YELLOW}--- Skipping {action_verb} Operation (No source groups found/matched) ---{Color.END}"); should_skip_replication = True
        elif (args.managed_targets or args.all_cids) and not DO_MSSP: print(f"\n{Color.YELLOW}--- Skipping MSSP {action_verb} Operation (No validated CIDs) ---{Color.END}"); should_skip_replication = True

        if not should_skip_replication:
            if DO_MSSP:
                print(f"\n{Color.BOLD}--- Starting {action_verb} Operation on {len(target_cids_for_actions)} Child Tenant(s) ---{Color.END}")
                for i, target_cid in enumerate(target_cids_for_actions):
                    child_name = f" ({kid_detail.get(target_cid, 'Unknown Name')})" if kid_detail else ""
                    print(f"\n===== Processing Target CID {i+1}/{len(target_cids_for_actions)}: {Color.DARKCYAN}{target_cid}{Color.END}{child_name} =====")
                    cid_results = replicate_or_update_rules_to_target(ioa_rules_source_data, target_cid, args.target_group_name, args.rule_name)
                    summary_tracker.update_cid_summary(target_cid, cid_results)
                    print(f"===== Finished CID: {Color.DARKCYAN}{target_cid}{Color.END} =====")
            else: # Non-MSSP Action (Source Tenant)
                print(f"\n{Color.BOLD}--- Starting {action_verb} Operation within {Color.MAGENTA}Source Tenant{Color.END} ---{Color.END}")
                print(f"{Color.YELLOW}Warning: Replicating/updating rules within the *same* tenant ({Color.MAGENTA}Source{Color.END}).")
                print(f"         Rules from source groups will be created/updated in target group '{Color.CYAN}{args.target_group_name}{Color.END}'.")
                source_cid_results = replicate_or_update_rules_to_target(ioa_rules_source_data, None, args.target_group_name, args.rule_name)
                summary_tracker.update_cid_summary(None, source_cid_results)

            print(f"{Color.BOLD}--- {action_verb} Operation Complete ---{Color.END}")

    # Delete Action
    if args.delete_group:
        delete_ids = args.delete_ids.strip() if args.delete_ids else None
        should_skip_delete = False
        if not delete_ids: print(f"\n{Color.YELLOW}--- Skipping Delete Operation (No IDs via --delete_ids) ---{Color.END}"); should_skip_delete = True
        elif (args.managed_targets or args.all_cids) and not DO_MSSP: print(f"\n{Color.YELLOW}--- Skipping MSSP Delete Operation (No validated CIDs) ---{Color.END}"); should_skip_delete = True

        if not should_skip_delete:
            if DO_MSSP:
                print(f"\n{Color.BOLD}--- Starting Delete Operation in {len(target_cids_for_actions)} Child Tenant(s) ---{Color.END}")
                print(f"{Color.YELLOW}Note: Attempting to delete Group IDs [{delete_ids}] in ALL targeted CIDs.{Color.END}")
                for i, target_cid in enumerate(target_cids_for_actions):
                    child_name = f" ({kid_detail.get(target_cid, 'Unknown Name')})" if kid_detail else ""
                    print(f"\n===== Deleting in Target CID {i+1}/{len(target_cids_for_actions)}: {Color.DARKCYAN}{target_cid}{Color.END}{child_name} =====")
                    target_delete_api = None
                    try:
                        target_delete_api = open_sdk(args.falcon_client_id, args.falcon_client_secret, args.base_url, "CustomIOA", member_cid=target_cid)
                        if not target_delete_api: raise Exception("SDK init failed for delete")
                        delete_results = delete_ioas(target_delete_api, delete_ids)
                        summary_tracker.update_delete_summary(target_cid, delete_results)
                        print(f"===== Finished Deletion for CID: {Color.DARKCYAN}{target_cid}{Color.END} =====")
                    except Exception as e:
                        print(f"{Color.RED}Error during delete setup/call for CID {target_cid}: {e}{Color.END}")
                        summary_tracker.update_delete_summary(target_cid, {"failed_count": len(delete_ids.split(',')), "errors": [{"message": f"Exception during delete setup/call: {e}"}]})
            else: # Non-MSSP Delete (Source Tenant)
                print(f"\n{Color.BOLD}--- Starting Delete Operation in {Color.MAGENTA}Source Tenant{Color.END} ---{Color.END}")
                delete_results = delete_ioas(falcon_ioa_source, delete_ids)
                summary_tracker.update_delete_summary(None, delete_results)

            print(f"{Color.BOLD}--- Delete Operation Complete ---{Color.END}")

# --- Final Summary ---
    summary_tracker.print_summary()

    end_time = time.time()
    # This is the full line 1078:
    print(f"\nScript finished in {Color.BOLD}{end_time - start_time:.2f}{Color.END} seconds.")

    # Deinitialize colorama
    if not args.nocolor:
        colorama.deinit()
