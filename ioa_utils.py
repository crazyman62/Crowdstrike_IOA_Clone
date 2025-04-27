# ioa_utils.py
# Contains shared utility functions, classes, and constants

import sys
import json
import time
import os
import platform

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

# --- Color Handling ---
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

# Global Color Object - Initialized by initialize_colors in main script
Color = BaseColor()

def initialize_colors(nocolor_arg):
    """Sets the global Color object based --nocolor arg and init colorama."""
    global Color
    if nocolor_arg:
        print("Color output disabled via --nocolor argument.")
        Color = NoColor()
        # Ensure colorama is not initialized if --nocolor is used
        try: colorama.deinit()
        except: pass
    else:
        # Initialize colorama. autoreset=False means we need explicit Color.END
        try:
            colorama.init(autoreset=False)
            Color = BaseColor() # Use standard ANSI codes
            print("Color output enabled (using colorama for cross-platform support).")
        except Exception as e:
             print(f"Warning: Failed to initialize colorama: {e}. Disabling color.")
             Color = NoColor()

def deinitialize_colors():
    """Deinitialize colorama if it was initialized."""
    # Check if Color is the BaseColor class (i.e., colors were not disabled)
    if isinstance(Color, BaseColor) and not isinstance(Color, NoColor):
        try:
             colorama.deinit()
        except:
             # Ignore if deinit fails (e.g., was never initialized)
             pass


# --- Summary Tracker Class ---
class ExecutionSummary:
    """Class to hold overall summary statistics for the script run."""
    def __init__(self):
        self.total_cids_processed = 0
        self.cids_with_errors = set()
        self.total_rules_processed = 0
        self.total_rules_created = 0
        self.total_rules_updated = 0
        self.total_rules_enabled_after_create = 0
        self.total_rules_enable_failed = 0
        self.total_rules_skipped_missing_data = 0
        self.total_rules_failed_creation = 0
        self.total_rules_failed_update = 0
        self.total_groups_deleted = 0
        self.total_groups_delete_failed = 0
        self.target_group_details = {}

    def update_cid_summary(self, cid, results):
        """Update overall summary from a single CID's processing results."""
        if not isinstance(results, dict): return
        self.total_cids_processed += 1
        cid_key = cid if cid else "Source Tenant"
        if results.get("errors"): self.cids_with_errors.add(cid_key)
        self.total_rules_processed += results.get("processed", 0)
        self.total_rules_created += results.get("created", 0)
        self.total_rules_updated += results.get("updated", 0)
        self.total_rules_enabled_after_create += results.get("enabled_after_create", 0)
        self.total_rules_enable_failed += results.get("enable_failed", 0)
        self.total_rules_skipped_missing_data += results.get("skipped_missing_data", 0)
        self.total_rules_failed_creation += results.get("failed_creation", 0)
        self.total_rules_failed_update += results.get("failed_update", 0)
        if "target_group_id" in results and results.get("target_group_id"):
             self.target_group_details[cid_key] = {
                "group_id": results.get("target_group_id"), "group_name": results.get("target_group_name") }

    def update_delete_summary(self, cid, delete_results):
        """Update overall summary from a single CID's deletion results."""
        if not isinstance(delete_results, dict): return
        cid_key = cid if cid else "Source Tenant"
        self.total_groups_deleted += delete_results.get("deleted_count", 0)
        self.total_groups_delete_failed += delete_results.get("failed_count", 0)
        if delete_results.get("errors"): self.cids_with_errors.add(cid_key)

    def print_summary(self):
        """Prints the final aggregated summary of the script execution."""
        print(f"\n{Color.BOLD}--- Overall Execution Summary ---{Color.END}")
        print(f"Total CIDs/Tenants Processed: {self.total_cids_processed}")
        if self.cids_with_errors:
             sorted_errors = sorted(list(self.cids_with_errors))
             print(f"{Color.RED}CIDs/Tenants with Errors:{Color.END} {', '.join(sorted_errors)}")
        print(f"\n{Color.UNDERLINE}Rule Operations Summary:{Color.END}")
        print(f"  Rules Processed (from source): {self.total_rules_processed}")
        print(f"  {Color.GREEN}Rules Created:{Color.END}                  {self.total_rules_created}")
        print(f"  {Color.LIGHTGREEN}Rules Enabled (after create):{Color.END}    {self.total_rules_enabled_after_create}")
        print(f"  {Color.CYAN}Rules Updated:{Color.END}                  {self.total_rules_updated}")
        print(f"  {Color.YELLOW}Rules Skipped (Missing Data):{Color.END}  {self.total_rules_skipped_missing_data}")
        print(f"  {Color.RED}Rules Failed Creation:{Color.END}         {self.total_rules_failed_creation}")
        print(f"  {Color.RED}Rules Failed Update:{Color.END}             {self.total_rules_failed_update}")
        print(f"  {Color.LIGHTRED}Rules Failed Enable (after create):{Color.END}{self.total_rules_enable_failed}")
        if self.total_groups_deleted > 0 or self.total_groups_delete_failed > 0:
            print(f"\n{Color.UNDERLINE}Rule Group Deletion Summary:{Color.END}")
            print(f"  {Color.GREEN}Groups Deleted Successfully:{Color.END} {self.total_groups_deleted}")
            print(f"  {Color.RED}Groups Failed Deletion:{Color.END}    {self.total_groups_delete_failed}")
        if self.target_group_details:
             print(f"\n{Color.UNDERLINE}Target Group Information:{Color.END}")
             for cid_key, details in sorted(self.target_group_details.items()):
                 cid_display = f"CID {Color.DARKCYAN}{cid_key}{Color.END}" if cid_key != "Source Tenant" else f"{Color.MAGENTA}Source Tenant{Color.END}"
                 print(f"  {cid_display}: Target Group '{details['group_name']}' (ID: {details['group_id']})")
        print(f"{Color.BOLD}--- End of Summary ---{Color.END}")


# --- SDK Initialization ---
def open_sdk(client_id: str, client_secret: str, base: str, service: str, member_cid: str = None):
    """Creates an instance of a specified FalconPy Service Class."""
    init_params = {"client_id": client_id, "client_secret": client_secret, "base_url": base}
    if member_cid: init_params["member_cid"] = member_cid
    try:
        ServiceClass = getattr(__import__('falconpy', fromlist=[service]), service)
        cid_str = f" for CID {Color.DARKCYAN}{member_cid}{Color.END}" if member_cid else f" for {Color.MAGENTA}source tenant{Color.END}"
        print(f"  Initializing {Color.BOLD}{service}{Color.END} SDK{cid_str}...")
        sdk_instance = ServiceClass(**init_params, debug=False, verbose=False) # Set debug=True for issues
        return sdk_instance
    except (ImportError, AttributeError):
        print(f"{Color.RED}Fatal Error: Invalid FalconPy service: '{service}'.{Color.END}")
        sys.exit(1)
    except Exception as e:
        # Log error but allow potential recovery depending on where it's called
        print(f"{Color.RED}Error: Failed to initialize Falcon {service} SDK{cid_str}: {e}{Color.END}")
        return None # Return None on failure

def open_mssp(client_id: str, client_secret: str, base: str):
    """Creates an instance of the Flight Control Service Class."""
    try:
        print(f"  Initializing {Color.BOLD}FlightControl{Color.END} SDK...")
        return FlightControl(client_id=client_id, client_secret=client_secret, base_url=base, debug=False, verbose=False)
    except Exception as e:
        print(f"{Color.RED}Fatal Error: Failed to initialize Flight Control SDK: {e}{Color.END}")
        sys.exit(1) # Exit if this fails

# --- Helper Functions ---
def chunk_long_description(desc, col_width) -> str:
    """Chunks a long string by delimiting with CR based upon column length."""
    if not isinstance(desc, str): return ""
    chunks = []; line = ""
    for word in desc.split():
        word = word.strip();
        if not word: continue
        while len(word) > col_width:
            if line: chunks.append(line)
            chunks.append(word[:col_width]); word = word[col_width:]; line = ""
        if len(line) + len(word) + (1 if line else 0) > col_width:
            if line: chunks.append(line)
            line = word
        else: line += (" " + word) if line else word
    if line: chunks.append(line)
    return "\n".join(chunks)

# --- Core Logic Functions (Shared) ---
def get_ioa_list(sdk: CustomIOA, filter_string: str = None):
    """Returns the list of IOA rule groups based upon the provided filter."""
    if not sdk:
         print(f"{Color.RED}Error: SDK object not provided to get_ioa_list.{Color.END}")
         return {"body": {"resources": []}, "status_code": 500, "errors": [{"message": "SDK not initialized"}]}

    parameters = {"limit": 500}
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
            offset = meta.get("offset", parameters["offset"])
            if not resources or len(all_resources) >= total: break
            parameters["offset"] = offset + limit
        except Exception as e:
            print(f"  {Color.RED}Error during API call in get_ioa_list: {e}{Color.END}")
            return {"body": {"resources": []}, "status_code": 500, "errors": [{"message": str(e)}]}

    print(f"  {Color.GREEN}Found {len(all_resources)} matching rule group(s).{Color.END}")
    return {"body": {"resources": all_resources}, "status_code": 200, "errors": None}

def display_ioas(matches: dict, table_format: str):
    """Displays the IOA listing in tabular format."""
    banner = [f"{Color.MAGENTA}{'='*51}", f"              Custom IOA Rule Groups", f"{'='*51}{Color.END}\n"]
    headers = {"name": f"{Color.BOLD}Group Name / ID / Comment{Color.END}", "desc": f"{Color.BOLD}Description{Color.END}", "plat": f"{Color.BOLD}Platform / Status / Ver{Color.END}", "rules": f"{Color.BOLD}Rules (Name / Status / Ver){Color.END}"}
    ioas = []
    resources = matches.get("body", {}).get("resources", [])
    if isinstance(resources, list):
        sorted_resources = sorted(resources, key=lambda x: x.get('name', '').lower() if isinstance(x, dict) else '')
        for match in sorted_resources:
            if not isinstance(match, dict): print(f"{Color.YELLOW}Warning: Skipping invalid group data.{Color.END}"); continue
            ioa = {}; name_comment = f"\n{Color.DARKCYAN}{match.get('comment', '')}{Color.END}" if match.get('comment') else ""
            ioa["name"] = f"{match.get('name', 'N/A')}\n{Color.CYAN}{match.get('id', 'N/A')}{Color.END}{name_comment}"
            ioa["desc"] = chunk_long_description(match.get("description", ""), 40)
            group_enabled = f"{Color.GREEN}Enabled{Color.END}" if match.get("enabled", False) else f"{Color.LIGHTRED}Disabled{Color.END}"
            platform_list = [f"{str(match.get('platform', 'N/A')).upper()}", f"{group_enabled}", f"Ver: {Color.BOLD}{match.get('version', 'N/A')}{Color.END}"]
            ioa["plat"] = "\n".join(platform_list)
            rules_list = match.get("rules", [])
            if isinstance(rules_list, list):
                 sorted_rules = sorted(rules_list, key=lambda x: x.get('name', '').lower() if isinstance(x, dict) else '')
                 rules_display = []
                 for rule in sorted_rules:
                     if isinstance(rule, dict):
                         rule_enabled = f"{Color.GREEN}E{Color.END}" if rule.get("enabled") else f"{Color.RED}D{Color.END}"
                         rules_display.append(f"{rule.get('name', 'N/A')} ({rule_enabled}/v{rule.get('instance_version', 'N/A')})")
                 ioa["rules"] = "\n".join(rules_display) if rules_display else f"{Color.YELLOW}No rules found.{Color.END}"
            else: ioa["rules"] = f"{Color.YELLOW}Invalid 'rules' format.{Color.END}"
            ioas.append(ioa)
    if not ioas:
        if matches.get("errors"): print(f"{Color.YELLOW}Could not display groups due to API errors.{Color.END}")
        else: print(f"\n{Color.YELLOW}--- No matching rule groups found ---{Color.END}\n")
    else: print("\n".join(banner)); print(tabulate(ioas, headers=headers, tablefmt=table_format))

def get_child_cid_details(mssp_sdk: FlightControl) -> dict:
    """Queries and returns a dictionary mapping accessible child CIDs to their names."""
    if not mssp_sdk:
        print(f"{Color.RED}Error: FlightControl SDK not provided to get_child_cid_details.{Color.END}")
        return {}

    print(f"Querying children CIDs using {Color.BOLD}FlightControl{Color.END} SDK...")
    all_child_cids = []; offset = None; limit = 500; kid_detail = {}
    while True:
        params = {"limit": limit};
        if offset: params["offset"] = offset
        try:
            kid_lookup = mssp_sdk.query_children(**params)
            status_code = kid_lookup.get("status_code", 500); body = kid_lookup.get("body", {})
            if status_code // 100 == 2:
                resources = body.get("resources", []);
                if not resources: break
                all_child_cids.extend(resources); meta = body.get("meta", {}).get("pagination", {})
                total = meta.get("total"); current_offset = meta.get("offset", offset or 0)
                if total is not None and (current_offset + limit >= total): break
                if len(resources) < limit: break
                offset = current_offset + limit
            else:
                e_msg = "Unknown";
                if body.get("errors"): e_msg = body["errors"][0].get("message",e_msg)
                print(f"{Color.RED}Err querying CIDs: {e_msg} (Code: {status_code}){Color.END}"); break
        except Exception as e: print(f"{Color.RED}Ex querying CIDs: {e}{Color.END}"); break
    print(f"Discovered {len(all_child_cids)} potential children CIDs.")
    if all_child_cids:
        print("Fetching details..."); child_details_list = []; chunk_size = 100
        for i in range(0, len(all_child_cids), chunk_size):
            chunk_ids = all_child_cids[i:i + chunk_size]
            try:
                resp = mssp_sdk.get_children(ids=chunk_ids)
                if resp.get("status_code", 500)//100 == 2: child_details_list.extend(resp.get("body", {}).get("resources", []))
                else:
                    e_msg = "Unknown";
                    if resp.get("body",{}).get("errors"): e_msg = resp["body"]["errors"][0].get("message", e_msg)
                    print(f"{Color.YELLOW}Warn: Get CID details chunk {i//chunk_size+1} failed. Code: {resp.get('status_code')}, Err: {e_msg}{Color.END}")
            except Exception as e: print(f"{Color.RED}Err fetch CID details chunk {i//chunk_size+1}: {e}{Color.END}")
        for child in child_details_list:
            cid = child.get("child_cid"); name = child.get("name", "Unknown")
            if cid: kid_detail[cid] = name
        print(f"{Color.GREEN}Fetched details for {len(kid_detail)} children.{Color.END}")
    else: print(f"{Color.YELLOW}No children CIDs found/accessible.{Color.END}")
    return kid_detail

def display_child_cids(cid_details: dict, table_format: str):
    """Displays Child CIDs and Names in a table."""
    if not cid_details: print("\nNo accessible child CIDs found to display."); return
    print(f"\n--- {Color.BOLD}Accessible Child CIDs{Color.END} ---")
    headers = {"cid": f"{Color.BOLD}Child CID{Color.END}", "name": f"{Color.BOLD}Child Name{Color.END}"}
    data = [{"cid": cid, "name": name} for cid, name in sorted(cid_details.items(), key=lambda item: item[1].lower())]
    print(tabulate(data, headers=headers, tablefmt=table_format)); print(f"--- Total: {len(data)} ---")

def get_target_group_details(target_ioa_api: CustomIOA, target_group_id: str):
    """Helper function to get the details of a specific rule group by ID."""
    if not target_ioa_api:
        print(f"{Color.RED}Error: SDK not provided to get_target_group_details.{Color.END}")
        return None
    try:
        resp = target_ioa_api.get_rule_groups(ids=[target_group_id])
        if resp.get("status_code", 500)//100 == 2:
            res = resp.get("body", {}).get("resources", [])
            if res: return res[0]
            else: print(f"  {Color.YELLOW}Warn: get_rule_groups ID {target_group_id} no resources.{Color.END}"); return None
        else:
            e_msg = "Unknown";
            if resp.get("body",{}).get("errors"): e_msg = resp["body"]["errors"][0].get("message", e_msg)
            print(f"  {Color.YELLOW}Warn: get_rule_groups ID {target_group_id} failed. Code: {resp.get('status_code')}. Err: {e_msg}{Color.END}"); return None
    except Exception as e: print(f"  {Color.RED}Err get_target_group_details ID {target_group_id}: {e}{Color.END}"); return None

