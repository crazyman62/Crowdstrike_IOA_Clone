# ioa_utils.py
# Contains shared utility functions, classes, and constants

import sys
import json
import time
import os
import platform
import threading
import logging

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

# Get a logger instance for this module
logger = logging.getLogger(__name__)

# --- Color Handling ---
class BaseColor:
    PURPLE = "\033[95m"; CYAN = "\033[96m"; DARKCYAN = "\033[36m"
    MAGENTA = "\033[35m"; BLUE = "\033[34m"; LIGHTBLUE = "\033[94m"
    GREEN = "\033[32m"; LIGHTGREEN = "\033[92m"; LIGHTYELLOW = "\033[93m"
    YELLOW = "\033[33m"; RED = "\033[31m"; LIGHTRED = "\033[91m"
    BOLD = "\033[1m"; UNDERLINE = "\033[4m"; END = "\033[0m"
class NoColor:
    PURPLE = ""; CYAN = ""; DARKCYAN = ""; MAGENTA = ""; BLUE = ""; LIGHTBLUE = ""
    GREEN = ""; LIGHTGREEN = ""; LIGHTYELLOW = ""; YELLOW = ""; RED = ""; LIGHTRED = ""
    BOLD = ""; UNDERLINE = ""; END = ""
Color = BaseColor()

def initialize_colors(nocolor_arg):
    global Color
    if nocolor_arg:
        print("Color output disabled via --nocolor argument.")
        Color = NoColor()
        try: colorama.deinit()
        except: pass
    else:
        try:
            colorama.init(autoreset=False)
            Color = BaseColor()
            print("Color output enabled (using colorama for cross-platform support).")
        except Exception as e:
             print(f"Warning: Failed to initialize colorama: {e}. Disabling color.")
             Color = NoColor()

def deinitialize_colors():
    if isinstance(Color, BaseColor) and not isinstance(Color, NoColor):
        try: colorama.deinit()
        except: pass


# --- Summary Tracker Class (Thread-Safe) ---
class ExecutionSummary:
    """Class to hold overall summary statistics for the script run."""
    def __init__(self):
        self.total_cids_processed = 0
        self.processed_cids_info = {} # Store {cid_key: {"name": name, "thread": thread_name, "has_errors": bool}}
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
        self._lock = threading.Lock()

    def _update_processed_cid(self, cid_key, name, thread_name, has_errors):
        """Internal helper to update the processed CID info."""
        if cid_key not in self.processed_cids_info:
            self.total_cids_processed += 1
            self.processed_cids_info[cid_key] = {"name": name, "thread": thread_name, "has_errors": has_errors}
        else:
            # If already processed, just update the error status if a new error occurred
            if has_errors:
                self.processed_cids_info[cid_key]["has_errors"] = True
            # Keep the original thread name that first processed it
            # self.processed_cids_info[cid_key]["thread"] = thread_name # Or update? Let's keep first.

    def update_cid_summary(self, cid, results, kids_details, thread_name):
        """Update overall summary from a single CID's processing results (thread-safe)."""
        with self._lock:
            if not isinstance(results, dict): return
            cid_key = cid if cid else "Source Tenant"
            cid_name = kids_details.get(cid, cid) if cid else "Source Tenant"
            has_errors = bool(results.get("errors"))

            self._update_processed_cid(cid_key, cid_name, thread_name, has_errors)

            # Accumulate rule stats
            self.total_rules_processed += results.get("processed", 0)
            self.total_rules_created += results.get("created", 0)
            self.total_rules_updated += results.get("updated", 0)
            self.total_rules_enabled_after_create += results.get("enabled_after_create", 0)
            self.total_rules_enable_failed += results.get("enable_failed", 0)
            self.total_rules_skipped_missing_data += results.get("skipped_missing_data", 0)
            self.total_rules_failed_creation += results.get("failed_creation", 0)
            self.total_rules_failed_update += results.get("failed_update", 0)

    def update_delete_summary(self, cid, delete_results, kids_details, thread_name):
        """Update overall summary from a single CID's deletion results (thread-safe)."""
        with self._lock:
            if not isinstance(delete_results, dict): return
            cid_key = cid if cid else "Source Tenant"
            cid_name = kids_details.get(cid, cid) if cid else "Source Tenant"
            has_errors = bool(delete_results.get("errors")) or delete_results.get("failed_count", 0) > 0

            self._update_processed_cid(cid_key, cid_name, thread_name, has_errors)

            # Accumulate delete stats
            self.total_groups_deleted += delete_results.get("deleted_count", 0)
            self.total_groups_delete_failed += delete_results.get("failed_count", 0)


    def print_summary(self):
        """Prints the final aggregated summary of the script execution."""
        with self._lock:
            print(f"\n{Color.BOLD}--- Overall Execution Summary ---{Color.END}")
            print(f"Total CIDs/Tenants Processed: {self.total_cids_processed}")

            # --- Processed CID List ---
            if self.processed_cids_info:
                 print(f"\n{Color.UNDERLINE}Processed CIDs/Tenants & Threads:{Color.END}")
                 # Sort items by CID name for readability
                 sorted_cids = sorted(self.processed_cids_info.items(), key=lambda item: item[1]['name'])
                 for cid_key, info in sorted_cids:
                     name_str = f"{Color.DARKCYAN}{info['name']}{Color.END}" if cid_key != "Source Tenant" else f"{Color.MAGENTA}Source Tenant{Color.END}"
                     status_color = Color.RED if info['has_errors'] else Color.GREEN
                     status_text = "Errors" if info['has_errors'] else "OK"
                     print(f"  - {name_str:<60} (Thread: {info['thread']:<15}) [{status_color}{status_text}{Color.END}]")
            # --- End Processed CID List ---

            # --- Rule Operations Summary ---
            # Only print if rules were processed
            if self.total_rules_processed > 0:
                print(f"\n{Color.UNDERLINE}Rule Operations Summary (Aggregated):{Color.END}")
                print(f"  Rules Processed (from source): {self.total_rules_processed}")
                print(f"  {Color.GREEN}Rules Created:{Color.END}                  {self.total_rules_created}")
                print(f"  {Color.LIGHTGREEN}Rules Enabled (after create):{Color.END}    {self.total_rules_enabled_after_create}")
                print(f"  {Color.CYAN}Rules Updated:{Color.END}                  {self.total_rules_updated}")
                print(f"  {Color.YELLOW}Rules Skipped (Missing Data):{Color.END}  {self.total_rules_skipped_missing_data}")
                print(f"  {Color.RED}Rules Failed Creation:{Color.END}         {self.total_rules_failed_creation}")
                print(f"  {Color.RED}Rules Failed Update:{Color.END}             {self.total_rules_failed_update}")
                print(f"  {Color.LIGHTRED}Rules Failed Enable (after create):{Color.END}{self.total_rules_enable_failed}")
            # --- End Rule Operations Summary ---

            # --- Deletion Summary ---
            if self.total_groups_deleted > 0 or self.total_groups_delete_failed > 0:
                print(f"\n{Color.UNDERLINE}Rule Group Deletion Summary (Aggregated):{Color.END}")
                print(f"  {Color.GREEN}Groups Deleted Successfully:{Color.END} {self.total_groups_deleted}")
                print(f"  {Color.RED}Groups Failed Deletion:{Color.END}    {self.total_groups_delete_failed}")
            # --- End Deletion Summary ---

            print(f"{Color.BOLD}--- End of Summary ---{Color.END}")


# --- SDK Initialization ---
# (open_sdk and open_mssp remain the same)
def open_sdk(client_id: str, client_secret: str, base: str, service: str, member_cid: str = None):
    init_params = {"client_id": client_id, "client_secret": client_secret, "base_url": base}
    if member_cid: init_params["member_cid"] = member_cid
    try:
        ServiceClass = getattr(__import__('falconpy', fromlist=[service]), service)
        cid_str = f" for CID {member_cid}" if member_cid else " for source tenant"
        logger.info(f"Initializing {service} SDK{cid_str}...")
        sdk_instance = ServiceClass(**init_params, debug=False, verbose=False)
        logger.info(f"Successfully initialized {service} SDK{cid_str}.")
        return sdk_instance
    except (ImportError, AttributeError):
        logger.critical(f"Fatal Error: Invalid FalconPy service: '{service}'.")
        sys.exit(1)
    except Exception as e:
        cid_str = f" for CID {member_cid}" if member_cid else " for source tenant"
        logger.error(f"Failed to initialize Falcon {service} SDK{cid_str}: {e}")
        return None

def open_mssp(client_id: str, client_secret: str, base: str):
    try:
        logger.info(f"Initializing FlightControl SDK...")
        sdk = FlightControl(client_id=client_id, client_secret=client_secret, base_url=base, debug=False, verbose=False)
        logger.info("Successfully initialized FlightControl SDK.")
        return sdk
    except Exception as e:
        logger.critical(f"Fatal Error: Failed to initialize Flight Control SDK: {e}")
        sys.exit(1)


# --- Helper Functions ---
# (chunk_long_description remains the same)
def chunk_long_description(desc, col_width) -> str:
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
# (get_ioa_list, display_ioas, get_child_cid_details, display_child_cids, get_target_group_details remain the same)
def get_ioa_list(sdk: CustomIOA, filter_string: str = None):
    if not sdk:
         logger.error("SDK object not provided to get_ioa_list.")
         return {"body": {"resources": []}, "status_code": 500, "errors": [{"message": "SDK not initialized"}]}
    parameters = {"limit": 500}
    if filter_string:
        safe_filter = filter_string.replace("'", "\\'")
        parameters["filter"] = f"name:*'*{safe_filter}*'"
        logger.info(f"Querying rule groups using filter: {parameters['filter']}...")
    else: logger.info("Querying all rule groups (no filter)...")
    all_resources = []; parameters["offset"] = 0
    while True:
        try:
            response = sdk.query_rule_groups_full(parameters=parameters)
            status_code = response.get("status_code", 500); body = response.get("body", {})
            if status_code // 100 != 2:
                 logger.warning(f"API query for rule groups returned status {status_code}.")
                 errors = body.get("errors", [{"message": "Unknown API error"}])
                 for error in errors: logger.error(f"API Error (query_rule_groups_full): {error.get('message', 'Unknown error')}")
                 return {"body": {"resources": []}, "status_code": status_code, "errors": errors}
            resources = body.get("resources", [])
            all_resources.extend(resources)
            meta = body.get("meta", {}).get("pagination", {}); total = meta.get("total", len(all_resources))
            limit = meta.get("limit", 500); offset = meta.get("offset", parameters["offset"])
            if not resources or len(all_resources) >= total: break
            parameters["offset"] = offset + limit
        except Exception as e:
            logger.error(f"Exception during API call in get_ioa_list: {e}", exc_info=True)
            return {"body": {"resources": []}, "status_code": 500, "errors": [{"message": str(e)}]}
    logger.info(f"Found {len(all_resources)} matching rule group(s).")
    return {"body": {"resources": all_resources}, "status_code": 200, "errors": None}

def display_ioas(matches: dict, table_format: str):
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
    if not mssp_sdk: logger.error("FlightControl SDK not provided to get_child_cid_details."); return {}
    logger.info(f"Querying children CIDs using FlightControl SDK...")
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
                logger.error(f"Error querying CIDs: {e_msg} (Code: {status_code})"); break
        except Exception as e: logger.error(f"Exception querying CIDs: {e}", exc_info=True); break
    logger.info(f"Discovered {len(all_child_cids)} potential children CIDs.")
    if all_child_cids:
        logger.info("Fetching details for discovered children..."); child_details_list = []; chunk_size = 100
        for i in range(0, len(all_child_cids), chunk_size):
            chunk_ids = all_child_cids[i:i + chunk_size]
            try:
                resp = mssp_sdk.get_children(ids=chunk_ids)
                if resp.get("status_code", 500)//100 == 2: child_details_list.extend(resp.get("body", {}).get("resources", []))
                else:
                    e_msg = "Unknown";
                    if resp.get("body",{}).get("errors"): e_msg = resp["body"]["errors"][0].get("message", e_msg)
                    logger.warning(f"Get CID details chunk {i//chunk_size+1} failed. Code: {resp.get('status_code')}, Err: {e_msg}")
            except Exception as e: logger.error(f"Error fetching children chunk {i//chunk_size+1}: {e}", exc_info=True)
        for child in child_details_list:
            cid = child.get("child_cid"); name = child.get("name", "Unknown")
            if cid: kid_detail[cid] = name
        logger.info(f"Fetched details for {len(kid_detail)} children.")
    else: logger.info("No children CIDs found/accessible.")
    return kid_detail

def display_child_cids(cid_details: dict, table_format: str):
    if not cid_details: print("\nNo accessible child CIDs found to display."); return
    print(f"\n--- {Color.BOLD}Accessible Child CIDs{Color.END} ---")
    headers = {"cid": f"{Color.BOLD}Child CID{Color.END}", "name": f"{Color.BOLD}Child Name{Color.END}"}
    data = [{"cid": cid, "name": name} for cid, name in sorted(cid_details.items(), key=lambda item: item[1].lower())]
    print(tabulate(data, headers=headers, tablefmt=table_format)); print(f"--- Total: {len(data)} ---")

def get_target_group_details(target_ioa_api: CustomIOA, target_group_id: str):
    if not target_ioa_api: logger.error("SDK not provided to get_target_group_details."); return None
    try:
        resp = target_ioa_api.get_rule_groups(ids=[target_group_id])
        if resp.get("status_code", 500)//100 == 2:
            res = resp.get("body", {}).get("resources", [])
            if res: return res[0]
            else: logger.warning(f"get_rule_groups ID {target_group_id} no resources."); return None
        else:
            e_msg = "Unknown";
            if resp.get("body",{}).get("errors"): e_msg = resp["body"]["errors"][0].get("message", e_msg)
            logger.warning(f"get_rule_groups ID {target_group_id} failed. Code: {resp.get('status_code')}. Err: {e_msg}"); return None
    except Exception as e: logger.error(f"Err get_target_group_details ID {target_group_id}: {e}", exc_info=True); return None

