# ioa_main.py
# Main script to orchestrate IOA rule management tasks

import sys
import time
import json
import os
import logging # Added for logging setup
import threading # Added for thread name
from argparse import ArgumentParser, RawTextHelpFormatter, Action
import concurrent.futures # Added for threading

# Import components from other modules
from ioa_utils import (
    Color, initialize_colors, deinitialize_colors, ExecutionSummary,
    open_sdk, open_mssp, get_ioa_list, display_ioas,
    get_child_cid_details, display_child_cids
)
from ioa_replication import replicate_or_update_rules_to_target
from ioa_deletion import delete_ioas

# --- Logging Setup ---
def setup_logging():
    """Configures basic logging."""
    # Use a format that includes timestamp and level name
    # Add %(threadName)s to see which thread is logging, useful for debugging concurrency
    log_format = '%(asctime)s - %(levelname)-8s - [%(threadName)s] - %(message)s'
    # Basic config sets up the root logger
    # Use FORCE=True in basicConfig if running in an environment that might pre-configure logging (like some notebooks)
    logging.basicConfig(level=logging.INFO, format=log_format, datefmt='%Y-%m-%d %H:%M:%S')
    # Optional: Silence noisy libraries if needed (e.g., urllib3 from requests)
    # logging.getLogger("urllib3").setLevel(logging.WARNING)
    # logging.getLogger("falconpy").setLevel(logging.WARNING) # Silence SDK debug/info if desired
    logging.info("Logging configured.")

# --- Argument Parser Action for Mutually Exclusive Groups ---
class MutuallyExclusiveAction(Action):
    _ACTION_GROUP_TRACKER_NAME = '_mutually_exclusive_action_group_tracker'
    def __init__(self, option_strings, dest, nargs=None, **kwargs):
        if nargs is not None: raise ValueError("nargs not allowed")
        super().__init__(option_strings, dest, nargs=0, **kwargs)
    def __call__(self, parser, namespace, values, option_string=None):
        tracker = getattr(namespace, self._ACTION_GROUP_TRACKER_NAME, None)
        if tracker is None: tracker = set(); setattr(namespace, self._ACTION_GROUP_TRACKER_NAME, tracker)
        if tracker and self.dest not in tracker:
            opts = ', '.join('--' + opt.replace('_', '-') for opt in tracker)
            parser.error(f"argument {option_string}: not allowed with argument {opts}")
        tracker.add(self.dest); setattr(namespace, self.dest, True)

# --- Argument Parsing ---
def consume_arguments():
    """Consume and validate command-line arguments, incorporating a config file."""
    # Define the parser fully first
    parser = ArgumentParser(
        description="Manage CrowdStrike Custom IOA Rules between tenants. Reads config from file if specified, flags override config.",
        formatter_class=RawTextHelpFormatter
    )

    # --- Config File Argument ---
    parser.add_argument(
        "-c", "--config",
        help="Path to a JSON configuration file.",
        metavar="CONFIG_FILE",
        default=None
    )

    # --- Other Arguments (Define all here) ---
    # Core arguments
    parser.add_argument("-n", "--nocolor", help="Force disable color output", action="store_true", default=None) # Default None initially
    parser.add_argument("-b", "--base_url", help="CrowdStrike API Base URL. Default: 'auto'", default=None)
    parser.add_argument("-t", "--table_format", help="Tabular display format. Default: 'fancy_grid'", default=None)
    parser.add_argument("--max-workers", help="Maximum concurrent threads for processing CIDs. Default: 5.", type=int, default=None) # Added for threading

    # Filters
    filter_group = parser.add_argument_group("source filters (for --list_parent_ioas, --replicate_rules)")
    filter_exclusive_group = filter_group.add_mutually_exclusive_group()
    filter_exclusive_group.add_argument("-f", "--filter", help="Filter SOURCE rule groups by name.", default=None)
    filter_exclusive_group.add_argument("--rule_name", help="Filter for a SINGLE rule name (used with --replicate_rules).", default=None)

    # Actions
    action_group = parser.add_argument_group("actions (choose one)")
    action_group.add_argument("--list_cids", help="List accessible child CIDs.", action=MutuallyExclusiveAction, dest='list_cids', default=False)
    action_group.add_argument("--list_parent_ioas", help="List parent tenant IOA groups.", action=MutuallyExclusiveAction, dest='list_parent_ioas', default=False)
    action_group.add_argument("-r", "--replicate_rules", help="Replicate/Update rules into a target group.", action=MutuallyExclusiveAction, dest='replicate_rules', default=False)
    action_group.add_argument("--replicate_all_parent_rules", help="Replicate/Update rules from ALL source groups.", action=MutuallyExclusiveAction, dest='replicate_all_parent_rules', default=False)
    action_group.add_argument("-d", "--delete_group", help="Delete rule group IDs in target(s).", action=MutuallyExclusiveAction, dest='delete_group', default=False)
    action_group.add_argument("--delete_ids", help="Rule group IDs to delete (required for --delete_group).", default=None)

    # Action Modifiers
    mod_group = parser.add_argument_group("action modifiers")
    mod_group.add_argument("--target_group_name", help="PRE-EXISTING target rule group name (Required for replication).", default=None)

    # MSSP Arguments
    mssp_group = parser.add_argument_group("mssp arguments (target specification)")
    mssp_target_group = mssp_group.add_mutually_exclusive_group()
    mssp_target_group.add_argument("-m", "--managed_targets", help="Comma-separated list of target child CIDs.", default=None)
    mssp_target_group.add_argument("--all_cids", help="Target ALL accessible child CIDs.", action="store_true", default=False)

    # API Keys (Define without required=True initially)
    req_group = parser.add_argument_group("API credentials")
    req_group.add_argument("-k", "--falcon_client_id", help="CrowdStrike Falcon API Client ID (or provide in config)", default=None)
    req_group.add_argument("-s", "--falcon_client_secret", help="CrowdStrike Falcon API Client Secret (or provide in config)", default=None)

    # --- Parse arguments initially ---
    # This captures command-line values, others remain None or default action values
    args = parser.parse_args()

    # --- Load Config File ---
    config_data = {}
    if args.config:
        config_file_path = args.config
        if os.path.exists(config_file_path):
            try:
                with open(config_file_path, 'r') as f:
                    config_data = json.load(f)
                print(f"Loaded configuration from: {config_file_path}") # Keep this print
            except Exception as e: parser.error(f"Error reading/parsing config file '{config_file_path}': {e}")
        else: parser.error(f"Specified config file does not exist: '{config_file_path}'")

    # --- Apply Config Defaults (if arg not set via command line) ---
    # Set defaults for args that were initially None
    args.nocolor = args.nocolor if args.nocolor is not None else config_data.get('nocolor', False) # Handle boolean flag
    args.base_url = args.base_url if args.base_url is not None else config_data.get('base_url', 'auto')
    args.table_format = args.table_format if args.table_format is not None else config_data.get('table_format', 'fancy_grid')
    args.max_workers = args.max_workers if args.max_workers is not None else config_data.get('max_workers', 5) # Apply default for max_workers
    args.filter = args.filter if args.filter is not None else config_data.get('filter', None)
    args.rule_name = args.rule_name if args.rule_name is not None else config_data.get('rule_name', None)
    args.delete_ids = args.delete_ids if args.delete_ids is not None else config_data.get('delete_ids', None)
    args.target_group_name = args.target_group_name if args.target_group_name is not None else config_data.get('target_group_name', None)
    args.managed_targets = args.managed_targets if args.managed_targets is not None else config_data.get('managed_targets', None)
    # Apply API keys from config ONLY if not provided via command line
    args.falcon_client_id = args.falcon_client_id if args.falcon_client_id is not None else config_data.get('falcon_client_id', None)
    args.falcon_client_secret = args.falcon_client_secret if args.falcon_client_secret is not None else config_data.get('falcon_client_secret', None)


    # --- Final Validation ---
    # Explicitly check for API keys AFTER applying config defaults
    if not args.falcon_client_id:
        parser.error("argument -k/--falcon_client_id is required (or must be in config file)")
    if not args.falcon_client_secret:
        parser.error("argument -s/--falcon_client_secret is required (or must be in config file)")
    # Validate max_workers
    if args.max_workers <= 0:
        parser.error("--max-workers must be a positive integer")


    # Initialize action flags safely (needed for mutually exclusive group logic)
    # This needs to happen AFTER args are fully populated
    args.list_cids = getattr(args, 'list_cids', False)
    args.list_parent_ioas = getattr(args, 'list_parent_ioas', False)
    args.replicate_rules = getattr(args, 'replicate_rules', False)
    args.replicate_all_parent_rules = getattr(args, 'replicate_all_parent_rules', False)
    args.delete_group = getattr(args, 'delete_group', False)

    # Action-specific validation
    if args.replicate_rules and not (args.filter or args.rule_name):
        parser.error("-f/--filter OR --rule_name required with --replicate_rules (can be set in config)")
    if args.replicate_all_parent_rules and args.rule_name:
        parser.error("--rule_name cannot be used with --replicate_all_parent_rules.")
    if (args.replicate_rules or args.replicate_all_parent_rules) and not args.target_group_name:
        parser.error("--target_group_name required for replication (can be set in config)")
    if args.delete_group and not args.delete_ids:
        parser.error("--delete_ids required with --delete_group (can be set in config)")

    # Ensure an action was selected
    if not any([args.list_cids, args.list_parent_ioas, args.replicate_rules, args.replicate_all_parent_rules, args.delete_group]):
         parser.error("No action specified. Choose one: --list_cids, --list_parent_ioas, --replicate_rules, --replicate_all_parent_rules, or --delete_group.")

    # Final check for MSSP target specification if action requires it
    if (args.replicate_rules or args.replicate_all_parent_rules or args.delete_group) and not args.managed_targets and not args.all_cids:
         logging.warning("No MSSP target specified (-m or --all_cids). Action will run on the source tenant only.")

    return args

# --- Worker Functions for Threading ---
def process_replication_for_cid(cid, args, source_data, summary_tracker, kids):
    """Worker function to replicate/update rules for a single CID."""
    worker_logger = logging.getLogger(__name__) # Get logger instance
    thread_name = threading.current_thread().name # Get thread name
    try:
        child_name = f" ({kids.get(cid,'?')})" if kids else ""
        worker_logger.info(f"Worker started for CID: {cid}{child_name}")
        target_sdk = open_sdk(args.falcon_client_id, args.falcon_client_secret, args.base_url, "CustomIOA", member_cid=cid)
        if target_sdk:
            # Pass kids dictionary AND thread_name to the replication function's summary update
            replicate_or_update_rules_to_target(
                target_sdk, source_data, cid, args.target_group_name, summary_tracker, args.rule_name, kids, thread_name
            )
        else:
            worker_logger.error(f"Cannot process replication in CID {cid} due to SDK init failure.")
            # Pass kids dictionary AND thread_name when updating summary
            summary_tracker.update_cid_summary(cid, {"errors": ["SDK init failed"]}, kids, thread_name)
        worker_logger.info(f"Worker finished for CID: {cid}")
        return True
    except Exception as e:
        worker_logger.error(f"Unhandled Exception in replication worker for CID {cid}: {e}", exc_info=True)
        summary_tracker.update_cid_summary(cid, {"errors": [f"Unhandled Exception: {e}"]}, kids, thread_name)
        return False

def process_deletion_for_cid(cid, args, summary_tracker, kids):
    """Worker function to delete groups for a single CID."""
    worker_logger = logging.getLogger(__name__) # Get logger instance
    thread_name = threading.current_thread().name # Get thread name
    try:
        child_name = f" ({kids.get(cid,'?')})" if kids else ""
        worker_logger.info(f"Worker started for deletion in CID: {cid}{child_name}")
        target_sdk = open_sdk(args.falcon_client_id, args.falcon_client_secret, args.base_url, "CustomIOA", member_cid=cid)
        if target_sdk:
            # Pass kids dictionary AND thread_name to the deletion function's summary update
            delete_ioas(target_sdk, args.delete_ids, summary_tracker, cid, kids, thread_name)
        else:
            worker_logger.error(f"Cannot perform delete in CID {cid} due to SDK init failure.")
            # Pass kids dictionary AND thread_name when updating summary
            summary_tracker.update_delete_summary(cid, {"failed_count":len(args.delete_ids.split(',')), "errors":[{"message":"SDK init failed"}]}, kids, thread_name)
        worker_logger.info(f"Worker finished deletion for CID: {cid}")
        return True
    except Exception as e:
        worker_logger.error(f"Unhandled Exception in deletion worker for CID {cid}: {e}", exc_info=True)
        summary_tracker.update_delete_summary(cid, {"failed_count":len(args.delete_ids.split(',')), "errors":[f"Unhandled Exception: {e}"]}, kids, thread_name)
        return False


# --- Main Execution Block ---
if __name__ == "__main__":
    start_time = time.time()
    # Setup logging first
    setup_logging()
    logger = logging.getLogger(__name__) # Get logger for main thread

    args = consume_arguments() # Gets args, potentially merged with config

    # Initialize color handling and summary tracker
    initialize_colors(args.nocolor) # Use final args value
    summary_tracker = ExecutionSummary()

    logger.info("Starting IOA Rule Management Script...")

    # --- SDK Init (Source) ---
    logger.info("Connecting to Source Tenant...") # Use logger
    falcon_ioa_source = open_sdk(args.falcon_client_id, args.falcon_client_secret, args.base_url, "CustomIOA")
    if not falcon_ioa_source: logger.critical("Fatal Error: Could not initialize SDK for source tenant. Exiting."); deinitialize_colors(); sys.exit(1)
    logger.info("Source SDK initialized.")

    # --- Actions ---
    if args.list_parent_ioas:
        logger.info("--- Listing Parent IOA Groups ---")
        parent_ioas = get_ioa_list(falcon_ioa_source, args.filter)
        display_ioas(parent_ioas, args.table_format) # Keep print for table display
        logger.info("--- Listing Complete ---")
        deinitialize_colors(); sys.exit(0)

    if args.list_cids:
        logger.info("--- Listing Child CIDs ---")
        mssp_sdk = open_mssp(args.falcon_client_id, args.falcon_client_secret, args.base_url)
        details = get_child_cid_details(mssp_sdk)
        display_child_cids(details, args.table_format) # Keep print for table display
        logger.info("--- Listing Complete ---")
        deinitialize_colors(); sys.exit(0)

    # --- Get Source Rules (if replicating) ---
    source_data = {"body": {"resources": []}, "status_code": 0, "errors": None}
    if args.replicate_rules or args.replicate_all_parent_rules:
        logger.info("--- Retrieving Source IOA Rule Groups ---")
        source_data = get_ioa_list(falcon_ioa_source, args.filter)
        if source_data.get("status_code", 500)//100 != 2:
            logger.critical("Fatal Err: Cannot get source groups. Exit.")
            if source_data.get("errors"): [logger.error(f"  - {e.get('message')}") for e in source_data["errors"]]
            deinitialize_colors(); sys.exit(1)
        count = len(source_data.get("body",{}).get("resources",[]))
        logger.info(f"Found {count} source groups.")
        if count == 0:
            logger.warning("No source groups match. No rules will be replicated/updated.")
            if args.rule_name: logger.warning(f"Check group filter ('{args.filter}') for rule '{args.rule_name}'.")

    # --- MSSP Child Handling ---
    DO_MSSP = False; kids = {}; targets = []
    if args.managed_targets or args.all_cids:
        logger.info("--- MSSP Target Handling ---")
        mssp_sdk = open_mssp(args.falcon_client_id, args.falcon_client_secret, args.base_url)
        kids = get_child_cid_details(mssp_sdk) # kids is the CID -> Name dictionary
        if not kids: logger.warning("No accessible child CIDs found. No MSSP actions.")
        elif args.all_cids: targets = sorted(list(kids.keys())); logger.info(f"Target all {len(targets)} children."); DO_MSSP = bool(targets)
        elif args.managed_targets:
            user_tgts = [c.strip() for c in args.managed_targets.split(",") if c.strip()]
            logger.info(f"Validating {len(user_tgts)} specified target CID(s)...")
            valid = []; invalid = []; norm_user = {t.split('-')[0].lower(): t for t in user_tgts}
            norm_kids = {c.split('-')[0].lower(): (c,n) for c,n in kids.items()}; valid_map = {}
            for norm_u, orig_u in norm_user.items():
                if norm_u in norm_kids: actual_c, name = norm_kids[norm_u]; valid_map[norm_u]=actual_c; logger.info(f"  - Validated: {actual_c} ({name})")
                else: invalid.append(orig_u); logger.warning(f"  - Not Found/Accessible: {orig_u}")
            targets = sorted([valid_map[n] for n in valid_map])
            if targets: DO_MSSP = True; logger.info(f"Proceed with {len(targets)} valid target CIDs.")
            if invalid: logger.warning(f"Invalid/Inaccessible CIDs: {', '.join(invalid)}")
            if not DO_MSSP: logger.warning("No valid CIDs specified. No MSSP actions.")

    MAX_WORKERS = args.max_workers
    logger.info(f"Using a maximum of {MAX_WORKERS} worker threads for CID processing.")
    main_thread_name = threading.current_thread().name # Get main thread name for source ops

    # --- Action Execution ---
    # Replicate/Update
    if args.replicate_rules or args.replicate_all_parent_rules:
        verb = "Replicate/Update Rules"; src_groups = source_data.get("body",{}).get("resources",[])
        skip = False
        if not (args.replicate_rules or args.replicate_all_parent_rules): skip=True
        elif not args.target_group_name: logger.error(f"Skip {verb}: --target_group_name required."); skip=True
        elif not src_groups and not args.rule_name: logger.warning(f"Skip {verb}: No source groups match."); skip=True
        elif (args.managed_targets or args.all_cids) and not DO_MSSP: logger.warning(f"Skip MSSP {verb}: No valid CIDs."); skip=True

        if not skip:
            if DO_MSSP:
                logger.info(f"--- Start {verb} on {len(targets)} Child Tenant(s) using up to {MAX_WORKERS} workers ---")
                with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                    # Pass kids dictionary to the worker submit call
                    future_to_cid = {executor.submit(process_replication_for_cid, cid, args, source_data, summary_tracker, kids): cid for cid in targets}
                    for future in concurrent.futures.as_completed(future_to_cid):
                        cid = future_to_cid[future]
                        try: future.result() # Check for exceptions raised in worker
                        except Exception as exc: logger.error(f"CID {cid} replication worker generated an exception: {exc}", exc_info=True)
            else: # Source Tenant
                logger.info(f"--- Start {verb} within Source Tenant ---")
                logger.warning(f"Target is Source Tenant. Rules -> Group '{args.target_group_name}'.")
                target_sdk = falcon_ioa_source
                # Pass empty kids dict and main thread name for source tenant run
                replicate_or_update_rules_to_target(target_sdk, source_data, None, args.target_group_name, summary_tracker, args.rule_name, {}, main_thread_name)
            logger.info(f"--- {verb} Complete ---")

    # Delete
    if args.delete_group:
        ids = args.delete_ids; skip = False
        if not ids: logger.warning("Skip Delete: No IDs provided."); skip=True
        elif (args.managed_targets or args.all_cids) and not DO_MSSP: logger.warning("Skip MSSP Delete: No valid CIDs."); skip=True

        if not skip:
            if DO_MSSP:
                logger.info(f"--- Start Delete in {len(targets)} Child Tenant(s) using up to {MAX_WORKERS} workers ---")
                logger.warning(f"Note: Attempt delete Group IDs [{ids}] in ALL targets.")
                with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                    # Pass kids dictionary to the worker submit call
                    future_to_cid = {executor.submit(process_deletion_for_cid, cid, args, summary_tracker, kids): cid for cid in targets}
                    for future in concurrent.futures.as_completed(future_to_cid):
                        cid = future_to_cid[future]
                        try: future.result() # Check for exceptions raised in worker
                        except Exception as exc: logger.error(f"CID {cid} deletion worker generated an exception: {exc}", exc_info=True)
            else: # Source Tenant Delete
                logger.info("--- Start Delete in Source Tenant ---")
                # Pass empty kids dict and main thread name for source tenant run
                delete_ioas(falcon_ioa_source, ids, summary_tracker, None, {}, main_thread_name)
            logger.info("--- Delete Complete ---")

    # --- Final Summary ---
    summary_tracker.print_summary() # Keep print for final summary
    end_time = time.time()
    # Keep print for final timing
    print(f"\nScript finished in {Color.BOLD}{end_time - start_time:.2f}{Color.END} seconds.")
    deinitialize_colors()

