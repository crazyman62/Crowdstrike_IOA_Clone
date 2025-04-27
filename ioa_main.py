# ioa_main.py
# Main script to orchestrate IOA rule management tasks

import sys
import time
from argparse import ArgumentParser, RawTextHelpFormatter, Action

# Import components from other modules
from ioa_utils import (
    Color, initialize_colors, deinitialize_colors, ExecutionSummary,
    open_sdk, open_mssp, get_ioa_list, display_ioas,
    get_child_cid_details, display_child_cids
)
from ioa_replication import replicate_or_update_rules_to_target
from ioa_deletion import delete_ioas

# --- Argument Parser Action for Mutually Exclusive Groups ---
# (Keep this class in main as it's part of arg parsing setup)
class MutuallyExclusiveAction(Action):
    """Custom argparse action for mutually exclusive flags."""
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
    """Consume and validate command-line arguments."""
    parser = ArgumentParser(description="Manage CrowdStrike Custom IOA Rules between tenants.", formatter_class=RawTextHelpFormatter)
    parser.add_argument("-n", "--nocolor", help="Force disable color output", action="store_true", default=False)
    parser.add_argument("-b", "--base_url", help="CrowdStrike API Base URL (e.g., 'us-1'). Default: 'auto'", default="auto")
    parser.add_argument("-t", "--table_format", help="Tabular display format. Default: 'fancy_grid'", default="fancy_grid")
    filter_group = parser.add_argument_group("source filters (for --list_parent_ioas, --replicate_rules)")
    filter_exclusive_group = filter_group.add_mutually_exclusive_group()
    filter_exclusive_group.add_argument("-f", "--filter", help="Filter SOURCE rule groups by name.", default=None)
    filter_exclusive_group.add_argument("--rule_name", help="Filter for a SINGLE rule name (used with --replicate_rules).", default=None)
    action_group = parser.add_argument_group("actions (choose one)")
    action_group.add_argument("--list_cids", help="List accessible child CIDs.", action=MutuallyExclusiveAction, dest='list_cids', default=False)
    action_group.add_argument("--list_parent_ioas", help="List parent tenant IOA groups.", action=MutuallyExclusiveAction, dest='list_parent_ioas', default=False)
    action_group.add_argument("-r", "--replicate_rules", help="Replicate/Update rules into a target group.", action=MutuallyExclusiveAction, dest='replicate_rules', default=False)
    action_group.add_argument("--replicate_all_parent_rules", help="Replicate/Update rules from ALL source groups.", action=MutuallyExclusiveAction, dest='replicate_all_parent_rules', default=False)
    action_group.add_argument("-d", "--delete_group", help="Delete rule group IDs in target(s).", action=MutuallyExclusiveAction, dest='delete_group', default=False)
    action_group.add_argument("--delete_ids", help="Rule group IDs to delete (required for --delete_group).", default=None)
    mod_group = parser.add_argument_group("action modifiers")
    mod_group.add_argument("--target_group_name", help="PRE-EXISTING target rule group name (Required for replication).", default=None)
    mssp_group = parser.add_argument_group("mssp arguments (target specification)")
    mssp_target_group = mssp_group.add_mutually_exclusive_group()
    mssp_target_group.add_argument("-m", "--managed_targets", help="Comma-separated list of target child CIDs.", default=None)
    mssp_target_group.add_argument("--all_cids", help="Target ALL accessible child CIDs.", action="store_true", default=False)
    req = parser.add_argument_group("required arguments")
    req.add_argument("-k", "--falcon_client_id", help="CrowdStrike Falcon API Client ID", required=True)
    req.add_argument("-s", "--falcon_client_secret", help="CrowdStrike Falcon API Client Secret", required=True)
    args = parser.parse_args()
    # Initialize flags safely
    args.list_cids = getattr(args, 'list_cids', False); args.list_parent_ioas = getattr(args, 'list_parent_ioas', False)
    args.replicate_rules = getattr(args, 'replicate_rules', False); args.replicate_all_parent_rules = getattr(args, 'replicate_all_parent_rules', False)
    args.delete_group = getattr(args, 'delete_group', False)
    # Validation
    if args.replicate_rules and not (args.filter or args.rule_name): parser.error("-f/--filter OR --rule_name required with --replicate_rules.")
    if args.replicate_all_parent_rules and args.rule_name: parser.error("--rule_name cannot be used with --replicate_all_parent_rules.")
    if (args.replicate_rules or args.replicate_all_parent_rules) and not args.target_group_name: parser.error("--target_group_name required for replication.")
    if args.delete_group and not args.delete_ids: parser.error("--delete_ids required with --delete_group.")
    if not any([args.list_cids, args.list_parent_ioas, args.replicate_rules, args.replicate_all_parent_rules, args.delete_group]): parser.error("No action specified.")
    return args

# --- Main Execution Block ---
if __name__ == "__main__":
    start_time = time.time()
    args = consume_arguments()

    # Initialize color handling and summary tracker
    initialize_colors(args.nocolor)
    summary_tracker = ExecutionSummary()

    print(f"{Color.BOLD}Starting IOA Rule Management Script...{Color.END}")

    # --- SDK Init (Source) ---
    print(f"\n{Color.UNDERLINE}Connecting to Source Tenant{Color.END}")
    # Exit if source SDK fails
    falcon_ioa_source = open_sdk(args.falcon_client_id, args.falcon_client_secret, args.base_url, "CustomIOA")
    if not falcon_ioa_source:
        print(f"{Color.RED}Fatal Error: Could not initialize SDK for source tenant. Exiting.{Color.END}")
        sys.exit(1)
    print(f"{Color.GREEN}Source SDK initialized.{Color.END}")

    # --- Actions ---
    # Listing actions exit after completion
    if args.list_parent_ioas:
        print(f"\n{Color.BOLD}--- Listing Parent IOA Groups ---{Color.END}")
        parent_ioas = get_ioa_list(falcon_ioa_source, args.filter)
        display_ioas(parent_ioas, args.table_format)
        print(f"\n{Color.BOLD}--- Listing Complete ---{Color.END}")
        deinitialize_colors()
        sys.exit(0)

    if args.list_cids:
        print(f"\n{Color.BOLD}--- Listing Child CIDs ---{Color.END}")
        mssp_sdk = open_mssp(args.falcon_client_id, args.falcon_client_secret, args.base_url)
        # Exit if mssp_sdk failed (already handled in open_mssp)
        details = get_child_cid_details(mssp_sdk)
        display_child_cids(details, args.table_format)
        print(f"\n{Color.BOLD}--- Listing Complete ---{Color.END}")
        deinitialize_colors()
        sys.exit(0)

    # --- Get Source Rules (if replicating) ---
    source_data = {"body": {"resources": []}, "status_code": 0, "errors": None}
    if args.replicate_rules or args.replicate_all_parent_rules:
        f_str = args.filter
        print(f"\n{Color.UNDERLINE}Retrieving Source IOA Rule Groups{Color.END}")
        print(f"Filter: {'All Groups' if not f_str else f'Group name contains *{f_str}*'}")
        source_data = get_ioa_list(falcon_ioa_source, f_str)
        if source_data.get("status_code", 500)//100 != 2:
            print(f"{Color.RED}Fatal Err: Cannot get source groups. Exit.{Color.END}")
            if source_data.get("errors"): [print(f"  - {e.get('message')}") for e in source_data["errors"]]
            deinitialize_colors(); sys.exit(1)
        count = len(source_data.get("body",{}).get("resources",[]))
        print(f"Found {count} source groups.")
        if count == 0:
            print(f"{Color.YELLOW}Warn: No source groups match. No rules replicated/updated.{Color.END}")
            if args.rule_name: print(f"{Color.YELLOW}  Check group filter ('{f_str}') for rule '{args.rule_name}'.{Color.END}")

    # --- MSSP Child Handling ---
    DO_MSSP = False; kids = {}; targets = []
    if args.managed_targets or args.all_cids:
        print(f"\n{Color.UNDERLINE}MSSP Target Handling{Color.END}")
        mssp_sdk = open_mssp(args.falcon_client_id, args.falcon_client_secret, args.base_url)
        # Exit if mssp_sdk failed (already handled in open_mssp)
        kids = get_child_cid_details(mssp_sdk)
        if not kids: print(f"{Color.YELLOW}No accessible child CIDs found. No MSSP actions.{Color.END}")
        elif args.all_cids: targets = sorted(list(kids.keys())); print(f"Target all {Color.BOLD}{len(targets)}{Color.END} children."); DO_MSSP = bool(targets)
        elif args.managed_targets:
            user_tgts = [c.strip() for c in args.managed_targets.split(",") if c.strip()]
            print(f"Validating {len(user_tgts)} specified target CID(s)...")
            valid = []; invalid = []; norm_user = {t.split('-')[0].lower(): t for t in user_tgts}
            norm_kids = {c.split('-')[0].lower(): (c,n) for c,n in kids.items()}; valid_map = {}
            for norm_u, orig_u in norm_user.items():
                if norm_u in norm_kids: actual_c, name = norm_kids[norm_u]; valid_map[norm_u]=actual_c; print(f"  - {Color.GREEN}OK:{Color.END} {actual_c} ({name})")
                else: invalid.append(orig_u); print(f"  - {Color.RED}Not Found:{Color.END} {orig_u}")
            targets = sorted([valid_map[n] for n in valid_map])
            if targets: DO_MSSP = True; print(f"{Color.GREEN}Proceed with {len(targets)} valid target CIDs.{Color.END}")
            if invalid: print(f"{Color.YELLOW}Warn: Invalid/Inaccessible CIDs: {', '.join(invalid)}{Color.END}")
            if not DO_MSSP: print(f"{Color.YELLOW}Warn: No valid CIDs specified. No MSSP actions.{Color.END}")

    # --- Action Execution ---
    # Replicate/Update
    if args.replicate_rules or args.replicate_all_parent_rules:
        verb = "Replicate/Update Rules"; src_groups = source_data.get("body",{}).get("resources",[])
        skip = False
        if not (args.replicate_rules or args.replicate_all_parent_rules): skip=True # Should not happen
        elif not args.target_group_name: print(f"\n{Color.RED}Skip {verb}: --target_group_name required.{Color.END}"); skip=True
        elif not src_groups and not args.rule_name: print(f"\n{Color.YELLOW}Skip {verb}: No source groups match.{Color.END}"); skip=True
        elif (args.managed_targets or args.all_cids) and not DO_MSSP: print(f"\n{Color.YELLOW}Skip MSSP {verb}: No valid CIDs.{Color.END}"); skip=True

        if not skip:
            if DO_MSSP:
                print(f"\n{Color.BOLD}--- Start {verb} on {len(targets)} Child Tenant(s) ---{Color.END}")
                for i, cid in enumerate(targets):
                    name = f" ({kids.get(cid,'?')})" if kids else ""
                    print(f"\n===== Process CID {i+1}/{len(targets)}: {Color.DARKCYAN}{cid}{Color.END}{name} =====")
                    # Pass args, source data, cid, target name, tracker, specific rule name
                    replicate_or_update_rules_to_target(
                        args, source_data, cid, args.target_group_name, summary_tracker, args.rule_name
                    )
                    print(f"===== Finish CID: {Color.DARKCYAN}{cid}{Color.END} =====")
            else: # Source Tenant
                print(f"\n{Color.BOLD}--- Start {verb} within {Color.MAGENTA}Source Tenant{Color.END} ---{Color.END}")
                print(f"{Color.YELLOW}Warn: Target is Source Tenant. Rules -> Group '{Color.CYAN}{args.target_group_name}{Color.END}'.{Color.END}")
                # Pass None for target_cid
                replicate_or_update_rules_to_target(
                    args, source_data, None, args.target_group_name, summary_tracker, args.rule_name
                )
            print(f"{Color.BOLD}--- {verb} Complete ---{Color.END}")

    # Delete
    if args.delete_group:
        ids = args.delete_ids.strip() if args.delete_ids else None; skip = False
        if not ids: print(f"\n{Color.YELLOW}Skip Delete: No IDs via --delete_ids.{Color.END}"); skip=True
        elif (args.managed_targets or args.all_cids) and not DO_MSSP: print(f"\n{Color.YELLOW}Skip MSSP Delete: No valid CIDs.{Color.END}"); skip=True

        if not skip:
            if DO_MSSP:
                print(f"\n{Color.BOLD}--- Start Delete in {len(targets)} Child Tenant(s) ---{Color.END}")
                print(f"{Color.YELLOW}Note: Attempt delete Group IDs [{ids}] in ALL targets.{Color.END}")
                for i, cid in enumerate(targets):
                    name = f" ({kids.get(cid,'?')})" if kids else ""
                    print(f"\n===== Delete in CID {i+1}/{len(targets)}: {Color.DARKCYAN}{cid}{Color.END}{name} =====")
                    # Need SDK for target CID
                    target_sdk = open_sdk(args.falcon_client_id, args.falcon_client_secret, args.base_url, "CustomIOA", member_cid=cid)
                    if target_sdk:
                        # Pass args, target_sdk, ids, tracker, cid
                        delete_ioas(args, target_sdk, ids, summary_tracker, cid)
                    else:
                        # SDK failed, update summary directly
                        print(f"{Color.RED}Error: Cannot perform delete in CID {cid} due to SDK init failure.{Color.END}")
                        summary_tracker.update_delete_summary(cid, {"failed_count":len(ids.split(',')), "errors":[{"message":"SDK init failed"}]})
                    print(f"===== Finish Delete CID: {Color.DARKCYAN}{cid}{Color.END} =====")
            else: # Source Tenant Delete
                print(f"\n{Color.BOLD}--- Start Delete in {Color.MAGENTA}Source Tenant{Color.END} ---{Color.END}")
                # Pass args, source_sdk, ids, tracker, None for cid
                delete_ioas(args, falcon_ioa_source, ids, summary_tracker, None)
            print(f"{Color.BOLD}--- Delete Complete ---{Color.END}")

    # --- Final Summary ---
    summary_tracker.print_summary()
    end_time = time.time()
    print(f"\nScript finished in {Color.BOLD}{end_time - start_time:.2f}{Color.END} seconds.")
    # Deinitialize colorama only if it was initialized
    deinitialize_colors()

