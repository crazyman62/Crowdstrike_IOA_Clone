# ioa_replication.py
# Contains logic for replicating/updating IOA rules

import json
import time

# Import necessary components from utils
from ioa_utils import (
    Color, open_sdk, get_target_group_details
)

# --- Main Replicate/Update Function ---
def replicate_or_update_rules_to_target(
    args: object, # Pass argparse namespace
    source_ioa_rules: dict,
    target_cid: str,
    target_group_name: str,
    summary_tracker: object, # Pass summary tracker instance
    specific_rule_name: str = None
    ):
    """
    Replicates or Updates rules from source groups into a single pre-existing target group.
    Fetches ALL rules in the target CID, then filters locally by rulegroup_id.
    Creates new rules as disabled, then enables them if the source was enabled.
    Updates existing rules directly. Handles name normalization (case, whitespace).
    Updates the provided summary_tracker object.
    Returns a dictionary with summary counts for this specific CID run.
    """
    target_ioa_api = None
    # Initialize summary dict for this specific CID run (returned for potential use)
    cid_summary = {
        "processed": 0, "created": 0, "updated": 0, "enabled_after_create": 0, "enable_failed": 0,
        "skipped_missing_data": 0, "failed_creation": 0, "failed_update": 0,
        "errors": [], "target_group_id": None, "target_group_name": target_group_name
    }

    # Open SDK for the target CID (or source if target_cid is None)
    try:
        target_ioa_api = open_sdk(args.falcon_client_id, args.falcon_client_secret, args.base_url, "CustomIOA", member_cid=target_cid)
        if not target_ioa_api: raise Exception("SDK Initialization returned None")
    except Exception as e:
        target_desc = f"CID {target_cid}" if target_cid else "Source Tenant"
        print(f"{Color.RED}Error: Could not initialize SDK for target {target_desc}. Skipping... Error: {e}{Color.END}")
        cid_summary["errors"].append(f"Failed to initialize SDK: {e}")
        summary_tracker.update_cid_summary(target_cid, cid_summary) # Update tracker even on failure
        return cid_summary # Return summary indicating failure for this CID

    source_resources = source_ioa_rules.get("body", {}).get("resources", [])
    if not isinstance(source_resources, list) or not source_resources:
        target_desc = f"CID {target_cid}" if target_cid else "Source Tenant"
        print(f"{Color.YELLOW}Warning: No valid source rule groups provided to process for {target_desc}.{Color.END}")
        cid_summary["errors"].append("No valid source rule groups provided.")
        summary_tracker.update_cid_summary(target_cid, cid_summary)
        return cid_summary

    action = "Update" if specific_rule_name else "Replicate/Update"
    target_desc = f"CID {Color.DARKCYAN}{target_cid}{Color.END}" if target_cid else f"{Color.MAGENTA}Source Tenant{Color.END}"
    print(f"Attempting to {action} rules into target group '{Color.CYAN}{target_group_name}{Color.END}' in {target_desc}...")
    if specific_rule_name:
        print(f"  Targeting specific rule: '{Color.LIGHTBLUE}{specific_rule_name}{Color.END}'")

    # --- Find the PRE-EXISTING Target Group ---
    target_group_id = None
    target_group_version = None # Track the current version for updates
    try:
        safe_group_name = target_group_name.replace("'", "\\'")
        fql_filter = f"name:'{safe_group_name}'"
        print(f"  Finding target group using filter: {fql_filter}...")
        existing_group_check = target_ioa_api.query_rule_groups_full(filter=fql_filter, limit=2) # Limit 2 to detect duplicates
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
                cid_summary["target_group_id"] = target_group_id # Store in summary
                if not target_group_id or target_group_version is None:
                     raise ValueError(f"Found group '{target_group_name}' but ID or version is missing.")
                print(f"  {Color.GREEN}Found target group ID: {target_group_id} (Initial Version: {target_group_version}).{Color.END}")
            else:
                print(f"  {Color.RED}Error: Target group '{target_group_name}' not found in {target_desc}. Rules cannot be processed.{Color.END}")
                cid_summary["errors"].append(f"Target group '{target_group_name}' not found.")
                summary_tracker.update_cid_summary(target_cid, cid_summary)
                return cid_summary
        else:
            err_msg = "Unknown API error"
            if body_find.get("errors"): err_msg = body_find["errors"][0].get("message", err_msg)
            print(f"  {Color.RED}Warning: Failed query for target group '{target_group_name}'. Status: {status_code_find}. Error: {err_msg}{Color.END}")
            cid_summary["errors"].append(f"API Error finding target group: {err_msg}")
            summary_tracker.update_cid_summary(target_cid, cid_summary)
            return cid_summary
    except Exception as e:
        print(f"  {Color.RED}Error finding target group '{target_group_name}': {e}.{Color.END}");
        cid_summary["errors"].append(f"Exception finding target group: {e}")
        summary_tracker.update_cid_summary(target_cid, cid_summary)
        return cid_summary

    # --- Get Existing Rules in Target Group (Name -> Details Mapping) ---
    # Query ALL rules, then filter locally
    existing_target_rules = {} # Map: normalized_name -> rule_details
    all_rules_in_cid = []
    try:
        print(f"  Querying ALL rules in target {target_desc} to filter locally...")
        offset = None; limit = 500
        all_rule_ids = []
        while True:
            params = {"limit": limit} # No filter here
            if offset: params["offset"] = offset
            query_rules_resp = target_ioa_api.query_rules(**params)
            query_status = query_rules_resp.get("status_code", 500)
            query_body = query_rules_resp.get("body", {})

            if query_status // 100 == 2:
                rule_ids = query_body.get("resources", [])
                if not rule_ids: break
                all_rule_ids.extend(rule_ids)
                # Pagination
                meta = query_body.get("meta", {}).get("pagination", {})
                total = meta.get("total"); current_offset = meta.get("offset", offset or 0)
                if total is not None and len(all_rule_ids) >= total: break
                if len(rule_ids) < limit: break
                offset = current_offset + limit
            else:
                 err_msg = "Unknown";
                 if query_body.get("errors"): err_msg = query_body["errors"][0].get("message", err_msg)
                 print(f"  {Color.YELLOW}Warning: Failed query ALL rules. Status: {query_status}. Err: {err_msg}. Update check failed.{Color.END}"); break
        # --- End of query_rules loop ---

        print(f"  Found {len(all_rule_ids)} total rule IDs. Fetching details...")
        if all_rule_ids:
            chunk_size = 500
            for i in range(0, len(all_rule_ids), chunk_size):
                id_chunk = all_rule_ids[i:i+chunk_size]
                get_rules_resp = target_ioa_api.get_rules(ids=id_chunk)
                get_status = get_rules_resp.get("status_code", 500)
                get_body = get_rules_resp.get("body", {})
                if get_status // 100 == 2: all_rules_in_cid.extend(get_body.get("resources", []))
                else: print(f"    {Color.YELLOW}Warning: Failed get details for rule ID chunk. Status: {get_status}{Color.END}")
        print(f"  Fetched details for {len(all_rules_in_cid)} rules total.")

        # --- Filter locally for the target group ---
        print(f"  Filtering for target group ID: {target_group_id}...")
        rules_in_target_group = [rule for rule in all_rules_in_cid if isinstance(rule, dict) and rule.get("rulegroup_id") == target_group_id]
        print(f"  Found {len(rules_in_target_group)} rules belonging to the target group.")

        # Populate map with normalized names from the filtered list
        for rule in rules_in_target_group:
            if rule.get("name"):
                original_name = rule["name"]; normalized_name = original_name.strip().lower()
                if normalized_name in existing_target_rules: print(f"    {Color.YELLOW}Warning: Duplicate normalized name '{normalized_name}'. Overwriting.{Color.END}")
                existing_target_rules[normalized_name] = rule
        print(f"  Mapped {len(existing_target_rules)} existing rules in target group by normalized name.")

    except Exception as e: print(f"  {Color.RED}Warning: Exception processing existing rules: {e}. Update check incomplete.{Color.END}")
    # --- End of Get Existing Rules ---

    # --- Process Rules from Source ---
    print(f"  Processing rules from source...")
    rules_processed_in_cid = 0
    for source_group in source_resources:
        source_group_name = source_group.get('name', 'Unknown Source Group')
        source_rules = source_group.get("rules", [])
        if not isinstance(source_rules, list) or not source_rules: continue

        for rule in source_rules:
            if not isinstance(rule, dict): continue

            rules_processed_in_cid += 1; cid_summary["processed"] += 1
            rule_name = rule.get("name"); source_rule_enabled = rule.get("enabled", False)
            if specific_rule_name and rule_name != specific_rule_name: continue

            if not rule_name:
                print(f"      {Color.YELLOW}Skipping (SrcGrp: {source_group_name}): Rule missing name.{Color.END}")
                cid_summary["skipped_missing_data"] += 1; continue

            normalized_lookup_name = rule_name.strip().lower()
            # print(f"\n    Processing Source Rule: '{rule_name}' (Normalized: '{normalized_lookup_name}')") # Removed debug

            payload_base = { "description": rule.get("description", ""), "disposition_id": rule.get("disposition_id"),
                             "comment": f"Src Rule ID: {rule.get('instance_id','N/A')} | Src Grp: '{source_group_name}'",
                             "field_values": rule.get("field_values", []), "pattern_severity": rule.get("pattern_severity"),
                             "name": rule_name, "rulegroup_id": target_group_id, "ruletype_id": rule.get("ruletype_id") }

            req_common = ["disposition_id", "field_values", "pattern_severity", "name", "rulegroup_id", "ruletype_id"]
            missing = [f for f in req_common if payload_base.get(f) is None]
            if not isinstance(payload_base.get("field_values"), list): missing.append("field_values (not list)")
            if missing:
                print(f"      {Color.YELLOW}Skipping '{rule_name}': Missing/Invalid fields: {', '.join(missing)}{Color.END}")
                cid_summary["skipped_missing_data"] += 1; continue

            existing_rule_details = existing_target_rules.get(normalized_lookup_name)
            # print(f"      DEBUG: Lookup key '{normalized_lookup_name}'. Found: {'Yes' if existing_rule_details else 'No'}") # Removed debug

            # --- UPDATE PATH ---
            if existing_rule_details:
                # print(f"      Rule exists. UPDATE path...") # Removed debug
                target_id = existing_rule_details.get("instance_id")
                if target_group_version is None: # Refresh group version if needed
                    print(f"        Refreshing group {target_group_id} ver..."); t0=time.time()
                    refreshed = get_target_group_details(target_ioa_api, target_group_id)
                    if not refreshed or refreshed.get("version") is None: print(f"      {Color.RED}Err: Update '{rule_name}'. Fail refresh group ver.{Color.END}"); cid_summary["failed_update"]+=1; continue
                    target_group_version = int(refreshed.get("version")); print(f"        Using group ver: {target_group_version} (Refresh {time.time()-t0:.2f}s)")

                print(f"      Update '{rule_name}' (ID: {target_id}) using group ver {target_group_version} (Src Enabled: {source_rule_enabled})...")
                if not target_id: print(f"      {Color.RED}Err: Update '{rule_name}'. Missing 'instance_id'.{Color.END}"); cid_summary["failed_update"]+=1; target_group_version=None; continue

                update_payload = { **payload_base, "instance_id": target_id, "rulegroup_version": int(target_group_version),
                                   "enabled": source_rule_enabled, "comment": payload_base["comment"] + " (Updated)" }
                update_payload_clean = {k: v for k, v in update_payload.items() if v is not None}
                update_body = { "comment": f"Update rule '{rule_name}' via script.", "rulegroup_id": target_group_id,
                                "rulegroup_version": int(target_group_version), "rule_updates": [update_payload_clean] }

                req_upd = ["instance_id", "rulegroup_version", "name", "description", "disposition_id", "field_values", "pattern_severity", "enabled"]
                missing_upd = [f for f in req_upd if f not in update_payload_clean]
                if missing_upd: print(f"      {Color.RED}Err: Update '{rule_name}'. Missing payload fields: {', '.join(missing_upd)}.{Color.END}"); cid_summary["failed_update"]+=1; target_group_version=None; continue

                try:
                    upd_resp = target_ioa_api.update_rules(body=update_body)
                    upd_code = upd_resp.get("status_code", 500); upd_body = upd_resp.get("body", {})
                    if upd_code//100 == 2:
                        print(f"      {Color.GREEN}Success update '{rule_name}'.{Color.END}"); cid_summary["updated"] += 1
                        res = upd_body.get("resources", [])
                        if res and isinstance(res[0],dict) and res[0].get("rulegroup_version") is not None:
                           new_ver = int(res[0].get("rulegroup_version"));
                           if target_group_version != new_ver: print(f"        Group ver -> {new_ver}"); target_group_version = new_ver
                        else: print(f"       {Color.YELLOW} Update OK, group ver not in resp.{Color.END}"); target_group_version = None # Invalidate cache
                    else:
                        errs = upd_body.get("errors", [{"message":"Unknown"}]); e_msg = errs[0].get("message","Unknown")
                        print(f"      {Color.RED}Fail update '{rule_name}'. Code: {upd_code}, Err: {e_msg}{Color.END}")
                        cid_summary["failed_update"] += 1; target_group_version = None
                except Exception as e_upd: print(f"      {Color.RED}Ex update '{rule_name}': {e_upd}{Color.END}"); cid_summary["failed_update"]+=1; target_group_version=None

            # --- CREATE PATH ---
            else:
                # print(f"      Rule not found. CREATE path...") # Removed debug
                print(f"      Create '{rule_name}' (as disabled)...")
                create_payload = { **payload_base, "enabled": False }; create_payload_clean = {k: v for k, v in create_payload.items() if v is not None}
                try:
                    create_resp = target_ioa_api.create_rule(body=create_payload_clean)
                    create_code = create_resp.get("status_code", 500); create_body = create_resp.get("body", {})
                    if create_code in [200, 201]:
                         res = create_body.get("resources", [])
                         if isinstance(res, list) and res:
                            new_details = res[0]; new_id = new_details.get("instance_id"); new_ver = new_details.get("instance_version"); new_group_ver = new_details.get("rulegroup_version")
                            if new_id is not None and new_ver is not None:
                                print(f"      {Color.GREEN}Success create '{rule_name}' (ID: {new_id}) disabled.{Color.END}"); cid_summary["created"] += 1
                                existing_target_rules[normalized_lookup_name] = new_details # Add to cache
                                if new_group_ver is not None: # Update group version cache
                                    new_ver_int = int(new_group_ver)
                                    if target_group_version is None or target_group_version != new_ver_int: print(f"        Group ver -> {new_ver_int}")
                                    target_group_version = new_ver_int
                                else: print(f"       {Color.YELLOW} Create OK, group ver not in resp.{Color.END}"); target_group_version = None

                                # Attempt to ENABLE if source was enabled
                                if source_rule_enabled:
                                    print(f"        Source enabled. Try enable new rule {new_id}...")
                                    if target_group_version is None: # Refresh if needed
                                        print(f"          Refresh group {target_group_id} ver..."); t0=time.time()
                                        refreshed_en = get_target_group_details(target_ioa_api, target_group_id)
                                        if not refreshed_en or refreshed_en.get("version") is None: print(f"        {Color.RED}Err: Enable '{rule_name}'. Fail refresh group ver.{Color.END}"); cid_summary["enable_failed"]+=1; continue
                                        target_group_version = int(refreshed_en.get("version")); print(f"          Using group ver: {target_group_version} (Refresh {time.time()-t0:.2f}s)")

                                    enable_payload = { "instance_id": new_id, "rulegroup_version": int(target_group_version), "enabled": True,
                                                       "name": rule_name, "description": create_payload_clean["description"], "disposition_id": create_payload_clean["disposition_id"],
                                                       "field_values": create_payload_clean["field_values"], "pattern_severity": create_payload_clean["pattern_severity"] }
                                    enable_body = { "comment": f"Enable rule '{rule_name}' after create.", "rulegroup_id": target_group_id,
                                                    "rulegroup_version": int(target_group_version), "rule_updates": [enable_payload] }
                                    try:
                                        en_resp = target_ioa_api.update_rules(body=enable_body)
                                        en_code = en_resp.get("status_code", 500); en_body = en_resp.get("body", {})
                                        if en_code//100 == 2:
                                            print(f"        {Color.GREEN}Success enable '{rule_name}'.{Color.END}"); cid_summary["enabled_after_create"] += 1
                                            en_res = en_body.get("resources", [])
                                            if en_res and isinstance(en_res[0],dict) and en_res[0].get("rulegroup_version") is not None:
                                                final_ver = int(en_res[0].get("rulegroup_version"))
                                                if target_group_version != final_ver: print(f"          Group ver -> {final_ver}"); target_group_version = final_ver
                                            else: print(f"       {Color.YELLOW} Enable OK, group ver not in resp.{Color.END}"); target_group_version = None
                                        else:
                                            errs = en_body.get("errors",[{"message":"Unknown"}]); e_msg=errs[0].get("message","Unknown")
                                            print(f"        {Color.RED}Fail enable '{rule_name}'. Code: {en_code}, Err: {e_msg}{Color.END}")
                                            cid_summary["enable_failed"] += 1; target_group_version = None
                                    except Exception as e_en: print(f"        {Color.RED}Ex enable '{rule_name}': {e_en}{Color.END}"); cid_summary["enable_failed"]+=1; target_group_version=None
                                else: print(f"        Source disabled. Rule '{rule_name}' remains disabled.{Color.END}")
                            else: # Failed to get ID/Ver from create response
                                print(f"      {Color.RED}Fail create '{rule_name}': Code OK but no ID/Ver.{Color.END}"); print(f"        Body: {json.dumps(create_body, indent=2)}")
                                cid_summary["failed_creation"] += 1; target_group_version = None
                         else: # Code OK but no resources
                            print(f"      {Color.RED}Fail create '{rule_name}': Code OK ({create_code}) but no resource details.{Color.END}"); print(f"        Body: {json.dumps(create_body, indent=2)}")
                            cid_summary["failed_creation"] += 1; target_group_version = None
                    else: # Create API call failed
                        errs = create_body.get("errors", [{"message":"Unknown"}]); e_msg = errs[0].get("message", "Unknown")
                        print(f"      {Color.RED}Fail create '{rule_name}'. Code: {create_code}, Err: {e_msg}{Color.END}")
                        cid_summary["failed_creation"] += 1; target_group_version = None
                except Exception as e_create: print(f"      {Color.RED}Ex create '{rule_name}': {e_create}{Color.END}"); cid_summary["failed_creation"]+=1; target_group_version=None

            # If specific rule processed, break loops
            if specific_rule_name and rule_name == specific_rule_name: print(f"    Finished specific rule '{specific_rule_name}'."); break
        if specific_rule_name and 'rule_name' in locals() and rule_name == specific_rule_name: break # Break outer loop too

    # --- End of rule processing for this CID ---
    print(f"\n--- {action} Summary for {target_desc} (Group: {target_group_name}/{target_group_id}) ---")
    print(f"Rules Processed:              {rules_processed_in_cid}")
    print(f"{Color.GREEN}Created (as disabled):{Color.END}      {cid_summary['created']}")
    print(f"{Color.LIGHTGREEN}Enabled (after create):{Color.END}     {cid_summary['enabled_after_create']}")
    print(f"{Color.CYAN}Updated:{Color.END}                  {cid_summary['updated']}")
    print(f"{Color.YELLOW}Skipped (Missing Data):{Color.END}     {cid_summary['skipped_missing_data']}")
    print(f"{Color.RED}Failed Creation:{Color.END}          {cid_summary['failed_creation']}")
    print(f"{Color.RED}Failed Update:{Color.END}            {cid_summary['failed_update']}")
    print(f"{Color.LIGHTRED}Failed Enable:{Color.END}            {cid_summary['enable_failed']}")
    if cid_summary['errors']: print(f"{Color.RED}CID-Level Errors:{Color.END}"); [print(f"  - {e}") for e in cid_summary['errors']]
    print("---------------------------------------------------------")

    # Update the main summary tracker before returning
    summary_tracker.update_cid_summary(target_cid, cid_summary)
    return cid_summary # Return per-CID summary

