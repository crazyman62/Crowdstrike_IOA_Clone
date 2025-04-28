# ioa_replication.py
# Contains logic for replicating/updating IOA rules

import json
import time
import logging

# Import necessary components from utils
from ioa_utils import (
    Color,
    get_target_group_details
)

# Get a logger instance for this module
logger = logging.getLogger(__name__)

# --- Main Replicate/Update Function ---
def replicate_or_update_rules_to_target(
    target_ioa_api: object,
    source_ioa_rules: dict,
    target_cid: str,
    target_group_name: str,
    summary_tracker: object,
    specific_rule_name: str = None,
    kids_details: dict = None,
    thread_name: str = "MainThread" # Accept thread name
    ):
    """
    Replicates or Updates rules from source groups into a single pre-existing target group
    using the provided target_ioa_api SDK instance. Uses logging for output.
    Updates the provided summary_tracker object.
    Returns a dictionary with summary counts for this specific CID run.
    """
    if kids_details is None: kids_details = {} # Ensure it's a dict

    cid_summary = {
        "processed": 0, "created": 0, "updated": 0, "enabled_after_create": 0, "enable_failed": 0,
        "skipped_missing_data": 0, "failed_creation": 0, "failed_update": 0,
        "errors": [], "target_group_id": None, "target_group_name": target_group_name
    }

    if not target_ioa_api:
        target_desc = f"CID {target_cid}" if target_cid else "Source Tenant"
        logger.error(f"Invalid SDK provided for target {target_desc}. Skipping replication.")
        cid_summary["errors"].append("Invalid SDK provided")
        # Pass kids/thread to summary update even on failure
        summary_tracker.update_cid_summary(target_cid, cid_summary, kids_details, thread_name)
        return cid_summary

    source_resources = source_ioa_rules.get("body", {}).get("resources", [])
    if not isinstance(source_resources, list) or not source_resources:
        target_desc = f"CID {target_cid}" if target_cid else "Source Tenant"
        logger.warning(f"No valid source rule groups provided to process for {target_desc}.")
        cid_summary["errors"].append("No valid source rule groups provided.")
        summary_tracker.update_cid_summary(target_cid, cid_summary, kids_details, thread_name)
        return cid_summary

    action = "Update" if specific_rule_name else "Replicate/Update"
    target_desc = f"CID {target_cid}" if target_cid else "Source Tenant" # Keep plain for logs
    logger.info(f"Attempting to {action} rules into target group '{target_group_name}' in {target_desc}...")
    if specific_rule_name: logger.info(f"Targeting specific rule: '{specific_rule_name}' for {target_desc}")

    # --- Find the PRE-EXISTING Target Group ---
    target_group_id = None
    target_group_version = None # Track the current version for updates
    try:
        safe_group_name = target_group_name.replace("'", "\\'")
        fql_filter = f"name:'{safe_group_name}'"
        logger.info(f"Finding target group using filter: {fql_filter}...")
        existing_group_check = target_ioa_api.query_rule_groups_full(filter=fql_filter, limit=2)
        status_code_find = existing_group_check.get("status_code", 500); body_find = existing_group_check.get("body", {})
        if status_code_find // 100 == 2:
            existing_details_list = body_find.get("resources", [])
            if existing_details_list:
                if len(existing_details_list) > 1: logger.warning(f"Found multiple groups named '{target_group_name}' in {target_desc}. Using first ID: {existing_details_list[0].get('id')}.")
                initial_target_group_details = existing_details_list[0]
                target_group_id = initial_target_group_details.get("id")
                target_group_version = initial_target_group_details.get("version")
                cid_summary["target_group_id"] = target_group_id
                if not target_group_id or target_group_version is None: raise ValueError(f"Group '{target_group_name}' missing ID/Version.")
                logger.info(f"Found target group ID: {target_group_id} (Initial Version: {target_group_version}) in {target_desc}.")
            else:
                logger.error(f"Target group '{target_group_name}' not found in {target_desc}. Rules cannot be processed.")
                # *** FIX: Pass thread_name to summary update ***
                cid_summary["errors"].append(f"Target group '{target_group_name}' not found."); summary_tracker.update_cid_summary(target_cid, cid_summary, kids_details, thread_name); return cid_summary
        else:
            err_msg = "Unknown API error";
            if body_find.get("errors"): err_msg = body_find["errors"][0].get("message", err_msg)
            logger.error(f"Failed query for target group '{target_group_name}' in {target_desc}. Status: {status_code_find}. Error: {err_msg}")
            # *** FIX: Pass thread_name to summary update ***
            cid_summary["errors"].append(f"API Error finding target group: {err_msg}"); summary_tracker.update_cid_summary(target_cid, cid_summary, kids_details, thread_name); return cid_summary
    except Exception as e:
        logger.error(f"Error finding target group '{target_group_name}' in {target_desc}: {e}", exc_info=True);
        # *** FIX: Pass thread_name to summary update ***
        cid_summary["errors"].append(f"Exception finding target group: {e}"); summary_tracker.update_cid_summary(target_cid, cid_summary, kids_details, thread_name); return cid_summary

    # --- Get Existing Rules in Target Group ---
    existing_target_rules = {} # Map: normalized_name -> rule_details
    all_rules_in_cid = []
    try:
        logger.info(f"Querying ALL rules in {target_desc} to filter locally...")
        offset = None; limit = 500; all_rule_ids = []
        while True:
            params = {"limit": limit};
            if offset: params["offset"] = offset
            query_rules_resp = target_ioa_api.query_rules(**params)
            query_status = query_rules_resp.get("status_code", 500); query_body = query_rules_resp.get("body", {})
            if query_status // 100 == 2:
                rule_ids = query_body.get("resources", []);
                if not rule_ids: break
                all_rule_ids.extend(rule_ids)
                meta = query_body.get("meta", {}).get("pagination", {}); total = meta.get("total"); current_offset = meta.get("offset", offset or 0)
                if total is not None and len(all_rule_ids) >= total: break
                if len(rule_ids) < limit: break
                offset = current_offset + limit
            else:
                 err_msg = "Unknown";
                 if query_body.get("errors"): err_msg = query_body["errors"][0].get("message", err_msg)
                 logger.warning(f"Failed query ALL rules in {target_desc}. Status: {query_status}. Err: {err_msg}. Update check failed."); break
        logger.info(f"Found {len(all_rule_ids)} total rule IDs in {target_desc}. Fetching details...")
        if all_rule_ids:
            chunk_size = 500
            for i in range(0, len(all_rule_ids), chunk_size):
                id_chunk = all_rule_ids[i:i+chunk_size]
                get_rules_resp = target_ioa_api.get_rules(ids=id_chunk)
                get_status = get_rules_resp.get("status_code", 500); get_body = get_rules_resp.get("body", {})
                if get_status // 100 == 2: all_rules_in_cid.extend(get_body.get("resources", []))
                else: logger.warning(f"Failed get details chunk in {target_desc}. Status: {get_status}")
        logger.info(f"Fetched details for {len(all_rules_in_cid)} rules total in {target_desc}.")
        logger.info(f"Filtering for target group ID: {target_group_id}...")
        rules_in_target_group = [rule for rule in all_rules_in_cid if isinstance(rule, dict) and rule.get("rulegroup_id") == target_group_id]
        logger.info(f"Found {len(rules_in_target_group)} rules belonging to the target group in {target_desc}.")
        for rule in rules_in_target_group:
            if rule.get("name"):
                original_name = rule["name"]; normalized_name = original_name.strip().lower()
                if normalized_name in existing_target_rules: logger.warning(f"Duplicate normalized name '{normalized_name}' in {target_desc}. Overwriting.")
                existing_target_rules[normalized_name] = rule
        logger.info(f"Mapped {len(existing_target_rules)} existing rules in target group by normalized name.")
    except Exception as e: logger.error(f"Exception processing existing rules in {target_desc}: {e}", exc_info=True)

    # --- Process Rules from Source ---
    logger.info(f"Processing rules from source for {target_desc}...")
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
                logger.warning(f"Skipping rule (SrcGrp: {source_group_name}): Missing name.")
                cid_summary["skipped_missing_data"] += 1; continue

            normalized_lookup_name = rule_name.strip().lower()
            payload_base = { "description": rule.get("description", ""), "disposition_id": rule.get("disposition_id"),
                             "comment": f"Src Rule ID: {rule.get('instance_id','N/A')} | Src Grp: '{source_group_name}'",
                             "field_values": rule.get("field_values", []), "pattern_severity": rule.get("pattern_severity"),
                             "name": rule_name, "rulegroup_id": target_group_id, "ruletype_id": rule.get("ruletype_id") }

            req_common = ["disposition_id", "field_values", "pattern_severity", "name", "rulegroup_id", "ruletype_id"]
            missing = [f for f in req_common if payload_base.get(f) is None]
            if not isinstance(payload_base.get("field_values"), list): missing.append("field_values (not list)")
            if missing:
                logger.warning(f"Skipping '{rule_name}' in {target_desc}: Missing/Invalid fields: {', '.join(missing)}")
                cid_summary["skipped_missing_data"] += 1; continue

            existing_rule_details = existing_target_rules.get(normalized_lookup_name)

            # --- UPDATE PATH ---
            if existing_rule_details:
                target_id = existing_rule_details.get("instance_id")
                if target_group_version is None: # Refresh group version if needed
                    logger.info(f"Refreshing group {target_group_id} ver for {target_desc}..."); t0=time.time()
                    refreshed = get_target_group_details(target_ioa_api, target_group_id)
                    if not refreshed or refreshed.get("version") is None: logger.error(f"Update '{rule_name}' in {target_desc}. Fail refresh group ver."); cid_summary["failed_update"]+=1; continue
                    target_group_version = int(refreshed.get("version")); logger.info(f"Using group ver: {target_group_version} (Refresh {time.time()-t0:.2f}s)")

                logger.info(f"Update '{rule_name}' (ID: {target_id}) in {target_desc} using group ver {target_group_version} (Src Enabled: {source_rule_enabled})...")
                if not target_id: logger.error(f"Update '{rule_name}' in {target_desc}. Missing 'instance_id'."); cid_summary["failed_update"]+=1; target_group_version=None; continue

                update_payload = { **payload_base, "instance_id": target_id, "rulegroup_version": int(target_group_version),
                                   "enabled": source_rule_enabled, "comment": payload_base["comment"] + " (Updated)" }
                update_payload_clean = {k: v for k, v in update_payload.items() if v is not None}
                update_body = { "comment": f"Update rule '{rule_name}' via script.", "rulegroup_id": target_group_id,
                                "rulegroup_version": int(target_group_version), "rule_updates": [update_payload_clean] }

                req_upd = ["instance_id", "rulegroup_version", "name", "description", "disposition_id", "field_values", "pattern_severity", "enabled"]
                missing_upd = [f for f in req_upd if f not in update_payload_clean]
                if missing_upd: logger.error(f"Update '{rule_name}' in {target_desc}. Missing payload fields: {', '.join(missing_upd)}."); cid_summary["failed_update"]+=1; target_group_version=None; continue

                try:
                    upd_resp = target_ioa_api.update_rules(body=update_body)
                    upd_code = upd_resp.get("status_code", 500); upd_body = upd_resp.get("body", {})
                    if upd_code//100 == 2:
                        logger.info(f"Success update '{rule_name}' in {target_desc}.")
                        cid_summary["updated"] += 1
                        res = upd_body.get("resources", [])
                        if res and isinstance(res[0],dict) and res[0].get("rulegroup_version") is not None:
                           new_ver = int(res[0].get("rulegroup_version"));
                           if target_group_version != new_ver: logger.info(f"Group ver -> {new_ver}"); target_group_version = new_ver
                        else: logger.warning(f"Update OK for '{rule_name}', group ver not in resp."); target_group_version = None
                    else:
                        errs = upd_body.get("errors", [{"message":"Unknown"}]); e_msg = errs[0].get("message","Unknown")
                        logger.error(f"Fail update '{rule_name}' in {target_desc}. Code: {upd_code}, Err: {e_msg}")
                        cid_summary["failed_update"] += 1; target_group_version = None
                except Exception as e_upd: logger.error(f"Ex update '{rule_name}' in {target_desc}: {e_upd}", exc_info=True); cid_summary["failed_update"]+=1; target_group_version=None

            # --- CREATE PATH ---
            else:
                logger.info(f"Create '{rule_name}' in {target_desc} (as disabled)...")
                create_payload = { **payload_base, "enabled": False }; create_payload_clean = {k: v for k, v in create_payload.items() if v is not None}
                try:
                    create_resp = target_ioa_api.create_rule(body=create_payload_clean)
                    create_code = create_resp.get("status_code", 500); create_body = create_resp.get("body", {})
                    if create_code in [200, 201]:
                         res = create_body.get("resources", [])
                         if isinstance(res, list) and res:
                            new_details = res[0]; new_id = new_details.get("instance_id"); new_ver = new_details.get("instance_version"); new_group_ver = new_details.get("rulegroup_version")
                            if new_id is not None and new_ver is not None:
                                logger.info(f"Success create '{rule_name}' (ID: {new_id}) disabled in {target_desc}.")
                                cid_summary["created"] += 1
                                existing_target_rules[normalized_lookup_name] = new_details # Add to cache
                                if new_group_ver is not None: # Update group version cache
                                    new_ver_int = int(new_group_ver)
                                    if target_group_version is None or target_group_version != new_ver_int: logger.info(f"Group ver -> {new_ver_int}")
                                    target_group_version = new_ver_int
                                else: logger.warning(f"Create OK for '{rule_name}', group ver not in resp."); target_group_version = None

                                # Attempt to ENABLE if source was enabled
                                if source_rule_enabled:
                                    logger.info(f"Source enabled. Try enable new rule {new_id} in {target_desc}...")
                                    if target_group_version is None: # Refresh if needed
                                        logger.info(f"Refreshing group {target_group_id} ver..."); t0=time.time()
                                        refreshed_en = get_target_group_details(target_ioa_api, target_group_id)
                                        if not refreshed_en or refreshed_en.get("version") is None: logger.error(f"Enable '{rule_name}'. Fail refresh group ver."); cid_summary["enable_failed"]+=1; continue
                                        target_group_version = int(refreshed_en.get("version")); logger.info(f"Using group ver: {target_group_version} (Refresh {time.time()-t0:.2f}s)")

                                    enable_payload = { "instance_id": new_id, "rulegroup_version": int(target_group_version), "enabled": True,
                                                       "name": rule_name, "description": create_payload_clean["description"], "disposition_id": create_payload_clean["disposition_id"],
                                                       "field_values": create_payload_clean["field_values"], "pattern_severity": create_payload_clean["pattern_severity"] }
                                    enable_body = { "comment": f"Enable rule '{rule_name}' after create.", "rulegroup_id": target_group_id,
                                                    "rulegroup_version": int(target_group_version), "rule_updates": [enable_payload] }
                                    try:
                                        en_resp = target_ioa_api.update_rules(body=enable_body)
                                        en_code = en_resp.get("status_code", 500); en_body = en_resp.get("body", {})
                                        if en_code//100 == 2:
                                            logger.info(f"Success enable '{rule_name}' in {target_desc}.")
                                            cid_summary["enabled_after_create"] += 1
                                            en_res = en_body.get("resources", [])
                                            if en_res and isinstance(en_res[0],dict) and en_res[0].get("rulegroup_version") is not None:
                                                final_ver = int(en_res[0].get("rulegroup_version"))
                                                if target_group_version != final_ver: logger.info(f"Group ver -> {final_ver}"); target_group_version = final_ver
                                            else: logger.warning(f"Enable OK for '{rule_name}', group ver not in resp."); target_group_version = None
                                        else:
                                            errs = en_body.get("errors",[{"message":"Unknown"}]); e_msg=errs[0].get("message","Unknown")
                                            logger.error(f"Fail enable '{rule_name}' in {target_desc}. Code: {en_code}, Err: {e_msg}")
                                            cid_summary["enable_failed"] += 1; target_group_version = None
                                    except Exception as e_en: logger.error(f"Ex enable '{rule_name}' in {target_desc}: {e_en}", exc_info=True); cid_summary["enable_failed"]+=1; target_group_version=None
                                else: logger.info(f"Source disabled. Rule '{rule_name}' remains disabled in {target_desc}.")
                            else: # Failed to get ID/Ver from create response
                                logger.error(f"Fail create '{rule_name}' in {target_desc}: Code OK but no ID/Ver. Body: {json.dumps(create_body)}")
                                cid_summary["failed_creation"] += 1; target_group_version = None
                         else: # Code OK but no resources
                            logger.error(f"Fail create '{rule_name}' in {target_desc}: Code OK ({create_code}) but no resource details. Body: {json.dumps(create_body)}")
                            cid_summary["failed_creation"] += 1; target_group_version = None
                    else: # Create API call failed
                        errs = create_body.get("errors", [{"message":"Unknown"}]); e_msg = errs[0].get("message", "Unknown")
                        logger.error(f"Fail create '{rule_name}' in {target_desc}. Code: {create_code}, Err: {e_msg}")
                        cid_summary["failed_creation"] += 1; target_group_version = None
                except Exception as e_create: logger.error(f"Ex create '{rule_name}' in {target_desc}: {e_create}", exc_info=True); cid_summary["failed_creation"]+=1; target_group_version=None

            # If specific rule processed, break loops
            if specific_rule_name and rule_name == specific_rule_name: logger.info(f"Finished specific rule '{specific_rule_name}'."); break
        if specific_rule_name and 'rule_name' in locals() and rule_name == specific_rule_name: break # Break outer loop too

    # --- End of rule processing for this CID ---
    logger.info(f"--- {action} Summary for {target_desc} (Group: {target_group_name}/{target_group_id}) ---")
    logger.info(f"Rules Processed:              {rules_processed_in_cid}")
    logger.info(f"Created (as disabled):      {cid_summary['created']}")
    logger.info(f"Enabled (after create):     {cid_summary['enabled_after_create']}")
    logger.info(f"Updated:                  {cid_summary['updated']}")
    logger.info(f"Skipped (Missing Data):     {cid_summary['skipped_missing_data']}")
    logger.info(f"Failed Creation:          {cid_summary['failed_creation']}")
    logger.info(f"Failed Update:            {cid_summary['failed_update']}")
    logger.info(f"Failed Enable:            {cid_summary['enable_failed']}")
    if cid_summary['errors']: logger.error(f"CID-Level Errors for {target_desc}: {cid_summary['errors']}")
    logger.info("---------------------------------------------------------")

    # Update the main summary tracker before returning
    # *** FIX: Pass thread_name to summary update ***
    summary_tracker.update_cid_summary(target_cid, cid_summary, kids_details or {}, thread_name)
    return cid_summary # Return per-CID summary

