# ioa_deletion.py
# Contains logic for deleting IOA rule groups

import json
import logging

# Import necessary components from utils
from ioa_utils import Color # Keep Color for potential inline formatting if needed later

# Get a logger instance for this module
logger = logging.getLogger(__name__)

def delete_ioas(
    sdk: object, # Pass initialized SDK
    ids_to_delete: str,
    summary_tracker: object, # Pass summary tracker instance
    target_cid: str = None, # Add target_cid for summary tracking
    kids_details: dict = None, # Pass kids details for name lookup in summary
    thread_name: str = "MainThread" # Accept thread name
    ):
    """
    Deletes specified IOA rule groups using the provided SDK. Uses logging.
    Updates the provided summary_tracker object.
    Returns a dictionary with deletion summary counts.
    """
    if kids_details is None:
        kids_details = {} # Ensure it's a dict even if not passed

    if not sdk:
         logger.error("SDK object not provided to delete_ioas.")
         delete_summary = {"deleted_count": 0, "failed_count": 0, "errors": [{"message": "SDK not provided"}]}
         # Pass kids/thread to summary update even on failure
         summary_tracker.update_delete_summary(target_cid, delete_summary, kids_details, thread_name)
         return delete_summary # Cannot proceed

    delete_summary = {"deleted_count": 0, "failed_count": 0, "errors": []}
    id_list = [i.strip() for i in ids_to_delete.split(",") if i.strip()]
    if not id_list:
        logger.warning("No valid rule group IDs provided for deletion.")
        delete_summary["errors"].append({"message": "No valid IDs provided for deletion"})
        # Pass kids/thread to summary update
        summary_tracker.update_delete_summary(target_cid, delete_summary, kids_details, thread_name)
        return delete_summary # Return immediately

    target_desc = f"CID {target_cid}" if target_cid else "Source Tenant"
    logger.info(f"Attempting to delete {len(id_list)} rule group(s) in {target_desc}: {', '.join(id_list)}")
    try:
        # Add comment for audit log
        res = sdk.delete_rule_groups(ids=id_list, comment="Deleting rule groups via script.")
        code = res.get("status_code"); body = res.get("body", {}); errs = body.get("errors", []); meta = body.get("meta", {})
        del_meta = meta.get("deleted_count", None); fail_meta = meta.get("failed_count", None)

        if code is not None and code//100 == 2:
            # Use meta counts if available for accuracy
            if del_meta is not None:
                 delete_summary["deleted_count"] = del_meta
                 delete_summary["failed_count"] = fail_meta if fail_meta is not None else (len(id_list) - del_meta)
            else: # Fallback: Infer from errors list
                fail_ids = set(e.get('id') for e in errs if e.get('id'))
                delete_summary["failed_count"] = len(fail_ids)
                delete_summary["deleted_count"] = len(id_list) - len(fail_ids)

            if delete_summary["failed_count"] > 0:
                logger.warning(f"Deletion request partially successful for {target_desc}.")
                logger.info(f"  Successfully deleted: {delete_summary['deleted_count']}")
                logger.warning(f"  Failed to delete: {delete_summary['failed_count']}")
                if errs:
                    logger.error(f"  Reported Deletion Errors for {target_desc}:")
                    for error in errs: logger.error(f"    - ID:{error.get('id','N/A')}, Code:{error.get('code','N/A')}, Msg:{error.get('message','Unknown')}")
                    delete_summary["errors"] = errs # Store errors in summary
            else:
                 logger.info(f"Successfully requested deletion for all {delete_summary['deleted_count']} group(s) in {target_desc}.")
        else: # Status code indicates failure
            logger.error(f"Error during deletion request for {target_desc}. Status: {code or 'N/A'}")
            delete_summary["failed_count"] = len(id_list); delete_summary["deleted_count"] = 0
            if errs:
                logger.error(f"Deletion Errors Reported for {target_desc}:")
                for error in errs: logger.error(f"  Code:{error.get('code','N/A')}, Msg:{error.get('message','Unknown')}, ID:{error.get('id','')}")
                delete_summary["errors"] = errs
            else:
                 e_msg = f"Delete API failed code {code}"
                 logger.error(f"  {e_msg}")
                 delete_summary["errors"].append({"message": e_msg, "status_code": code})
    except Exception as e:
        logger.error(f"Exception calling delete_rule_groups API for {target_desc}: {e}", exc_info=True)
        delete_summary["failed_count"]=len(id_list); delete_summary["deleted_count"]=0
        delete_summary["errors"].append({"message":f"Exception during delete: {e}"})

    # Update the main summary tracker
    summary_tracker.update_delete_summary(target_cid, delete_summary, kids_details, thread_name)
    return delete_summary # Return summary for this specific deletion run
