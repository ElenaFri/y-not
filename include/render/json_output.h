#pragma once

#include "access.h"

/* Renders result as a JSON object (schema_version 1) to stdout. Unlike
   render_result_text(), this never partially fails: even when path
   resolution failed upstream (result->access_path == NULL), this still
   emits a valid document with an empty "trace" array, so scripts consuming
   --json output never have to handle a mixed JSON/plain-text error format.
   `requested_path` is used as a fallback for the "path" field when
   result->access_path is NULL. */
void render_result_json(const AccessResult *result, const char *username,
                        AccessOperation op, const char *requested_path);

/* user_lookup() failure never reaches check_access(); this keeps --json's
   output contract valid for that case too. */
void render_user_not_found_json(const char *username, AccessOperation op,
                                const char *requested_path);
