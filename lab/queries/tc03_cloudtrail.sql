-- TC-03: one view of user, role and tool for a test call (CloudTrail Lake).
-- Replace <event_data_store_id> with your event data store ID.
SELECT
    eventTime,
    userIdentity.arn                      AS role_session,
    userIdentity.sessionContext.sourceIdentity AS source_user,
    eventName,
    requestParameters,
    errorCode
FROM <event_data_store_id>
WHERE eventTime > date_add('hour', -2, now())
  AND userIdentity.arn LIKE '%mcp-tool-%'
ORDER BY eventTime DESC;
-- Expected: each tool's role session carries the user as sourceIdentity
-- (set with sts:SetSourceIdentity when the agent assumes the per-tool role).
