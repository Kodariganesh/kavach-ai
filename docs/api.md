# API

Base URL: `http://localhost:8000`

## Start a mission

`POST /api/v1/mission/start`

```json
{ "repository_url": "https://github.com/owner/repository" }
```

Returns `202 Accepted` immediately while a background worker clones and scans the repository.

```json
{ "mission_id": "uuid" }
```

## Poll mission state

`GET /api/v1/mission/{mission_id}`

Returns stage, progress, score, scanner health, normalized findings, timeline events, and the latest verification result.

## List findings

`GET /api/v1/findings/{mission_id}`

Returns normalized findings with stable fingerprints, scanner rule IDs, severity, and remediation status.

## Analyze a finding

`POST /api/v1/mission/{mission_id}/findings/{finding_id}/analyze`

Returns structured root cause, impact, recommendation, confidence, and patch guidance. Analysis is cached for the mission so re-opening a finding does not spend another model call.

## Create a patch proposal

`POST /api/v1/mission/{mission_id}/findings/{finding_id}/patch`

Returns a human-reviewable patch proposal. Secret findings intentionally do not produce an automated source patch.

## Approve and verify a patch

`POST /api/v1/mission/{mission_id}/patches/{patch_id}/verify`

Kavach applies the exact proposed replacement in an isolated copy, rescans the relevant scanner, and only applies the patch to the mission workspace after the target finding is absent.

## Export mission report

`GET /api/v1/mission/{mission_id}/report`

Returns a JSON audit report with scanner status, findings, score change, timeline, and verification evidence.

## Clean up a mission

`DELETE /api/v1/mission/{mission_id}`

Removes the in-memory record and its temporary cloned workspace.

`POST /api/v1/explain/{finding_id}` remains temporarily available for compatibility; new clients should use the mission-scoped analysis endpoint.
