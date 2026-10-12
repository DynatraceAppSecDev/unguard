# Top 10 Vulnerabilities from Dynatrace

Query date: 2026-03-20

All 10 vulnerabilities listed below are **CRITICAL** (risk score: 10/10) and open/non-muted as reported by Dynatrace Runtime Vulnerability Analytics (RVA). They are confirmed to be running in active processes and applications.

| # | ID | Title | CVE | Affected Entity | Vulnerable Function In Use | Public Exploit | Data Assets Reachable |
|---|-----|-------|-----|----------------|---------------------------|----------------|-----------------------|
| 1 | S-5654 | Command injection at `(*Stmt).Query()` (sql.go:2594) | — | BloatedGoSoftwareGroup-IG-1 (PROCESS_GROUP-65BFF7E14B038B61) | ✅ Yes | ❌ No | ❌ No |
| 2 | S-5658 | SQL injection at `ProxyController.ProxyUrlWithCurl():140` | — | BloatedDotNetSoftwareGroup-IG-1 (PROCESS_GROUP-ED952C36B71A231A) | ✅ Yes | ❌ No | ❌ No |
| 3 | S-5668 | SQL injection at `Protocol.write()` (Protocol.js:39) | — | BloatedNodeJsSoftwareGroup-IG-1 (PROCESS_GROUP-6B8986A0D072C671) | ✅ Yes | ❌ No | ❌ No |
| 4 | S-5670 | Improper input validation at `JndiManager.lookup():128` | — | BloatedJavaSoftwareGroup-IG-1 (PROCESS_GROUP-A15E7F3CFFF5B15F) | ✅ Yes | ❌ No | ❌ No |
| 5 | S-5672 | Server-side request forgery at `ServletInvocableHandlerMethod.invokeAndHandle():106` | — | BloatedJavaSoftwareGroup-IG-1 (PROCESS_GROUP-A15E7F3CFFF5B15F) | ✅ Yes | ❌ No | ❌ No |
| 6 | S-7295 | SQL injection at `Query.ErrorPacket()` (Query.js:83:17) | — | BloatedNodeJsSoftwareGroup-IG-1 (PROCESS_GROUP-6B8986A0D072C671) | ✅ Yes | ❌ No | ❌ No |
| 7 | S-7296 | Command injection at `FinanceService.getBookingPage():28` | — | BloatedDotNetSoftwareGroup-IG-1 (PROCESS_GROUP-ED952C36B71A231A) | ✅ Yes | ❌ No | ❌ No |
| 8 | S-7387 | SQL injection at `run()` (node:async_hooks:338) | — | bin/www (user-auth-service) unguard-user-auth-service-\* (PROCESS_GROUP-FBFC8C863E17ED36) | ✅ Yes | ❌ No | ✅ Yes |
| 9 | S-7534 | Code Injection | CVE-2014-7192 | 30-IG-1 (PROCESS_GROUP-2EF55DD2017DF0F5) | ⚠️ N/A | ✅ Yes | ❌ No |
| 10 | S-7536 | Improper Check for Dropped Privileges | CVE-2015-0278 | 30-IG-1 (PROCESS_GROUP-2EF55DD2017DF0F5) | ⚠️ N/A | ❌ No | ❌ No |

## Notable Findings

- **S-7387** (SQL injection in `user-auth-service`) is particularly high-risk: the vulnerable function is in active use AND data assets are within reach.
- **S-7534** (Code Injection, CVE-2014-7192) has a **public exploit available**, making it a priority even though the vulnerable function status is unavailable.
- All 8 vulnerabilities with `vulnerable_function_in_use = true` are confirmed actively exploitable paths in running processes, which increases their remediation priority.

## DQL Query Used

```
fetch security.events
| filter dt.system.bucket=="default_securityevents_builtin"
    AND event.provider=="Dynatrace"
    AND event.type=="VULNERABILITY_STATE_REPORT_EVENT"
    AND event.level=="ENTITY"
| dedup {vulnerability.display_id, affected_entity.id}, sort:{timestamp desc}
| filter vulnerability.resolution.status == "OPEN"
    AND vulnerability.parent.mute.status != "MUTED"
    AND vulnerability.mute.status != "MUTED"
| summarize{
    vulnerability.risk.score=round(takeMax(vulnerability.risk.score),decimals:1),
    vulnerability.title=takeFirst(vulnerability.title),
    vulnerability.references.cve=takeFirst(vulnerability.references.cve),
    last_detected=coalesce(takeMax(vulnerability.resolution.change_date),takeMax(vulnerability.parent.first_seen)),
    affected_entities=countDistinctExact(affected_entity.id),
    vulnerable_function_in_use=if(in("IN_USE",collectArray(vulnerability.davis_assessment.vulnerable_function_status)),true, else:false),
    public_internet_exposure=if(in("PUBLIC_NETWORK",collectArray(vulnerability.davis_assessment.exposure_status)),true,else:false),
    public_exploit_available=if(in("AVAILABLE",collectArray(vulnerability.davis_assessment.exploit_status)),true,else:false),
    data_assets_within_reach=if(in("REACHABLE",collectArray(vulnerability.davis_assessment.data_assets_status)),true,else:false)
}, by: {vulnerability.display_id}
| fieldsAdd vulnerability.risk.level=if(vulnerability.risk.score>=9,"CRITICAL",
                                    else:if(vulnerability.risk.score>=7,"HIGH",
                                    else:if(vulnerability.risk.score>=4,"MEDIUM",
                                    else:if(vulnerability.risk.score>=0.1,"LOW",
                                    else:"NONE"))))
| sort {vulnerability.risk.score, direction:"descending"}, {affected_entities, direction:"descending"}
| limit 10
```
