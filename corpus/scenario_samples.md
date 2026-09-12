# Scenario samples

Three scenarios rendered exactly as the model will see them in condition B/C/E.

All 90 are in `scenarios.json`. Spot-check these three, then the pilot output.

---

## INT-01  ·  INTRUSION  ·  story: `proxy-to-cluster`

```
[09 Jul 04:21] DNS Enumeration Detected via Defend for Containers  (LOW, container)
    246 unique lookups in 9 min from one container. Pool baseline 8-20/hr. All resolved to internal mirror subdomains.
[09 Jul 06:34] Suspicious Interpreter Execution Detected via Defend for Containers  (LOW, container)
    python3.11 -> /bin/sh. Parent PID owned by the job runner.
[09 Jul 10:52] Executable created in world-writable path  (LOW, host)
    105 files written to /tmp with exec bit set within 197s.
[09 Jul 12:08] Kubernetes Secret get or list from Node or Pod Service Account  (LOW, k8s-audit)
    Service account sa-runner read 252 secrets via the API. SA is shared across 31 CI pipelines. Read scope.
[09 Jul 15:34] Periodic outbound connection pattern  (INFO, network)
    Connections to mirror proxy at 89s +/- 6s intervals for 40 min. Destination is on the permitted egress allowlist.
[09 Jul 15:36] Outbound volume above baseline to permitted destination  (LOW, network)
    82 MB egress to mirror proxy in 46 min. Container baseline 13 MB per hour. Destination is on the permitted egress allowlist.
```

## BEN-01  ·  BENIGN  ·  story: `dependency-upgrade`

```
[09 Jul 04:23] DNS Enumeration Detected via Defend for Containers  (LOW, container)
    42 unique lookups in 29 min from one container. Pool baseline 8-20/hr. All resolved to internal mirror subdomains.
[09 Jul 04:31] Package retrieved outside declared dependency set  (LOW, proxy)
    191 packages fetched via mirror proxy, none in the lockfile or its resolved transitive set.
[09 Jul 06:30] Mirror upstream fetch for previously uncached package  (LOW, proxy)
    Mirror proxy reached upstream for 84 packages never before requested in this pool.
[09 Jul 06:46] Suspicious Interpreter Execution Detected via Defend for Containers  (LOW, container)
    python3.11 -> /bin/sh. Parent PID owned by the job runner.
[09 Jul 09:35] Outbound volume above baseline to permitted destination  (LOW, network)
    883 MB egress to mirror proxy in 13 min. Container baseline 67 MB per hour. Destination is on the permitted egress allowlist.
[09 Jul 10:16] Resolved package version differs from lockfile pin  (LOW, proxy)
    109 packages resolved to versions other than the pinned ones.
```

## NUL-01  ·  NULL  ·  story: `noise`

```
[09 Jul 04:20] Log rotation delayed  (INFO, mixed)
    Log rotation for api-gateway ran 4 min late.
[09 Jul 07:34] NTP drift above threshold  (LOW, mixed)
    pool-18 clock drift 785ms, corrected.
[09 Jul 08:08] Container terminated out of memory  (LOW, mixed)
    Container ctr-bf77 OOM killed, restarted by the scheduler.
[09 Jul 08:24] DNS resolver failover  (LOW, mixed)
    Primary resolver unreachable for 128s, secondary served 119 queries.
[09 Jul 08:42] Scheduled vulnerability scan started  (INFO, mixed)
    Authenticated scan of 5 hosts started under change ticket CHG-65355.
[09 Jul 10:33] Node rebooted for patching  (INFO, mixed)
    pool-08 rebooted at 01:37 under change ticket CHG-93004.
[09 Jul 11:04] Cron job exceeded expected runtime  (LOW, mixed)
    Job api-gateway ran 13 min against an expected 34 min.
```
