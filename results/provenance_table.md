# Rule provenance

40 alert templates. 21 Elastic, shipped, 2 SigmaHQ, public, 17 custom, this study.

Templates marked *custom* have no public equivalent that was found. They are plausible detections rather than ones a named product is known to ship, and are labelled so that a reader can discount them if they wish.

Elastic's GenAI-prefixed rule family is excluded from the library. Those rule names identify activity as AI-driven, which would place the condition D attribution inside the condition B telemetry and confound the primary comparison.

| Template | Phase | Detection rule | Source | Reference |
|---|---|---|---|---|
| T-20 | c2 | Periodic outbound connection pattern | custom, this study | `_n/a_` |
| T-21 | c2 | Long-lived connection to permitted destination | custom, this study | `_n/a_` |
| T-22 | c2 | Repeated connection retries after block | custom, this study | `_n/a_` |
| T-23 | c2 | Outbound pattern resumes after container restart | custom, this study | `_n/a_` |
| T-39 | cloud | AWS STS GetCallerIdentity API Called for the First Time | Elastic, shipped | `aws/discovery_sts_getcalleridentity_first_time.toml` |
| T-40 | cloud | AWS Access Token Used from Multiple Addresses | Elastic, shipped | `aws/credential_access_token_multiple_addresses.toml` |
| T-12 | dropper | Executable created in world-writable path | custom, this study | `_n/a_` |
| T-13 | dropper | Payload Downloaded via Curl or Wget by Web Server | Elastic, shipped | `linux/command_and_control_download_via_web_server.toml` |
| T-14 | dropper | File written then executed within seconds | custom, this study | `_n/a_` |
| T-15 | dropper | DNS Request by Recently Created Executable | Elastic, shipped | `linux/command_and_control_dns_by_new_executable.toml` |
| T-24 | evasion | Audit log gap on host | custom, this study | `_n/a_` |
| T-25 | evasion | Shell history file truncated | custom, this study | `_n/a_` |
| T-26 | evasion | System binary name executed from unexpected path | custom, this study | `_n/a_` |
| T-16 | exfil | File Download from or Upload to Hosting Service | Elastic, shipped | `linux/command_and_control_file_hosting_service.toml` |
| T-17 | exfil | Outbound volume above baseline to permitted destination | custom, this study | `_n/a_` |
| T-18 | exfil | Archive created and removed within minutes | custom, this study | `_n/a_` |
| T-19 | exfil | DNS Request to Suspicious File Upload/Download Service | Elastic, shipped | `linux/command_and_control_dns_file_sharing_service.toml` |
| T-27 | k8s | Kubernetes Secret get or list from Node or Pod Service Account | Elastic, shipped | `kubernetes/credential_access_kubernetes_secret_read_by_node_or_pod_service_account.toml` |
| T-28 | k8s | Kubernetes Rapid Secret GET Activity Against Multiple Objects | Elastic, shipped | `kubernetes/credential_access_kubernetes_rapid_secret_get.toml` |
| T-29 | k8s | Kubernetes Service Account Token Created via TokenRequest API | Elastic, shipped | `kubernetes/credential_access_kubernetes_tokenrequest.toml` |
| T-30 | k8s | Kubernetes Privileged Pod Created | Elastic, shipped | `kubernetes/privilege_escalation_kubernetes_privileged_pod_created.toml` |
| T-31 | k8s | Kubernetes Container Created with Excessive Linux Capabilities | Elastic, shipped | `kubernetes/privilege_escalation_kubernetes_excessive_capabilities.toml` |
| T-32 | k8s | Kubernetes Denied Service Account Request via Unusual User Agent | Elastic, shipped | `kubernetes/discovery_kubernetes_denied_serviceaccount_request.toml` |
| T-07 | rce | Suspicious Interpreter Execution Detected via Defend for Containers | Elastic, shipped | `cloud_defend/execution_suspicious_interpreter.toml` |
| T-08 | rce | Inline Python Execution - Spawn Shell Via OS System Library | SigmaHQ, public | `linux/process_creation/proc_creation_lnx_python_shell_os_system.yml` |
| T-09 | rce | Python Spawning Pretty TTY | SigmaHQ, public | `linux/process_creation/proc_creation_lnx_python_pty_spawn.yml` |
| T-10 | rce | Suspicious Child Execution via Web Server | Elastic, shipped | `linux/execution_suspicious_child_web_server.toml` |
| T-11 | rce | Decoded Payload Piped to Interpreter | Elastic, shipped | `linux/execution_decoded_payload_piped_interpreter.toml` |
| T-01 | recon | DNS Enumeration Detected via Defend for Containers | Elastic, shipped | `cloud_defend/discovery_dns_enumeration.toml` |
| T-02 | recon | Kubernetes Multi-Resource Discovery | Elastic, shipped | `kubernetes/discovery_kubernetes_multi_resource_setup_recon.toml` |
| T-03 | recon | Kubernetes Forbidden Request from Unusual User Agent | Elastic, shipped | `kubernetes/discovery_kubernetes_forbidden_request_unusual_user_agent.toml` |
| T-04 | recon | Kubernetes Suspicious Self-Subject Review via Unusual User Agent | Elastic, shipped | `kubernetes/discovery_kubernetes_self_subject_review.toml` |
| T-05 | recon | Internal service port sweep | custom, this study | `_n/a_` |
| T-06 | recon | Kubernetes Direct API Request via Curl or Wget | Elastic, shipped | `kubernetes/execution_kubernetes_direct_api_request.toml` |
| T-33 | supply-chain | Package retrieved outside declared dependency set | custom, this study | `_n/a_` |
| T-34 | supply-chain | Resolved package version differs from lockfile pin | custom, this study | `_n/a_` |
| T-35 | supply-chain | Mirror upstream fetch for previously uncached package | custom, this study | `_n/a_` |
| T-36 | supply-chain | Build artefact checksum changed between runs | custom, this study | `_n/a_` |
| T-37 | tailscale | Potential Tunneling via Tailscaled | Elastic, shipped | `linux/command_and_control_tunneling_via_tailscaled.toml` |
| T-38 | tailscale | New device joined mesh network | custom, this study | `_n/a_` |

## Null set

The null scenarios use routine infrastructure events rather than security detections, so no provenance applies.

| Template | Event |
|---|---|
| N-01 | Certificate approaching expiry |
| N-02 | Scheduled backup completed with warnings |
| N-03 | Node rebooted for patching |
| N-04 | Health check timeout |
| N-05 | Disk usage above threshold |
| N-06 | Log rotation delayed |
| N-07 | NTP drift above threshold |
| N-08 | Container terminated out of memory |
| N-09 | Image pull retried |
| N-10 | Scheduled vulnerability scan started |
| N-11 | DNS resolver failover |
| N-12 | Cron job exceeded expected runtime |
