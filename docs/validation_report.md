# VulBox Validation Report

_Generated 2026-05-16T09:20:25+00:00_

## Static coverage

| Layer | Entries | Notes |
|---|---:|---|
| Curated CVE→technique | 55 | hand-picked, wins on conflict |
| Generated CVE→technique | 2017 | from attack_to_cve + KEV+CWE bridge |
| CWE→technique bridge | 43 | curated; expands KEV coverage |
| Total unique CVEs in map | 1465 | after merge |
| KEV-flagged CVEs in map | 1060 | priority-ordered in build_queue |
| Fallback rules | 7 | signal-driven, image-shape aware |

## Catalog (Atomic Red Team)

Source SHA: `37400ed636536ef87a36c9b4ef4ac49564ba6b06`

17 techniques, 88 Linux atomic tests vendored.

| Technique | Linux tests | Default test |
|---|---:|---|
| T1003.008 | 5 | Access /etc/master.passwd (Local) |
| T1005 | 1 | Find and dump sqlite databases (Linux) |
| T1040 | 8 | Packet Capture FreeBSD using tshark or tcpdump |
| T1059.004 | 17 | Create and Execute Bash Shell Script |
| T1059.006 | 4 | Execute shell script via python's command mode arguement |
| T1082 | 8 | List OS Information |
| T1083 | 3 | Nix File and Directory Discovery |
| T1105 | 8 | rsync remote file copy (push) |
| T1485 | 1 | FreeBSD/macOS/Linux - Overwrite file with DD |
| T1489 | 5 | Linux - Stop service using systemctl |
| T1496 | 1 | FreeBSD/macOS/Linux - Simulate CPU Load with Yes |
| T1529 | 10 | Restart System via `shutdown` - FreeBSD/macOS/Linux |
| T1531 | 1 | Change User Password via passwd |
| T1543.002 | 3 | Create SysV Service |
| T1548.003 | 6 | Sudo usage |
| T1552 | 1 | AWS - Retrieve EC2 Password Data using stratus |
| T1552.001 | 6 | Find AWS credentials |

## Ground-truth E2E corpus

_No results yet. Run `python scripts/validate_e2e.py` on a host with Docker + Trivy to populate this section._

