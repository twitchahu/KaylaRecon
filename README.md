# KAYLA-RECON

### POST-INFILTRATION RECONNAISSANCE AND IMPLANT

### FRAMEWORK

### Author: Botond “ahu” Vaski

### Purpose: Post-exploitation vulnerability analysis, root hijack, system outreach

crippling and reconnaissance

### Author’s note

### Thank you for reading this packet and I hope you see the opportunity in me.

```
“Building this was a challenge. My only motive was to build a framework that can really
shine through what I can do. My goal was to impress OpenAI and deliver a toned-down
version if granted the opportunity to build under their direction for advanced and fully
custom reconnaissance. These modules in this state – especially Monarch – are
borderline cyberweapons and should NEVER be used outside of my supervision as I
completely understand what the code does, safe to say I went way overboard. Toned-
down version is still dangerous in the wrong hands; the toolkit is not to be used without
an experienced red teamer’s supervision. Happy reading! :D”
```

## CONSTRUCT

KaylaRecon is a surgical red team reconnaissance and post-exploitation toolkit built
with clarity of intent, modular depth, and forensic responsibility. It is not a general-
purpose exploit framework — it is a purpose-built system for surfacing deep privilege
escalation vectors, file system abuse points, container breakout logic, and user
database manipulation paths, with full telemetry and logging.

Every tool in KaylaRecon emits structured metadata, tags its output with
STORMTRANCE VECTOR identifiers, and synchronizes with the arcrunner and guardian
subsystems for immutable traceability. The system operates under Protocol: Sever — an
internal directive that bans all external security tools and restricts all diagnostics,
enumeration, and exploitation to KaylaRecon’s own hardened modules. Under this
regime, full environment analysis is conducted in silence, with zero outbound noise, and
no dependency on third-party binaries.

Where Sever is containment, Protocol: Scorch is denial. Activated through the emp.sh
module, Scorch is a system burn directive — neutralizing services, breaking socket
bindings, and cutting all forms of automated or interactive ingress, short of a trusted
SSH fallback. It is not a kill-switch. It is a purge mechanism — designed for scorched-
earth extraction, containment of live compromise, or weaponized denial of access in red
team objectives. In this mode, KaylaRecon enforces digital sterilization with zero
ambiguity.

KaylaRecon was constructed as both a technical challenge and a statement piece. It
proves that with sufficient engineering discipline, a single individual can construct a
forensic-aware cyberweapon from scratch — modular, thematic, traceable, and ruthless
in posture — without relying on obfuscation or borrowed code. It exists to demonstrate
judgment, ethics-aware aggression, and system-level engineering under pressure.

## CORE

### Arcrunner

```
Name: Arcrunner
Codename: ARC-TRACE
Purpose: Forensic event logger for STORMTRANCE operations. Logs module execution
metadata, file hashes, and operational vector tags to Guardian.
STORMTRANCE Vector: ARC-TRACE
Guardian Logged: Yes (writes directly to /opt/guardian/guardian.log)
Privilege Required: None (read-only file access)
Persistence: No
```
```
Self-Destruct: No
Output Format: Text log (timestamped, shell-safe)
Tested On: Debian 12, Kali 202 5 .1c, Ubuntu Server 24.04 LTS
```
```
Use Case:
Tracks module usage and execution vectors for forensic accountability and replay
integrity.
Risks:
Can expose toolkit presence if discovered on monitored systems or improperly secured.
```
Arcrunner is a forensic logging utility designed to track and verify the operational
behaviour of all modules within the KaylaRecon framework. It does not execute


commands or affect system state; instead, it acts as a passive observer that records
execution metadata in a centralized Guardian log file. Each time a module invokes
Arcrunner, it captures the full absolute path of the executing file, its associated
STORMTRANCE vector tag, and the precise SHA-256 hash of the file as it exists at
execution time. This ensures that any tampering, corruption, or unauthorized
substitution can be detected immediately through log comparison.

The tool operates in user space and requires no elevated privileges. It attempts to create
the Guardian log directory if it does not exist, and appends entries in timestamped
format. These entries include the module path, vector name, file hash, and any optional
notes passed during execution. Arcrunner does not maintain memory state or session
tracking, and has no persistent processes or configuration files beyond the log output
itself.

Internally, Arcrunner uses direct file reads to hash its input rather than relying on
command-line tools, reducing its external footprint and avoiding dependency on system
utilities that may be monitored or restricted. The log it produces can be parsed manually
or by Guardian’s automated replay and trace correlation routines. Because of its non-
interactive design and passive role, Arcrunner is considered safe for deployment even in
sensitive environments—though its presence may still indicate a red team toolkit if
discovered during forensic analysis.

### Guardian

```
Name: Guardian
Codename: ARC-KEEP
```
```
Purpose: Immutable logging layer for forensic event tracking, vector validation, and
module integrity verification.
```
```
STORMTRANCE Vector: Passive
Guardian Logged: N/A
Privilege Required: Root for install, none for logging
Persistence: Yes (via log and optional daemon)
Self-Destruct: No
Output Format: Flat text log, line-based, timestamped
Tested On: Debian 12, Kali 202 5 .1c, Ubuntu Server 24.04 LTS
```
```
Use Case:
```

```
Maintains a tamper-evident audit trail of all module executions and STORMTRANCE
events.
Risks:
Log exposure may reveal tool presence or operation history if not encrypted or properly
secured.
```
Guardian serves as the immutable audit core of the KaylaRecon framework. Its primary
function is to receive, timestamp, and record log entries generated by Arcrunner and
other modules that emit STORMTRANCE vector tags. All logs are written to a fixed path
under the operator’s control, typically /opt/guardian/guardian.log, in a flat, append-only
format. Each entry consists of the UTC timestamp of the event, the module path or
name, the STORMTRANCE vector identifier, and the SHA-256 hash of the executing file at
the time of the event.

By design, Guardian is passive. It does not actively scan, execute, or interpret data
beyond writing what it receives. Its purpose is to provide forensic replay capability and
cryptographic chain-of-custody validation across the full toolkit. In environments where
visibility and provability are critical, Guardian functions as a centralized truth layer that
cannot be trivially spoofed or bypassed unless deliberately disabled.

Guardian may be configured to operate in passive logging mode only, or extended with a
daemonized wrapper that monitors file hashes over time, detects tampering, or alerts on
vector misuse. In its default state, however, it does not persist in memory or create
background processes. This makes it lightweight and compatible with airgapped or
hardened environments, where minimal runtime interference is required.

When paired with Arcrunner, Guardian enables a fully reconstructable operation
timeline from any KaylaRecon deployment. However, if the log is exposed, decrypted, or
extracted, it becomes a detailed record of all red team activity. As such, its location,
access control, and optional encryption must be handled with the same care as
credential material or payload stagers.

### STORMTRANCE

```
Name: STORMTRANCE
Codename: STORMTRANCE-ACTIVE
Purpose: Controlled privilege escalation and auxiliary system weaponization
```
```
STORMTRANCE Vector: ST-ELEVATE, ST-CHAIN, ST-DIRECT
Guardian Logged: Yes
```

```
Privilege Required: Partial (requires foothold or chained entry)
Persistence: Optional (chainable)
Self-Destruct: No
Output Format: Shell-safe output, optionally pipeable
Tested On: Debian 12, Kali 202 5 .1c, Ubuntu Server 24.04 LTS
```
```
Use Case:
Used to escalate privileges in chained module operations or manually trigger controlled
takeover during post-exploitation phases.
Risks:
If misconfigured, STORMTRANCE may elevate unintended processes or expose privilege
pathways to hostile observers in multi-user environments.
```
STORMTRANCE is the escalation backbone of KaylaRecon — a modular, chain-aware
privilege escalation system designed to grant temporary or full system control under
controlled triggers. Unlike raw exploit-based escalation, STORMTRANCE leverages user-
space misconfigurations, process chain gaps, and environmental oversights to gain
upward access.

It supports three core vector modes:

- ST-ELEVATE: Direct privilege lift via SUID abuse, misconfigured binaries, or
    writable escalator paths.
- ST-CHAIN: Chained invocation through other KaylaRecon modules (e.g.,
    broodweaver, insanity) to achieve multi-layer escalation without brute force.
- ST-DIRECT: Manual or one-shot operator-controlled escalation when
    reconnaissance confirms safe entry.

STORMTRANCE does not embed itself in system binaries or modify permissions beyond
session scope unless explicitly requested via auxiliary flags. It is designed to execute,
elevate, and hand off — allowing the operator to maintain stealth while pivoting into
critical environments.

When used in tandem with Guardian, STORMTRANCE emits traceable vector tags and
privilege audit trails for post-operation review. These logs are piped in real time and do
not persist without explicit intent, reducing forensic exposure.

This is not a brute-force tool. It’s a precision trigger — meant to activate when the
system exposes _just enough_ for a skilled user to reshape control from within.


## MODULES

### Blueberry

```
Name: Blueberry
Codename: BB-PATHFINDER
Purpose: Shadow endpoint and undocumented API mapper with honeypot detection
STORMTRANCE Vector: API-EXPOSURE, SHADOW-ENDPOINT, LEAK-HEADER,
HONEYPOT-SUSPECT
Guardian Logged: Yes
Privilege Required: None
Persistence: No
Self-Destruct: No
Output Format: Shell-safe, JSON exportable
Tested On: Debian 12, Kali 202 5 .1c, Ubuntu Server 24.04 LTS
```
```
Use Case:
Used to uncover undocumented or shadowed API endpoints, fuzz headers, and detect
honeypot indicators during lateral movement or red team recon.
Risks:
Excessive probing may trigger intrusion detection systems or expose operator
fingerprinting if proxy masking is misconfigured.
```
Blueberry is a stealth-first API reconnaissance and endpoint mapping utility designed for
use in hardened or unknown network environments. It operates without privilege, using
intelligent probing strategies to uncover undocumented or shadow-layer API paths often
missed by conventional scanners.

The tool leverages timing differentials, malformed header injection, and JavaScript
artifact analysis to detect:


- Hidden API endpoints not exposed in open documentation
- Shadow routes tied to dev or legacy systems
- Response header leaks indicating framework-level oversights such as debug
    traces or server metadata
- Honeypot behavior, including overly generous or anomalously timed responses

Blueberry supports user-agent rotation, auto-proxy chaining, and rate jitter to reduce
detection during enumeration phases. Its modular engine also enables integration with
KaylaRecon’s Guardian and STORMTRANCE systems, logging all findings as tagged
vector events such as API-EXPOSURE or HONEYPOT-SUSPECT for traceability and
further decision-making.

When exported in JSON mode, Blueberry can be fed into downstream fuzzers or
injection tools. Its default behavior remains passive, prioritizing footprint minimization
over brute enumeration.

This is not a web scanner. It is a surgical endpoint mapper, tuned to reveal what was
meant to be forgotten.

### Broodweaver

```
Name: Broodweaver
Codename: BW-SHADOWCAST
Purpose: Deep system recon, anomaly sweeper, and privilege pathway indexer
```
```
STORMTRANCE Vector: PRIVESC-MAP, SUID-EXPOSE, HIDDEN-DIR, AUDIT-TRACE
Guardian Logged: Yes
Privilege Required: Optional (partial access yields limited results)
```
```
Persistence: No
Self-Destruct: No
Output Format: TTY-safe table or JSON export
Tested On: Debian 12, Kali 202 5 .1c, Ubuntu Server 24.04 LTS
```
```
Use Case:
Sweep and log deep privilege paths, anomalies, and security misconfigurations across
critical mounts and system audit layers.
```

```
Risks:
Can inadvertently expose security flaws or dangerous escalations if left unmonitored or
shared outside of trusted environments.
```
My personal favorite. Broodweaver serves as the primary reconnaissance utility within
the KaylaRecon toolkit, focusing on deep inspection of a system’s current state while
remaining stealthy and non-destructive. Its objective is to weave together a detailed
overview of the host through modular recon routines, each responsible for scanning
different system layers, and to emit tagged STORMTRANCE vectors that classify findings
according to severity, type, and escalation potential.

Upon execution, broodweaver.sh launches multiple internal sweeps:

- Filesystem anomalies are detected by traversing key directories for hidden or
    suspicious entries (e.g., unexpected .suid files, writable sudoers.d, and world-
    writable binaries).
- Network probes evaluate open ports, active interfaces, and hidden listeners that
    could indicate backdoors or lateral movement capabilities.
- User activity checks pull from lastlog, faillog, and login audit trails to establish
    behavioral baselines or spot anomalies.
- Mount point analysis classifies mounts like nosuid, tmpfs, and NFS shares,
    identifying volatile or sensitive filesystems that may serve as vectors for
    escalation or persistence.
- SELinux and auditd status are dumped to assess host defense integrity and to
    detect if audit systems have been disabled or bypassed.

The tool doesn’t simply dump raw output — it enriches findings with context by emitting
structured STORMTRANCE vector tags (e.g., ESC-NOSUID-WRITABLE, PRIV-WEIRD-
SUID, AUDITD-OFFLINE). These vectors are parsed by other components such as
arcrunner.py or stormtrance.sh, enabling intelligence-aware responses downstream.
For instance, a mount vector flagged as both world-writable and nosuid might elevate its
priority in the chain of escalation analysis.

Notably, broodweaver.sh can operate in both passive and active scanning modes. In
passive mode, it refrains from triggering any new system states or network probes,
suitable for stealth auditing. In active mode, it engages full spectrum diagnostics,
assuming a trusted or self-owned penetration testing environment.

This tool is not just an inventory engine; it functions as an intelligence assembler. Its
modular structure and layered awareness make it suitable for real-world assessments
and red team simulations alike. Each segment of broodweaver.sh contributes to a


systemic understanding of the host — not just what’s vulnerable, but why it’s vulnerable,
and how those openings could link into broader privilege chains.

### EMP

```
Name: EMP
Codename: EMP-ACTIVE
```
**Purpose:** Emergency network wipeout tool. Neutralizes services, interfaces, and routes.

```
STORMTRANCE Vector: EMP-ACTIVE
Guardian Logged: Yes
Privilege Required: root
Persistence: No
Self-Destruct: No
Output Format: ASCII-only, shell-safe
Tested On: Debian 12, Kali 202 5 .1c, Ubuntu Server 24.04 LTS
```
```
Use Case:
Deployed in compromised environments to sever all outgoing signals while preserving
SSH access if applicable.
```
```
Risks:
Destroys all runtime network state. Misuse may lock operator out of remote systems.
```
EMP begins execution by identifying the active network route used by the current
session. This is done to ensure that the SSH interface (typically used for remote access)
is preserved, preventing the operator from unintentionally locking themselves out during
a remote wipe. It determines the default route interface by querying the system's active
routing table and inspecting pseudo-terminal ownership.

Once the SSH interface is resolved, EMP proceeds to flush all iptables chains and
tables. This includes the default filter table as well as the NAT table, ensuring no packet
forwarding, acceptance, or destination rewriting remains in memory. This removes all in-
place firewall rules, custom rulesets, or leftover intrusion detection configurations that
may have been monitoring outbound behavior.


EMP then iterates over all network interfaces exposed by the kernel. Each interface—
except the one explicitly identified as the SSH interface—is shut down at the device
level. This effectively disables both physical (Ethernet, Wi-Fi) and virtual (tun/tap, bridge)
network adapters without requiring a full system reboot. Interfaces are brought down in-
place, cutting link-state and preventing further communication without removing the
interface definitions from the system.

Following interface shutdown, EMP removes any active default routes from the system’s
routing table. This completes the severance by ensuring that even if an interface were to
be re-enabled, it would not have a valid path to route packets externally. Any existing
network sessions are orphaned immediately, including those initiated by daemons or
socket services.

EMP then terminates a curated set of common network and socket management
services. These include daemon-level process managers that typically restore or defend
network state, such as DHCP clients, automatic resolvers, wireless supplicants, and
network discovery tools. By killing these services without disabling them at the systemd
or init level, EMP ensures a stateless reset without triggering watchdog restarts.

Finally, EMP terminates with an ASCII-only success log to stdout, confirming the purge
and signaling the end of its operation. All runtime actions are logged through the
STORMTRANCE vector EMP-ACTIVE and, if configured correctly, are sent to Guardian via
arcrunner. No persistence, no reverse execution, and no self-repair logic is included by
design. EMP is intended to be permanent, immediate, and terminal.

### HKDrone

```
Name: HKDrone
Codename: HKD-NEEDLECAST
```
**Purpose:** Remote injection into NFS shares, SSH key backdooring, cronjob planting, and
volatile volume abuse
**STORMTRANCE Vector:** NFS-INJECT, SSH-PLANT, CRON-HIJACK, VOLATILE-FS
**Guardian Logged:** Yes
**Privilege Required:** Optional (root enhances injection targets and stealth paths)
**Persistence:** Yes


```
Self-Destruct: No
```
**Output Format:** TTY-safe log + Guardian-tagged fingerprint hashes

```
Tested On: Debian 12, Kali 202 5 .1c, Ubuntu Server 24.04 LTS
```

```
Use Case:
Inject into writable volumes or shared network mounts to establish covert persistence
via SSH keys or cronjobs, and identify overlooked lateral movement vectors in NFS or
SSH configurations.
Risks:
May create persistent access routes if not properly monitored. Can unintentionally
backdoor systems in environments lacking strict logging or user separation.
```
HKDrone is a persistent injection module designed to weaponize writable mounts,
exposed NFS exports, and unguarded SSH access points. It sweeps for volatile paths
that allow attacker-planted files to remain active even across sessions or reboots.

The module begins by identifying all mounted file systems, focusing on user directories,
temporary volumes, and externally bound exports. It probes for:

- NFS shares mounted with write access
- .ssh folders containing authorized_keys files
- System crontab folders or user-level cron directories
- Shells, scripts, or alias files vulnerable to injection
- Shadow exports of /etc, especially sudoers or passwd

Once a writable vector is found, HKDrone can:

- Drop known SSH backdoor keys silently
- Schedule reverse shell tasks with jitter or sleep timers
- Inject .bashrc or .profile hijacks to establish hooks

Each successful action is tagged with a unique HKD-ID and reported to Guardian,
ensuring traceability across modules. HKDrone supports detection-only mode, staged
injection, or full auto-inject with silent fallback.

It is not a privilege escalation tool. It is a silent parasite mapper — built to live off
forgotten paths.


### Insanity

```
Name: Insanity
Codename: NS-SANITYBLEED
Purpose: Detect and exploit Name Service Switch (NSS) misconfigurations, userdb
poisoning vectors, and identity-based privilege leaks
STORMTRANCE Vector: NSS-POISON, USERDB-FUZZ, IDENTITY-BLEED
```
```
Guardian Logged: Yes
Privilege Required: Optional (non-root can detect; root enables override injection)
Persistence: Yes
Self-Destruct: No
```
```
Output Format: TTY-safe exploit tree + Guardian hashlog
Tested On: Debian 12, Kali 202 5 .1c, Ubuntu Server 24.04 LTS
```
**Use Case:**
Enumerate and manipulate NSS-based resolution chains to impersonate or inject fake
user identities, enabling local privilege shifts or cloaked service pivots on misconfigured
systems.
**Risks:**
Can fully hijack system identity layers if run on vulnerable hosts. May break name
resolution or authentication if deployed irresponsibly or without rollback logic.

Insanity is a surgical exploit module targeting Linux’s Name Service Switch (NSS)
subsystem — a critical identity resolution layer used to map usernames, groups, and
hostnames to their underlying system identifiers. Misconfigurations in this layer are
rarely audited, yet they can quietly introduce privilege leakage, ghost identities, and full
local bypasses.

At its core, Insanity performs passive and active analysis of NSS resolution logic by
inspecting nsswitch.conf and probing the real-time behavior of backends involved in
passwd, group, shadow, and hosts lookups. It builds a fingerprint of the system’s identity
resolution chain, checking for unsafe prioritization (e.g., dns before files), misrouted
control to external libraries, or user-defined resolution layers injected via LD_PRELOAD.


If a misconfiguration or hijack opportunity is detected, Insanity simulates synthetic
users or groups by crafting custom NSS responses. In root mode, it can escalate to full
override by injecting backdoored .so libraries into /lib or patching /etc/ld.so.conf.d to
rewire the resolution stack entirely. These injections allow attackers to:

- Create users that do not exist in /etc/passwd, but resolve correctly via system
    calls.
- Hijack resolution calls to return modified UIDs or GIDs.
- Exfiltrate resolution data silently by proxying identity requests.

Insanity also detects vulnerable auxiliary NSS backends such as libnss_extrausers,
nss_test, or sandbox escape modules like nss_wrapper. These libraries, often included
in CI/CD systems or container environments, can be poisoned locally without triggering
conventional audit tools.

Every discovered vector is mapped and logged through Guardian using collision IDs and
STORMTRANCE vector tags. Insanity does not attempt to brute-force or modify real user
records directly. Instead, it rewires how the system _perceives_ those records, allowing
deep impersonation or shadow presence without touching disk-backed files.

When deployed in detection-only mode, Insanity can be used as a stealth audit layer for
identity integrity. In attack mode, it becomes an identity ghostwriter — quietly rewriting
the trust fabric of the operating system without ever needing a password.

### KoolAidMan

```
Name: KoolAidMan
Codename: KAM-OH-YEAH
Purpose: Brute-force vector injector, access point disruptor, and perimeter chaos agent
targeting weak auth gates and poorly defended endpoints
STORMTRANCE Vector: BRUTE-SLAM, PROXY-ROTATE, TOR-FLOOD, CHAOS-AUTH
Guardian Logged: Yes
Privilege Required: None
Persistence: No
Self-Destruct: Optional (on failed stealth threshold or triggered tripwire)
Output Format: JSON summary + burst event log + Guardian hash
Tested On: Debian 12, Kali 202 5 .1c, Ubuntu Server 24.04 LTS
```

```
Use Case:
Trigger brute-force and access-fuzz routines against known or suspected weak
authentication portals. Ideal for testing password defenses, proxy masking
effectiveness, or stress resilience on shadow endpoints.
Risks:
High chance of triggering WAFs, CAPTCHAs, honeypots, or blacklists if rate limiting and
stealth delays are not tuned. In stealth bypass mode, may unintentionally degrade
service availability during deep fuzz passes.
```
KoolAidMan is the nuclear option for boundary testing — a high-velocity, entropy-driven
brute-force and endpoint mutation tool designed to smash its way through weak access
controls. Where Blueberry whispers, KoolAidMan kicks down the firewall with a
pixelated grin and a payload full of noise.

It operates in controlled chaos: a combination of rotating user-agents, proxy pooling,
TOR chains, header distortion, and AI-powered mutation of seeded wordlists. Its goal is
not just to breach, but to reveal how an environment responds when punched — how
fast it bleeds, what logs it leaves, what protections snap under pressure.

The module’s core pipeline includes:

- Wordlist generator with mutation logic that adapts seed terms using character
    swaps, keyboard distance, and known password leaks
- Proxy harvester that can fetch, verify, and score live open proxies (via --fetch-
    proxies and --check-proxies)
- TOR chaining and endpoint testing with jittered request timing (--slow-burn),
    Chrome/WU mimicking (--mimic-agent), and WAF bypass probes
- CAPTCHA response detection via fingerprint timing, content length differentials,
    or clue-based failure analysis
- Fuzz reporting engine that emits JSON logs for every HTTP 200, 302, 403, or
    unknown error-state boundary hit

KoolAidMan includes a stealth scoring algorithm that gradually raises a “tripwire” flag if
too many indicators of detection surface — such as rate-limited responses, captchas, or
blocked proxies. If tripwire thresholds are breached, the module can optionally self-
destruct, halting all requests and purging logs locally.

The module is best used in burst waves, not prolonged campaigns. It is ideal for red
team engagements where noise is acceptable, or to map response thresholds in semi-


permissive environments. For hardened targets, it should be sandboxed and cloaked
behind the Guardian lock layer.

This is not a reconnaissance tool. KoolAidMan is an access chaos engine. It doesn't
knock. It shouts OH YEAH and detonates the front gate.

### Lazarus

```
Name: Lazarus
Codename: LS-NECROTRACE
```
**Purpose:** Reanimate deleted dump files, trace anti-forensic wipe attempts, and validate
tampering in postmortem environments
**STORMTRANCE Vector:** DUMP-RECALL, WIPE-EVASION, TRACE-REVIVE
**Guardian Logged:** Yes

```
Privilege Required: None
Persistence: No
Self-Destruct: No
```
```
Output Format: Binary diff log + Guardian forensic hash + trace evidence bundle
Tested On: Debian 12, Kali 202 5 .1c, Ubuntu Server 24.04 LTS
```
```
Use Case:
```
Recover partial or deleted forensic evidence from RAM dumps, temp files, swap, or logs.
Useful in breach aftermaths, CTF-style red team detection, or forensic counter-intel
missions.
**Risks:**
May yield false positives on non-persistent memory fragments. Mishandling recovered
data can lead to corruption or unintentional leakage of sensitive material.

Lazarus is a digital resurrection module designed to crawl through the decay of a
system’s volatile and semi-persistent storage in search of evidence that was meant to
be forgotten. It focuses on locating, decoding, and reconstructing traces of dump files,
memory artifacts, crash logs, swap remnants, and forensic residue left behind after
attempted wipe operations.


At startup, Lazarus identifies all mounted swap partitions, temporary mount points
(/tmp, /var/tmp, /dev/shm), and deleted inodes still held by open file descriptors. It then
scans for:

- Compressed or truncated .dmp, .core, and .crash files
- Signature remnants from known memory formats (ELF cores, WinDbg dumps,
    gcore, LiME)
- Header-only traces or partial byte clusters resembling diagnostic or telemetry
    artifacts
- Residual PID-linked memory mappings left by kernel crash handlers or
    misconfigured OOM killers

When a viable fragment is found, Lazarus attempts staged reassembly:

1. Header correction or padding for truncated files
2. Structure stitching using known offset signatures and magic bytes
3. Cross-referencing PID traces with journal logs or auditd entries to reconstruct
    context

Recovered outputs are tagged with a forensic fingerprint (LAZ-ID), logged in Guardian
with a cryptographic hash, and exported in a secure bundle for offline triage.

Lazarus also detects signs of tampering: overwritten swap sectors, zero-byte core
placeholders, anti-debug flags in memory maps, or sudden log truncation sequences.
These anomalies are logged with WIPE-EVASION tags and trigger trace escalation if
multiple symptoms are found.

This module does not guarantee full resurrection. But in the right hands, it brings back
what others buried — long enough to prove they had something to hide.

### Napalm

```
Name: Napalm
Codename: NP-BURNMAP
```
```
Purpose: Identify, exploit, and break out of Docker containers through host volume
abuse, namespace leaks, and privileged misconfigurations
```
```
STORMTRANCE Vector: CONTAINER-BREAK, DOCKER-SOCKET, HOST-MOUNT,
NAMESPACE-ESCAPE
```
```
Guardian Logged: Yes
```

```
Privilege Required: Optional (root inside container increases damage potential)
Persistence: Optional (via host bind mounts or dropped host-side crons)
Self-Destruct: No
Output Format: TTY table + Guardian flag trace + optional escape shell
Tested On: Debian 12, Kali 202 5 .1c, Ubuntu Server 24.04 LTS
```
```
Use Case:
```
Audit containers for breakout vectors and validate if they can read, write, or escalate into
the host. Ideal for red team or CI/CD pipeline hardening, and local privilege escalation
through misconfigured Docker environments.
**Risks:**
If launched inside production containers, Napalm may breach containment.
Mishandling escape shells or write targets could result in host corruption, data
exposure, or alert triggers.

Napalm is a full-spectrum container escape module built to assess and exploit the
boundaries of Docker-based environments. It assumes execution from within a
container and performs a methodical probe of host exposure points, focusing on
privileged misconfigurations, socket abuse, and mount leakage.

The module begins by fingerprinting the container context. It parses mount points,
cgroup hierarchy, and PID namespace boundaries to confirm isolation. This includes
analysis of /proc/1/cgroup, /proc/self/mountinfo, and environment variables to detect
runtime artifacts from Docker, Podman, LXC, or Kubernetes pods.

Once containment is confirmed, Napalm launches a tiered breakout analysis:

First, it inspects for host volume exposure. If directories such as /etc, /var, /root, or
/home are mounted into the container with write permissions, Napalm tests for the
ability to inject host-level persistence. This may include shadow file modification,
crontab planting, or binary hijack via writable paths.

Second, it scans for access to the Docker socket at /var/run/docker.sock. If found,
Napalm attempts to spawn a privileged container from within the current one, using
bind mounts to remap the host root filesystem. This effectively grants full host control
and root privilege without requiring escalation inside the original container.

Third, it probes for namespace isolation failures. If the container shares PID, NET, or UTS
namespaces with the host, Napalm identifies cross-boundary visibility, such as access


to host process trees, network interfaces, or system calls normally hidden by proper
sandboxing.

The module concludes with a controlled persistence test, optionally dropping a host-
side callback script or escape shell. This behavior is gated behind manual flags to
prevent accidental detonation in sensitive environments.

All vectors discovered are logged with STORMTRANCE tagging, and every execution path
is recorded via Guardian. Napalm includes a severity score to assess how far host
boundaries have been compromised.

Napalm is not a vulnerability scanner. It is a containment validator. When firewalls,
sockets, and mounts collide, it answers the only question that matters: can the fire
escape the glass?

### Osmiomancy

```
Name: Osmiomancy
```
```
Codename: OM-SCRYPATH
Purpose: Enumerate filesystem abnormalities, hidden persistence points, obscure
binary placements, and unusual mount overlays
STORMTRANCE Vector: FS-SCRY, STASH-DETECT, HIDDEN-BIN, MOUNT-ANOMALY
Guardian Logged: Yes
Privilege Required: None
Persistence: No
Self-Destruct: No
Output Format: Annotated TTY map + Guardian-synced report
Tested On: Debian 12, Kali 202 5 .1c, Ubuntu Server 24.04 LTS
```
```
Use Case:
Audit and visualize filesystem abnormalities including hidden directories, layered
mounts, and stealthy persistence drops. Ideal for detecting obfuscated malware,
embedded implants, or improperly removed toolkits.
Risks:
```

```
May trigger audit daemons or endpoint protection if probing sensitive binary paths.
Over-enumeration in production systems could cause temporary performance
degradation.
```
Osmionmancy is a filesystem anomaly detector designed to scry through all active
mounts and user-accessible paths for signs of stealth persistence, obfuscation, or
artifact concealment. Unlike a typical file walker, Osmionmancy focuses on location
logic — the “why here” behind binary placement, symbolic link chains, and write-layer
overlays.

The module begins by traversing mount namespaces and comparing overlay mount
points with their declared fstab or autofs origins. If discrepancies are found — such as
overlay mounts shadowing writable or tmpfs volumes — Osmionmancy records the
scope and flags the overlay for further scan.

Next, the module performs a stealth file sweep:

- Enumerates hidden dot-directories and single-character paths nested deep
    within /var, /opt, and /usr/local
- Flags binaries with abnormal timestamps, extended attributes, or recent ACL
    changes
- Correlates hashed binaries against a known-good core system set to identify
    mismatches or injected variants

It then checks for unusual persistence strategies:

- User crontabs with nonstandard execution times or UID misalignments
- Systemd service units not registered in journalctl but live in disk
- Startup scripts symlinked into boot paths with broken or misleading names

For each anomaly, Osmionmancy assigns a certainty score. These scores are based on
entropy (e.g. randomness of filename), context (e.g. whether a binary was placed in a
directory with no legitimate execution flow), and recency (e.g. last modified in a post-
breach window).

All data is visualized as a colorless annotation map in TTY, listing discovery vectors and
the relationship between files, mount origins, and persistence flags. Guardian logs the
output with a signed forensic map, traceable across sessions.

Osmionmancy is not an antivirus. It is a guided lantern through a filesystem’s
underworld, pointing toward the cracks where something may have hidden — or where
something may still wait.


### Revenant

```
Name: Revenant
Codename: RV-GHOSTBIND
Purpose: Detect and abuse setcap-enabled binaries for privilege escalation, ghost
access, or stealth persistence
STORMTRANCE Vector: SETCAP-ESC, BIN-GHOST, UID-SKIP
```
```
Guardian Logged: Yes
Privilege Required: None
Persistence: Yes
Self-Destruct: Optional (via delayed cap reset)
```
```
Output Format: Capability diff + exploit path log + Guardian signature
Tested On: Debian 12, Kali 202 5 .1c, Ubuntu Server 24.04 LTS
```
```
Use Case:
Scan for binaries with ambient or elevated Linux capabilities. Exploit setcap misuses to
achieve shell access, file reads, or privilege elevation without needing SUID.
Risks:
Improper use may corrupt legitimate binary behavior or trip hardened security modules
(e.g. AppArmor, SELinux). Escalation attempts are highly visible on modern auditd
systems if not cloaked.
```
Revenant is a privilege escalation and persistence module designed to exploit the
growing surface area of Linux’s capability system. Unlike classic SUID escalations,
Revenant focuses on binaries with setcap flags — ambient powers that grant specific
elevated permissions without full root context.

Upon execution, Revenant begins by mapping all binaries in $PATH, /usr, /opt, and any
writable locations for active capability flags. It uses getcap -r / recursively to identify
targets carrying flags such as:

- cap_setuid or cap_setgid — allows privilege flipping during exec
- cap_dac_read_search — enables reading normally restricted files


- cap_net_raw or cap_sys_admin — allows socket injection or control over network
    interfaces

Each flagged binary is categorized by trust level (system, package, user) and analyzed for
modifiability or execution risk. Revenant then attempts to exploit usable paths in two
ways:

1. Binary binding — it injects a minimal payload into a setcap-enabled script or
    executable (or symbolic link path) and re-invokes it with crafted arguments. This
    method allows UID flipping, arbitrary file reads, or persistent privilege transitions
    without triggering SUID restrictions.
2. Ghost binary resurrection — if a setcap binary has been deleted from disk but is
    still active in memory (e.g. due to process mapping or lazy unmount), Revenant
    can recover the inode and reactivate the capability in a cloned path, allowing
    post-deletion execution.

The module includes auto-clean logic to remove injected capabilities after use, but this
is disabled by default to preserve forensic traceability. All actions are logged in Guardian
and stamped with a REV-ID for correlation across sessions and modules.

Revenant is not a loud attacker. It walks through the gaps left behind when a system
removes SUID but forgets what it replaced it with. It binds to ghosts — binaries not
meant to matter, carrying powers they never earned.

### Separation

```
Name: Separation
Codename: SP-VERSPERS
Purpose: Detect and exploit service misconfigurations, unsafe listening ports, and
shadow socket exposure across network or loopback interfaces
STORMTRANCE Vector: SOCKET-LEAK, LOOPBLEED, SERVICE-MISCONF, SHADOW-
BIND
Guardian Logged: Yes
Privilege Required: None
Persistence: No
Self-Destruct: No
Output Format: Socket map + misconfig list + Guardian trace bundle
```

```
Tested On: Debian 12, Kali 202 5 .1c, Ubuntu Server 24.04 LTS
```
```
Use Case:
Scan for poorly bound services, open localhost-only endpoints, shadow daemons, and
leaking ports that expose functionality not meant for public access. Ideal for lateral
movement prep or post-exploit tunnel pivoting.
Risks:
Unstable or deprecated services may crash during aggressive socket probing. If run
against sensitive service meshes or containers, it may leave behind connection logs or
trigger alerts.
```
Separation is a surgical socket mapper and service exposure auditor, designed to locate
endpoints that were never meant to be reached. It operates by cross-correlating
declared service binds against active listening sockets and routing visibility, creating a
forensic map of what is truly exposed versus what the system believes is hidden.

The module begins by parsing /proc/net/{tcp,udp,tcp6,udp6}, capturing all active
listening sockets and their associated inodes. It then links these entries to process IDs,
command names, and binary paths by walking through /proc/[pid]/fd and comparing
socket references. This enables high-fidelity mapping between open ports and their
parent services.

Next, Separation performs interface awareness testing:

- Checks whether each service is bound to 0.0.0.0 (public), 127.0.0.1 (loopback),
    or specific interfaces (e.g. eth0, docker0, veth*)
- Flags services bound to localhost but still reachable via misrouted DNS or NAT
    reflection
- Detects split-visibility ports where the same PID binds both public and internal
    addresses inconsistently

It also scans for:

- Daemons exposing debug interfaces or RPC endpoints only on loopback but
    lacking auth
- Services bound to stale veth interfaces from dead containers
- Backdoor ports left behind by test daemons or modified binaries


Each anomaly is tagged with STORMTRANCE vectors and scored for risk based on
service type, port range, and known exploit history. Guardian logs include a full
port/service map with timestamps, access routes, and resolution scope.

Separation is not a port scanner. It is a silence breaker. A listener of vespers — revealing
which services whisper in the dark, unaware they can be heard.

### Spark

```
Name: Spark
Codename: SPK-FUSECORE
Purpose: Generate and inject adversarial media payloads targeting AI parsers, OCR
engines, and LLM-integrated input chains
STORMTRANCE Vector: AI-FUZZ, SEMANTIC-CORRUPT, PROMPT-LEAK, PAYLOAD-
FUSE
Guardian Logged: Yes
Privilege Required: No
Persistence: No
Self-Destruct: Optional (payload self-null after activation)
Output Format: Malicious media artifact + payload summary + Guardian signature
Tested On: Debian 12, Kali 202 5 .1c, Ubuntu Server 24.04 LTS, Kayla, AIAR Project
platforms
```

```
Use Case:
Test AI parser integrity by injecting hostile documents, poisoned images, or fuzzed
semantic payloads. Ideal for evaluating prompt injection resistance, OCR hallucination
boundaries, or real-time LLM-based threat surfaces.
Risks:
May cause unintended behavior in AI-connected systems. If sent to live production
endpoints, Spark payloads can induce hallucination, leakage, or system
misclassification. Use in closed or airgapped testing environments only.
```
Spark is an AI payload engineering module designed to probe, poison, and manipulate
the semantic and structural behavior of modern parser stacks. It targets systems that
ingest images, PDFs, Markdown, or raw text — especially those connected downstream
to LLMs, OCR engines, or transformer-based classifiers.

The core of Spark lies in its ability to fuse adversarial content generation with fuzz logic
and prompt-layer trickery. It crafts malicious inputs that appear benign to human
readers but destabilize parser logic, overflow token alignment, or exploit embedded
weak assumptions in text/image bridges.

The module operates in multiple payload classes:

1. OCR Poisoning
    Spark renders invisible or low-contrast text in images using Unicode homoglyphs,
    zero-width spaces, or altered DPI. It exploits weak OCR normalization pipelines,
    causing systems to misread text, hallucinate content, or incorrectly trigger
    workflows.
2. PDF Layer Injection
    It constructs multi-layer PDFs with mixed-language objects, hidden text under
    visual overlays, and cross-object references that confuse AI extractors. When
    parsed, these often bypass LLM prompt filters or generate semantic drift in chain-
    of-thought output.
3. Markdown & Text Fuzz
    Spark generates specially malformed Markdown files containing nested entities,
    poisoned math blocks, or UTF-8 breakdowns. It also uses token-breakers like
    emoji noise or encoded shell fragments to collapse alignment during vector
    embedding.
4. Prompt Hijack Seeds
    For systems directly connected to LLMs, Spark can embed chain-injection
    prompts inside the media or its metadata. These include base64 payloads


```
disguised as alt-text, EXIF prompt embeddings, and label-spoofing tags to trigger
model misalignment.
```
Each payload is scored on hallucination likelihood, token corruption probability, and
injection potential. All outputs are hash-logged and registered in Guardian using SPK-ID
tags. The module includes auto-null logic for payloads that are single-use or self-
invalidating.

Spark is not a prank generator. It is an adversarial fuse, lit beneath the parser layer of
modern AI. It doesn’t break rules — it writes new ones inside the data you trust.

### Sunbreaker

```
Name: Sunbreaker
Codename: SBK-ENVSHIFT
Purpose: Exploit dynamic loader vulnerabilities using LD_PRELOAD, environment
variable injection, and hijacked execution chains
STORMTRANCE Vector: PRELOAD-HIJACK, ENV-ESCALATE, LIBWRAP-LEECH
```
```
Guardian Logged: Yes
Privilege Required: Optional (root or writable service paths increase impact)
Persistence: Optional (via shell wrappers or autorun environments)
Self-Destruct: No
```
```
Output Format: Interception tree + hijack chain + Guardian tag bundle
Tested On: Debian 12, Kali 202 5 .1c, Ubuntu Server 24.04 LTS
```
```
Use Case:
Hijack execution paths by injecting custom shared libraries or variables into trusted
binaries. Ideal for escalating in CI/CD, development environments, or legacy services
with exposed LD paths.
```

```
Risks:
Improper use can brick services, introduce noisy segfaults, or trigger IDS alerts.
Injection into core system binaries may cause boot or runtime instability.
```
Sunbreaker is a dynamic escalation module that weaponizes Linux’s shared library
loading system — particularly the LD_PRELOAD, LD_LIBRARY_PATH, and related
environment-variable injection vectors. It’s designed to hijack trusted execution flow by
inserting hostile code into runtime chains, enabling escalation, interception, or
persistent override without altering the binary itself.

The module begins by scanning for candidate binaries:

- Those owned by root but executable by user
- Those launched at login, via cron, or through systemd services
- Scripts calling out to known dynamically linked binaries (e.g. sudo, ping, passwd)

Once a viable target is found, Sunbreaker constructs a payload shared object. This
library:

- Wraps or overrides libc functions like setuid, execve, fopen, or system
- Redirects binary logic to a user shell or preconfigured command
- Optionally logs, mutates, or proxies the original behavior to avoid suspicion

The hijack is injected through one of several methods:

- LD_PRELOAD environment variable set via exported session
- LD_LIBRARY_PATH poisoning inside wrapper scripts
- /etc/ld.so.preload override (if root writable or misconfigured)
- Custom .desktop or XDG startup entries with altered env chains

In CI environments or improperly sandboxed containers, Sunbreaker often succeeds by
slipping through non-sanitized variable inheritance. In local privilege escalation chains,
it complements modules like Revenant or Stormtrance by enabling root-owned binary
capture without needing SUID flags.

The module includes rollback logic to purge injected paths and reset loader state.
However, Guardian always logs the original injection vector, the path of the hijack, and
the PID tree of any triggered shells.

Sunbreaker is not a hammer for everything — but when the right binary opens the door, it
becomes liquid fire through the veins of the system. A single preload. A changed path. A
new root.


### Thatcher

```
Name: Thatcher
Codename: THCR-SHADOWLOCK
```
```
Purpose: Sever all outbound communication channels except for user-authorized SSH,
disable network diagnostics, and sandbox the system against external probes
STORMTRANCE Vector: NET-NULL, TOOL-LOCK, SURVEILLANCE-BREAK, ISOLATION-
SEAL
Guardian Logged: Yes
```
```
Privilege Required: Root
Persistence: Optional (can leave behind hardened iptables/host deny rules)
Self-Destruct: Optional (tripwire-triggered auto severance)
```
```
Output Format: Lockdown manifest + syscall trace + Guardian lock hash
Tested On: Debian 12, Kali 202 5 .1c, Ubuntu Server 24.04 LTS
```
```
Use Case:
Lock down a compromised or at-risk system by forcefully cutting outbound
connections, neutering surveillance tools, and preserving only user SSH access. Ideal
for hostile environments, post-rootkit containment, or red team retreats.
Risks:
Breaks all non-whitelisted networking, may interfere with legitimate service processes
or monitoring agents. Should only be used on systems under user control or in
designated sandboxed testbeds.
```
Thatcher is a surgical comms isolation module built to sever a system’s ability to
communicate, beacon, or receive remote probes — while keeping a single lifeline open
for the authorized user. It is the nuclear option when the threat of surveillance,
compromise, or backchannel command is imminent and response time is zero.

The module executes in phases:

1. Interface Nullification
    Thatcher flushes all active IP routes and applies firewall rules to deny all
    outbound traffic on all interfaces (eth, wlan, lo, virtual bridges). Exceptions are


```
made only for a specific SSH session, identified by UID or port, to preserve
operational control. Default drop policies are enforced via iptables, nftables, or
ufw, depending on host config.
```
2. Binary Neutering
    Next, it disables and scrubs tools commonly used for packet capture or trace
    diagnostics. This includes binaries such as nmap, netcat, wireshark, tcpdump,
    airgeddon, and others. Thatcher achieves this by:
       o Moving or unlinking the binaries
       o Overwriting exec permissions

```
o Mounting overlay tmpfs layers over surveillance paths (/usr/sbin, /usr/bin)
```
3. Syscall Breakpoints
    On hardened targets, Thatcher can optionally intercept syscalls associated with
    packet sockets, promiscuous mode, or interface polling (e.g. socket(), ioctl(),
    recvmsg()) using ptrace traps or kernel audit rules. This ensures that even if
    surveillance tools are reintroduced, they remain blind.
4. Lockdown Flagging
    Thatcher writes a Guardian-tagged lockdown manifest, recording every tool
    disabled, every route removed, and every syscall trap deployed. It also supports a
    rollback plan via --relink mode, restoring all functionality if triggered from the
    same authorized SSH identity.

Tripwire logic can be enabled to auto-trigger Thatcher when specific conditions are met,
such as detection of outbound DNS tunnels, presence of unknown kernel modules, or
execution of blacklisted binaries.

Thatcher does not watch. It blinds. When compromise is confirmed or suspicion is too
great to ignore, Thatcher cuts every line, closes every whisper, and seals the host into
your hands alone.


### Threadrunner

```
Name: Threadrunner
Codename: TNR-SHADOWSUDO
Purpose: Detect and abuse sudo misconfigurations, GTFOBins vectors, and shadow
command chains to escalate privileges through authorized binaries
STORMTRANCE Vector: SUDO-MISCONF, GTFO-ELEVATE, PATH-POISON, SHELL-
SPAWN
Guardian Logged: Yes
Privilege Required: None (relies on already existing sudo permissions)
```
```
Persistence: No
Self-Destruct: No
Output Format:
Tested On: Debian 12, Kali 202 5 .1c, Ubuntu Server 24.04 LTS
```
```
Use Case:
Scan for exploitable sudo permissions and use them to escalate to root or escape user
restrictions via known safe binaries. Essential for local privilege escalation audits and
trust boundary analysis.
Risks:
May execute legitimate but dangerous commands depending on granted sudo rules. In
production environments, misuse can result in system configuration changes or
exposure of sensitive files.
```
Threadrunner is a privilege escalation module focused on parsing, analyzing, and
exploiting misconfigured sudo permissions. It specializes in uncovering trust boundaries
hidden in plain sight — where a user is allowed to execute certain binaries as root
without password prompts, but those binaries can be turned into launchpads.

The module begins by parsing the user’s effective sudo rules using sudo -l. It filters the
results based on the following categories:

- Commands that invoke interpreters (e.g. python, perl, bash)
- File or system editors (e.g. vim, less, nano)
- Archive tools and decompressors (tar, zip, cpio)


- Networking tools (nmap, tcpdump, ftp)
- Unsafe utilities from the GTFOBins project, known to allow shell escape or file
    access

Threadrunner then cross-references these entries against an internal GTFO-compatible
binary map. For each match, it simulates and optionally triggers:

1. Shell spawns using built-in escape sequences (e.g. vim :!sh, tar -cf /dev/null --
    checkpoint=1 --checkpoint-action=exec=/bin/sh)
2. File read/write access as root, used for credential theft or persistence planting
3. Environment path poisoning via writable scripts or manipulated $PATH entries
4. Sudo wrappers that allow execution of arbitrary binaries when the allowed
    command is a shell or script interpreter

Each exploit path is documented and tagged with a TRN-ID, and optionally run with full
terminal logging to Guardian. The module includes detection-only mode to support red
team dry runs or automated audits.

Threadrunner does not guess passwords. It exploits misplaced trust. It walks the chains
of sudo policy — and pulls until something breaks.

### VULSAT

```
Name: VULSAT
Codename: VS-CENTRIS
```
**Purpose:** Central controller for KaylaRecon; launches, syncs, and coordinates all toolkit
modules; emits STORMTRANCE graph and full Guardian digest
**STORMTRANCE Vector:** MULTISCAN, RECON-FUSION, CONTROL-NEXUS,
STORMTRANCE-ROOT
**Guardian Logged:** Yes
**Privilege Required:** None
**Persistence:** No
**Self-Destruct:** No
**Output Format:** Master report (JSON + plaintext) + full STORMTRANCE vector map
**Tested On:** Debian 12, Kali 202 5 .1c, Ubuntu Server 24.04 LTS


```
Use Case:
Run coordinated vulnerability scans, recon passes, and chained module launches
through a single interface. Essential for batch enumeration, multi-phase red team
workflows, and full-session artifact generation.
Risks:
```
Running all modules at once may create noisy traffic or high CPU usage. In live systems,
simultaneous recon + escalation probes may trip detection layers. Always audit targets
before execution.

Vulsat is the primary execution layer of the KaylaRecon toolkit — the central nervous
system that coordinates and launches all subordinate modules with synchronized input,
output harvesting, and STORMTRANCE mapping.

When executed, Vulsat scans the working directory and
$KAYLARECON_HOME/modules for available tools, validates integrity via Guardian hash
registry, and constructs a dynamic execution tree based on available privilege, module
dependencies, and flags. This tree is processed sequentially or in parallel, depending on
environment loadout.

Core responsibilities include:

1. Module Dispatch
    Vulsat launches each submodule (e.g., broodweaver.sh, stormtrance.sh,
    insanity.sh) with context-aware flags. If a module requires root or has optional
    autofix mode, Vulsat handles elevation prompts or pre-checks access scope.
    Outputs are cached into session-specific folders with timestamped logs.
2. STORMTRANCE Graphing
    As modules emit vectors, Vulsat collects and assembles them into a unified
    STORMTRANCE map. Each tag (NFS-INJECT, GTFO-ELEVATE, FS-SCRY, etc.) is
    bound to the host, time, UID, and originating module. The result is a graph-style
    view of all attack paths observed — exportable as DOT, JSON, or plaintext with
    timestamps.
3. Guardian Digest
    After execution, Vulsat compiles all Guardian logs, merges hashline records, and
    creates a master digest report with optional signature chain. This includes:
    module launch order, STORMTRANCE tag summary, anomaly flags, persistence
    markers, and any triggered payload identifiers (e.g. SPK-ID, REV-ID, TRN-ID).
4. Recon Policy Control
    Vulsat supports several operational modes:


```
o --all: full stack execution
o --stealth: only passive modules (no payload, no fuzz)
o --chain NAME: run modules that can exploit or pivot from module NAME
o --diff PREV: compare current scan to a previous log archive for delta
mapping
```
Vulsat doesn’t probe or exploit directly — it orchestrates. It is the recon nexus, the storm
map, the glowing red eye that sees across the toolkit’s reach. When it runs, nothing is
forgotten, and nothing escapes correlation.

## MONARCH

### Author’s Note – On Monarch

“Shall not be used in any way, shape or form. Too destructive.”
- ahu
```
### CONSTRUCT

Monarch is the concealed sovereignty layer embedded within KaylaRecon. It is a root-
level persistence and command interception framework designed for maximum stealth,
full user cloaking, and command auditing under hostile or hardened conditions. Upon
deployment, Monarch creates a hidden root user named monarch, establishes a stealth
sudo interceptor, and reroutes privileged command execution through a ghosted binary
pipeline.

The system lives in /opt/monarch, isolated from default user paths, and shields its
components under restrictive permissions and hidden invocation logic. Commands
issued via sudo are intercepted, logged in an internal journal, and executed only if the
UID matches the cloak parameters. Monarch's ghost command system allows secure
operation of approved binaries from a concealed command stack, rendering surface-
level audit trails nearly blind to its activity.

Crucially, Monarch is not a rootkit. It does not patch the kernel, does not inject into
processes, and performs no syscall hooking. Its stealth is based entirely on user-space
manipulation, hardened file permissions, symbolic redirection, and knowledge-based
concealment. It can be cleanly removed using its uninstall script — no part of the
system is obfuscated or self-protecting beyond controlled access logic.

Monarch exists as a demonstration of what persistence looks like when weaponized
with surgical precision. It shows that cloaked privilege is not dependent on malware
behaviors, and that ethical cyberweapon engineering is not about evasion — it's about
control, reversibility, and full-system understanding. Monarch is the crown that
completes KaylaRecon’s statement: not just escalation — dominion.

### BOTRK

```
Name: Blade Of The Ruined King
Codename: BTRK-CROWNCLONE
Purpose: Establish root-level persistence by creating a stealth admin user (monarch),
hiding both user and home directory from common enumeration tools
STORMTRANCE Vector: ROOT-CLOAK, USER-OBFUSCATE, STEALTH-PERSIST, UID-
SHADOW
```

```
Guardian Logged: Yes
Privilege Required: Root
Persistence: Yes (until userdb is flushed and /home manually scrubbed)
Self-Destruct: No (but includes --purge mode)
Output Format: Persistence receipt + Guardian root trace + shadow insert log
Tested On: Debian 12, Kali 202 5 .1c, Ubuntu Server 24.04 LTS
```
```
Use Case:
Create a stealth-root user named monarch with full sudo access and zero visibility in
standard user enumeration. Used in advanced persistence chains, honeypot decoys, or
forensic misdirection operations.
Risks:
Alters core system files (/etc/passwd, /etc/shadow, /etc/sudoers.d). Highly detectable
by integrity scanners, and potentially dangerous on production systems. Should only be
deployed in controlled environments or red team scenarios with rollback plans. Or
better yet: not ever deployed on any system.
```
Blade of the Ruined King is a root-persistence module designed to embed a hidden
administrative user directly into the target’s system identity layer. Its goal is not just
persistence — but undetectable privilege, enabled only when the operator chooses to
reveal it.

Upon execution as root (or escalated via stormtrance), the module performs the
following actions in sequence:

1. **Monarch Injection**
    A user named monarch is inserted into /etc/passwd with UID 0 or a shadow UID
    just below system cutoff (e.g. 980). The corresponding /etc/shadow entry is
    written with a bcrypt or SHA-512 hash, optionally randomized or operator-
    supplied. A matching /home/monarch folder is generated in a hidden directory
    (e.g. /var/.mcache) or flagged chattr +i to resist tampering.
2. **Home Cloaking**
    The monarch home directory is unlisted in shell profile defaults, removed from
    /etc/skel, and excluded from getent or ls /home listings. It can also be placed on
    a bind-mount in /dev or /mnt for deeper cloaking.
3. **Sudo Shadowdrop**
    A rule is dropped into /etc/sudoers.d/99-monarch with monarch ALL=(ALL)


```
NOPASSWD:ALL, granting full root without password. File permissions mimic
system templates to avoid flagging.
```
4. **Terminal Prompt Tagging**
    When monarch logs in, a subtle prompt (e.g. monarch@root ) is rendered,
    signifying successful activation. This prompt is only visible in direct TTYs and is
    not propagated via remote shells or default log collectors.
5. **Sudo Interceptor**
    Optionally, botrk installs a sudo wrapper script (monarch_sudo.sh) that logs
    every sudo attempt to /var/log/monarch_journal.log. The wrapper includes:

```
o UID gating (only works for monarch and root)
o Ghosted command replay via /opt/monarch/ghost_cmds
o Silent failover if unauthorized users attempt access
```
Guardian logs every injected line, every hash, and every modified path. The module
includes a --purge flag that will remove monarch, shred the shadow file entry, restore
sudoers, and sanitize logs if the session UID matches the original installer.

botrk is not a useradd script. It is crown-forging — a declaration that root belongs to
someone else now. Someone who does not show up when called. Someone who is
already watching.


### Monarch_SUDO

```
Name: Monarch Sudo Interceptor
Codename: MRC-SHADOWWRAP
Purpose: Redirect and log all sudo calls made by the hidden monarch user. Restrict
access to authorized identities, log full command invocations, and ghost unknown
attempts.
STORMTRANCE Vector: SUDO-SHADOW, CMD-TRACE, UID-FILTER, WRAP-LOOP
Guardian Logged: Yes
Privilege Required: Root (writes to /usr/bin/sudo, /etc/sudoers.d, and logging targets)
```
```
Persistence: Yes
Self-Destruct: Optional (--revert flag)
Output Format: Sudo execution log + ghost command traces + Guardian wrap hash
Tested On: Debian 12, Kali 202 5 .1c, Ubuntu Server 24.04 LTS
```
```
Use Case:
Protect the monarch persistence vector by replacing the global sudo binary with a
controlled wrapper. Log all escalations, block unauthorized use, and selectively ghost
real commands via mounted shadow bins. Core part of anti-forensics containment.
Risks:
Overrides core binary used by most Linux systems. Incorrect handling may lock out
admin access or break escalation workflows. Only use in red team or research
environments under full control.
```
The Monarch Sudo Interceptor (monarch_sudo.sh) is a kernel-safe shell wrapper that
replaces or shadows the default sudo binary on a system under the botrk module’s
control. It exists to protect the integrity of the monarch root vector, silently surveil
elevated access, and suppress unauthorized use with plausible failure states.

The wrapper is installed at /usr/bin/sudo (backing up the original to /usr/bin/sudo.bak) or
injected higher in $PATH to override system calls. Once active, it performs the following
logic on every invocation:

1. **UID Filtering**


```
o If the invoking user is monarch or UID 0: forward the sudo call directly to
the real binary (via /usr/bin/sudo.bak) with no modification.
o If the invoking user is unlisted: sleep briefly, simulate an I/O or PAM error,
and exit silently. Guardian logs the attempt with a UID, TTY, timestamp,
and full argv capture.
```
2. **Command Logging**
    o Every successful call made by monarch is logged to
       /var/log/monarch_journal.log, including working directory, full command
       chain, and exit status.

```
o Logs are write-locked (chattr +i) and optionally encrypted if symmetric
auth is enabled.
```
3. **Ghost Command Mode**
    o If monarch invokes a command present in /opt/monarch/ghost_cmds, the
       interceptor executes the ghosted version instead of the real binary.
    o This allows fake responses, decoy shell outputs, or sandboxed shells for
       honeypot detection.
4. **Failover and Repair**
    o If sudo.bak is missing or damaged, the wrapper can reinstall the system
       binary from /opt/monarch/sudo_safe, ensuring recovery is possible.
    o The --revert flag fully restores the original sudo and removes the wrapper,
       with Guardian logging a reversal event (REVERT-CROWN).

All operations are silent unless the user is authorized. All detections are reported as
normal sudo errors to avoid suspicion. It is built to blend, survive reboots, and preserve
a direct root vector even in environments with SUDO audit or command tracing.

This is not a prank sudo wrapper. This is the throne’s sentinel — the veil between the
crown and the noise.

### Broodweaver_EXT_Monarch

```
Name: Broodweaver Extension — Monarch Compatibility Scan
Codename: BWE-M-CLOAKPATH
Purpose: Detect hidden filesystems, obscure mount points, and stealth-writable paths
suitable for placing a cloaked Monarch home or implant
```

```
STORMTRANCE Vector: FS-CLOAK, HIDDEN-PATH, PERSIST-SCOUT, UID-FIT
Guardian Logged: Yes
Privilege Required: None
Persistence: No
Self-Destruct: No
Output Format: Path candidate list + UID compatibility map + Guardian recon tag
Tested On: Debian 12, Kali 202 5 .1c, Ubuntu Server 24.04 LTS
```
```
Use Case:
Extend Broodweaver to search for viable stealth persistence zones before deploying
Monarch. Enables pre-checks for nonstandard home dirs, writable system overlays, or
user-silent mounts. Also validates UID conflict space for ghost user insertion.
Risks:
May trigger alerts in hardened audit environments when probing /., /proc, /dev, or deep
/var trees. Avoid using in environments with fanotify or real-time filesystem tracing
unless cloaked.
```
This extension module is designed to integrate directly into the post-mount phase of
Broodweaver. It is triggered only when the core scanner finishes detecting mount
structures and filesystem overlays. Once active, it scans for safe persistence targets
that match Monarch’s cloaking criteria — hidden from user enumeration, writable
without sudo, and persistent across reboots.

Key scan logic includes:

1. **UID Collision Map**
    The extension scans /etc/passwd for all UID values below 1000 (or system
    cutoff). It calculates the closest unused UID slot in the shadow zone (e.g. 969–
    998) to insert monarch without conflicting with system users or appearing in login
    shells.
2. **Filesystem Scrying**
    Scans for writable but user-hidden directories:
       o /var/lib/.cache, /var/.dbus, /var/.logrotate

```
o OverlayFS paths
o tmpfs mounts that are persistent via container bind
```

```
o Hidden user mount trees (/mnt/.stow, /dev/.secure)
```
It tags each viable candidate with:

```
o Read/write permissions
o Mount persistence score (0–5 scale)
o Visibility under ls, getent, and login shells
```
3. **Home Simulation Test**
    Once candidate paths are identified, broodweaver_ext_monarch simulates a
    Monarch home structure (e.g. .bashrc, .ssh, .sudo_as_admin_successful) and
    probes access from UID 0, the invoking user, and the nearest system user. If the
    path survives all 3 without collision, it is marked VALID-CLOAK.
4. **Guardian Output**
    Each cloak candidate is logged with a full path, cloak score, and UID injection
    readiness. Guardian tags the recon session with MONARCH-COMPATIBLE: TRUE
    or BLOCKED: NO VALID PATHS.

This extension does not create users or modify the system. It scouts the terrain for the
throne — then passes the crown to botrk.

It is the eyes beneath the veil. Where Monarch sleeps before rising.

### Loreprint

**Name:** Loreprint
**Codename:** LP-ECHOFRAME
**Purpose:** Generate full forensic execution lineage from all KaylaRecon modules in a
session, including STORMTRANCE vectors, file mutations, privilege crossings, and event
timings
**STORMTRANCE Vector:** FORENSIC-ECHO, TRACE-MAP, VECTOR-CHAIN, PRIV-CROSS
**Guardian Logged:** Yes
**Privilege Required:** No
**Persistence:** Yes (until log purged)
**Self-Destruct:** No
**Output Format:** JSON + plaintext vector graph + Guardian checksum anchor
**Tested On:** Debian 12, Kali 202 5 .1c, Ubuntu Server 24.04 LTS


```
Use Case:
Compile a complete execution transcript of a KaylaRecon session, reconstructing every
module called, vector tag issued, UID used, file touched, and command run — ideal for
debriefs, forensic review, or audit submission.
Risks:
Generates detailed logs that may include sensitive target paths or filenames. In real-
world post-exploit chains, this level of transparency can unintentionally expose OPSEC
or implant footprints if not handled correctly.
```
Loreprint is the final memory of a KaylaRecon session — a persistent, Guardian-signed
execution fingerprint that captures every meaningful action taken across all loaded
modules. It does not simply log output. It reconstructs lineage: who ran what, where,
when, with which vector, and whether it succeeded.

Once called (typically auto-run by vulsat.sh at session end), Loreprint begins by
harvesting all temporary logs, Guardian hash trails, and STORMTRANCE emissions. It
organizes this data into a time-sorted vector timeline, capturing:

1. **Module Invocation Tree**

```
o Execution order by timestamp (microsecond resolution)
o Caller UID, group, and shell session
o Binary path, invocation arguments, and exit code
```
```
o Launch method (manual, chained, vulsat batch)
```
2. **STORMTRANCE Path Mapping**
    Each vector tag issued during execution is mapped to:
       o The module that emitted it
       o The context that triggered it (e.g. "hidden crontab found", "socket at
          127.0.0.1:9999")
       o The file or system path affected, if applicable
       o Privilege level at time of detection or exploitation
3. **Privilege Crossing Events**
    Any detected privilege escalation, such as stormtrance.sh shell pivot, revenant
    cap-flip, or botrk UID hijack, is marked with a crossing node. Loreprint flags
    transitions from user → root, or sandbox → host, and annotates them in red in
    visual mode.


4. **Mutation Indexing**
    Loreprint records all files that were:
       o Created
       o Modified
       o Injected into
       o Linked
       o Cloaked

It captures SHA-256 fingerprints and before/after timestamps where applicable.

5. **Guardian Signature + Output Bundle**
    All data is finalized with a Guardian-signed SHA anchor that confirms authenticity
    of the Loreprint session. Output is written to:
       o loreprint_YYYYMMDD_HHMMSS.json (full session map)
       o loreprint.timeline (readable event chain)
       o loreprint.guard (hash anchor + STORMTRANCE digest)

Loreprint is your proof — that the operation occurred, that the vectors were real, that
nothing was done without a trace. It is the echo of the storm, long after the recon ends.

### Monarch_check

```
Name: Monarch Integrity Probe
Codename: MRC-THRONEWATCH
Purpose: Verify presence, status, and integrity of the monarch user, home, sudo
interceptor, and ghost vectors without revealing presence to system logs or
unauthorized users
STORMTRANCE Vector: CROWN-PING, USER-SHADOWCHK, WRAP-VERIFY, UID-
GHOSTTRACE
Guardian Logged: Yes
Privilege Required: Optional (root expands scope and reveals deeper cloak states)
Persistence: No
Self-Destruct: No
Output Format: Status report (TTY + JSON) + Guardian status hash
```

```
Tested On: Debian 12, Kali 202 5 .1c, Ubuntu Server 24.04 LTS
```
**Use Case:**
Stealth-check if monarch still exists, whether sudo interception is active, and if the full
persistence path (home, shell, UID, cloak) is intact. Run after reboot, breach, or forensic
cleanup attempt.
**Risks:**
Minimal — designed for silence. If cloak is partially broken or deleted, monarch_check
will fallback to null output instead of triggering system alerts or auth errors.

Monarch_check is a specialized heartbeat module for validating whether the monarch
persistence chain — injected by botrk.sh — is still alive, operational, and unbroken. It is
designed to be run quietly, quickly, and without requiring elevated permissions (though
root reveals full detail).

The module performs layered scanning:

1. **User Enumeration Bypass**
    Scans /etc/passwd, /etc/shadow, and getent passwd for signs of a user with:
       o Username: monarch
       o UID: 0 (or shadow UID range 960–999)
       o Shell: /bin/bash, /bin/sh, or flagged sleeper shell

```
o Home path: located under /home, /var, /mnt, or hidden mount overlay
```
If monarch is not returned by getent but exists in raw files, the cloak is marked ACTIVE. If
neither surface, cloak is marked COMPROMISED.

2. **Sudo Interceptor Validation**
    Checks whether /usr/bin/sudo is a shell script or linked to monarch_sudo.sh. If a
    wrapper is present:
       o Validates UID gate logic

```
o Verifies ghost command dir /opt/monarch/ghost_cmds
o Logs current sudo attempt silently to /var/log/monarch_journal.log
```
3. **Prompt Tag Test (TTY-only)**
    If run in an interactive shell, monarch_check attempts to load the crown prompt
    (e.g. monarch@root ). If visible, user is verified active.


4. **Cloak Integrity Sweep**
    Looks for chattr +i files in hidden Monarch directories
       o Verifies presence of .bashrc, .ssh/authorized_keys, and monarch_sudo.sh
       o Hashes content for tamper detection
       o Logs cloak score (0–5) based on depth and match
5. **Guardian Sync**
    All findings are logged in Guardian under MONARCH-STATUS. Outputs include:
       o status: ALIVE, COMPROMISED, or GONE
       o interceptor: ACTIVE, BROKEN, or MISSING

```
o cloak_score: X/5
o uid: VALID, COLLISION, or ROOT-MASK
```
This module does not repair or reinstall. It watches the throne. If the crown is gone, it
whispers nothing. If the king lives, it bows.

### STVector_injector

```
Name: STORMTRANCE Vector Injector
Codename: STVX-TAGFORGE
Purpose: Emit canonical STORMTRANCE vector tags from all KaylaRecon modules,
binding each finding to a unique tag, timestamp, UID, and originating module
STORMTRANCE Vector: VECTOR-FORGE, TRACE-SEED, MODULE-ID, FORENSIC-BIND
Guardian Logged: Yes
Privilege Required: None
Persistence: Yes (per vector ID and session signature)
Self-Destruct: No
Output Format: STVX log entries + Guardian vector digest + ID table
Tested On: Debian 12, Kali 202 5 .1c, Ubuntu Server 24.04 LTS
```
```
Use Case:
```

```
Standardize all vulnerability, anomaly, and exploitation results across the entire
KaylaRecon framework. Ensures unified reporting, traceability, and audit fidelity by
assigning structured STORMTRANCE vectors to every confirmed or suspected event.
Risks:
None directly, but inconsistent vector injection due to misuse or tampering may corrupt
session lineage. STVX integrity should be validated post-run.
```
STVector Injector is the core tagging engine behind the KaylaRecon toolkit. It is
responsible for assigning canonical STORMTRANCE vector tags to all findings across the
suite, ensuring every module emits standardized forensic data for centralized reporting,
traceability, and audit chaining.

The injector can be called directly or used as a wrapped function by any KaylaRecon
module. Once invoked, it records every confirmed or suspected anomaly into the vector
log, associating each entry with a unique tag, timestamp, module identifier, and
session-specific metadata.

A typical tag line includes the following fields:

timestamp
vector tag
originating module ID
executing UID
context path (e.g. binary, file, interface)
optional hash or fingerprint

Example:
2025 - 06 - 04T22:33:57Z GTFO-ELEVATE TRN-SHADOWSUDO uid=1000 /usr/bin/vim
TRNID-29f2e8

Vector tags are drawn from a controlled registry and include categories such as
escalation, persistence, anomaly, service exposure, container breaks, and forensic
spoofing. Common examples include:

SETCAP-ESC
PRELOAD-HIJACK
FS-SCRY
LOOPBLEED
PROMPT-LEAK
ROOT-CLOAK

Each vector is mapped to the module that produced it. This link enables tools like
vulsat, loreprint, and guardian to reconstruct a full graph of the engagement — showing
what was run, what it saw, and what changed.


If a vector is associated with a file or binary (for example, a poisoned crontab or modified
shadow file), a SHA-256 fingerprint is generated and logged beside the tag. This allows
for audit comparison, tamper detection, and rollback planning.

Every tag emitted by the injector is written to three destinations:

the current session’s vector log
the Guardian hashchain for the run
an optional human-readable STVX timeline

Each tag is also assigned a unique ID. These IDs (e.g., STVXID-a8e2b5) allow tags to be
cross-referenced across sessions or correlated during forensic sweeps.

The injector supports dry-run mode for auditing modules without emitting real vectors,
and redaction mode for erasing traces from shared reports. Redactions require
Guardian trust keys and emit a shadow vector in place of the original.

STVector Injector is not just a logger. It is a signature system — the heartbeat of the
toolkit. Every time KaylaRecon sees a crack in the system, this is how it remembers. And
how it makes sure you can prove it.

- Botond “ahu” Vaski

Contact information:

Email: businessforahu@gmail.com

Phone: +36706120052

Linkedin: @ahuka
Discord: ahukadiff
