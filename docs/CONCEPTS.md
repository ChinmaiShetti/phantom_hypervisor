# Skill Lab Concept Mapping

Legend: **Implemented** means it is working code or configuration in this repository and can be
shown live. **Explained** means it is covered through comparison or documentation only, not built.

## Cloud Computing

| Concept | Status | Where / how |
|---|---|---|
| Cloud computing | Implemented | License server runs on Render's public cloud, reachable over the internet |
| PaaS | Implemented | Render is a PaaS: we supply a Dockerfile, and Render provisions compute, networking, TLS and health checks |
| SaaS | Implemented (conceptually) | The hosted license and verification API plus dashboard is consumed as a service by clients ("licensing as a service") |
| IaaS | Explained | EC2 or Compute Engine would require us to manage the VM, OS, Docker and firewall ourselves (see AWS table) |
| Public cloud | Implemented | Render's shared multi-tenant infrastructure; public HTTPS endpoint |
| Cloud deployment | Implemented | `render.yaml` Blueprint plus Docker runtime, deployed from GitHub |
| Resource provisioning | Implemented / Explained | Free instance type in `render.yaml`; CPU and memory limits in `docker-compose.yml`. Autoscaling is explained only |

## Virtualization

| Concept | Status | Where / how |
|---|---|---|
| Virtual machines | Explained, and observed | Docker Desktop's WSL2 utility VM. The client logs `hypervisor_flag=True` and the WSL2 kernel |
| Hypervisors | Explained | README section 5.1 (Type 1 vs. Type 2). Docker is explicitly **not** a hypervisor |
| Isolation | Implemented | Separate containers, private bridge network, no client ports, read-only filesystems, non-root users |
| Resource allocation | Implemented | `deploy.resources.limits` (cgroups): server 0.5 CPU / 256 MB, client 0.25 CPU / 128 MB |
| Virtualization vs. containerization | Explained, and demonstrated | Both containers report the *same* kernel version, which shows the shared kernel |

## Docker

| Concept | Status | Where |
|---|---|---|
| Images | Implemented | `phantom-server`, `phantom-client` (`python:3.12-slim`) |
| Containers | Implemented | `docker compose ps` |
| Dockerfiles | Implemented | `server/Dockerfile`, `client/Dockerfile` (layer caching, non-root, HEALTHCHECK) |
| Docker Compose | Implemented | `docker-compose.yml` |
| Bridge networks | Implemented | `phantom-net`; DNS by service name `phantom-server` |
| Port mapping | Implemented | `8000:8000` (server only) |
| Volumes | Implemented | `phantom-server-data`, `phantom-client-data` |
| Environment variables | Implemented | `.env` / `.env.example`, compose interpolation |
| Lifecycle | Implemented | build, up, ps, logs, stop/start, down; `restart: unless-stopped` |

## AWS / Cloud Concepts (explained by analogy)

| AWS concept | PHANTOM equivalent | Status |
|---|---|---|
| EC2 (virtual servers) | Render web instance / a container. EC2 gives you a whole VM to manage; a container packages only the app | Explained |
| S3 (object storage) | Docker volumes locally. On Render the disk is ephemeral, so durable state needs external storage (S3 for files, RDS/Postgres for records) | Explained |
| IAM / access management | `X-Admin-Secret` for admin APIs; the private key is held only by the server; the client gets only the public key (least privilege) | Implemented (simplified) |
| Security Groups | Only port 8000 is published; the client exposes no ports; the bridge network is private; Render exposes only HTTPS | Implemented (analogy) |
| Regions / AZs | Render lets you pick a region; multi-AZ redundancy is not used on the free tier | Explained |

## Networking

| Concept | Status | Where |
|---|---|---|
| HTTP | Implemented | Client to server inside `phantom-net` |
| HTTPS | Implemented (Render) | TLS terminated by Render's proxy; `--proxy-headers` used for real client IPs |
| REST APIs | Implemented | 11 JSON endpoints, correct status codes, OpenAPI at `/docs` |
| IP addresses | Implemented | Docker assigns container IPs on the bridge (`docker network inspect phantom-net`); rate limiting is per IP |
| Ports | Implemented | Uvicorn on 8000, mapped host:container, `$PORT` on Render |
| Client-server communication | Implemented | Online verification, manifest download, integrity reporting |
| Firewall configuration | Explained / analogy | Unpublished ports are unreachable from the host; on a VM you would use ufw or Security Groups |

## Linux

| Concept | Status | Where |
|---|---|---|
| Linux environments | Implemented | Both containers run Debian (slim) Linux on the WSL2 kernel |
| Shell commands | Implemented | `docker compose exec phantom-client sh`, `ls -l /data`, `cat /proc/self/status` |
| Permissions | Implemented | Non-root users (uid 10001/10002), `chmod -R a-w /app`, secrets written with mode `0600`, `read_only` root FS |
| Application execution | Implemented | `ENTRYPOINT`/`CMD`, `exec uvicorn` (PID 1 receives SIGTERM for graceful shutdown) |
| /proc filesystem | Implemented | Debugger (`TracerPid`) and hypervisor (`cpuinfo`) detection |

## CI/CD

| Concept | Status | Where |
|---|---|---|
| GitHub | Implemented | Repository `ChinmaiShetti/phantom_hypervisor` |
| GitHub Actions | Implemented | `.github/workflows/ci.yml` (test, config validation, Docker build and smoke test) |
| Automated testing | Implemented | 45 pytest tests |
| Deployment pipelines | Implemented | Push to `main`, CI, Render auto-deploy after checks pass |
| Secrets management | Implemented | `.env` gitignored; Render secret env vars; production refuses to start without secrets |
| Dev vs. production environments | Implemented | `APP_ENV` switches secret handling; local Compose vs. Render |

## Cybersecurity (core of the project)

| Concept | Status |
|---|---|
| Asymmetric cryptography (Ed25519) | Implemented |
| Hashing / integrity (SHA-256) | Implemented |
| Digital signatures on licenses and manifests | Implemented |
| Authentication (admin secret, constant-time compare) | Implemented |
| Rate limiting / brute-force mitigation | Implemented |
| Revocation | Implemented |
| Security event logging and monitoring | Implemented |
| Anti-debugging / environment detection | Simulated (limitations documented) |
| Obfuscation / code virtualisation (Denuvo-style) | Explained only |
