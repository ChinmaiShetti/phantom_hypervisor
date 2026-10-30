# PHANTOM: Faculty Demonstration Script (about 12 minutes)

## Before the session (5 minutes beforehand)

```powershell
cd C:\Users\chinm\Desktop\phantom_hypervisor
docker compose down -v                 # clean slate (deletes old demo data)
docker compose up -d --build
docker compose ps                      # phantom-server must show (healthy)
Get-Content .env | Select-String ADMIN # note the admin secret
```

Open three windows side by side:
1. Browser at `http://localhost:8000` (the dashboard)
2. PowerShell running `docker compose logs -f phantom-client` (live protected-app log)
3. PowerShell for commands

If you are using the cloud deployment, open `https://<app>.onrender.com/health` a minute
early to wake the free instance.

---

## 1. Architecture and containers (2 minutes)

> "PHANTOM is a miniature DRM and anti-tamper system. There are two containers on a private
> Docker bridge network: a license server and a protected client application."

```powershell
docker compose ps
docker network inspect phantom-net --format "{{range .Containers}}{{.Name}} {{.IPv4Address}}{{println}}{{end}}"
docker volume ls | Select-String phantom
docker image ls | Select-String phantom
```

Points to make:
* The client talks to `http://phantom-server:8000`. That name comes from Docker's DNS, not `localhost`.
* Only the server publishes a port. The client is unreachable from outside.
* **Containers are not VMs.** Point at the client log line `kernel=...microsoft-standard-WSL2`.
  Both containers share one kernel, the one in Docker Desktop's WSL2 VM.

## 2. Licensing with digital signatures (3 minutes)

Dashboard: paste the admin secret and click **Unlock admin**.

1. **Generate test license** (30 days). Point at the claim chips: ID, product, licensee, expiry, key fingerprint.
   > "The server signed this with its Ed25519 private key. The client only has the public key."
2. Click **Copy**, then in the command window:
   ```powershell
   docker compose exec phantom-client python -m client.main activate <paste>
   ```
   Within 20 seconds the client log shows: offline signature OK, integrity OK, online OK,
   `APPLICATION RUNNING [ONLINE]`. The *Protected Clients* card turns green.
3. **Verify license** shows **ACCESS GRANTED · VALID**.
4. **Forge license**: the dashboard edits the expiry to the year 2100 and keeps the old signature,
   which gives **ACCESS DENIED · BAD_SIGNATURE** and a critical event.
   > "Changing one byte breaks the signature. Without the private key, a valid license cannot be forged."
5. **Expired license** gives `EXPIRED`. **Garbage key** gives HTTP 400 `MALFORMED`.

## 3. Revocation (1 minute)

In **License Registry**, click **Revoke** on the license the client is using.
Within one check interval the client log shows `REVOKED` and then `APPLICATION LOCKED`, and the client card turns red.
> "The signature is still valid offline. Revocation needs the online check, which is why DRM phones home."

Re-issue and activate a fresh license so the client is green again.

## 4. Integrity and tamper detection (2 minutes)

Dashboard **Integrity Lab**:
1. **Run integrity check** shows PASS and the trusted vs. observed SHA-256 values.
2. **Modify file** shows `MODIFIED`, with the observed hash in red. The status card says TAMPERED and the Tampering alerts count goes up.
3. **Delete file** shows `MISSING`. **Inject file** shows `UNEXPECTED`.
4. **Restore** shows PASS again.

The same thing on the real client container:
```powershell
docker compose exec phantom-client python -m client.main tamper
docker compose exec phantom-client python -m client.main check     # LOCKED: MODIFIED
docker compose exec phantom-client python -m client.main restore
```
> "The reference hashes are themselves signed by the server, so an attacker can't just edit the manifest."

## 5. Server outage and recovery (2 minutes)

```powershell
docker compose stop phantom-server
```
* The dashboard shows **SERVER OFFLINE**.
* The client log shows `server unreachable` and then **RUNNING [OFFLINE-GRACE]**, and after about 60 s, `LOCKED: grace period expired`.

```powershell
docker compose start phantom-server
```
* The dashboard shows "License server is back online". The client log returns to **RUNNING [ONLINE]**.
* The data survived, because the SQLite database is on a Docker **volume**.

## 6. Debugger detection, simulated (30 seconds)

```powershell
docker compose exec -e PHANTOM_SIMULATE_DEBUGGER=1 -e DEBUGGER_POLICY=block phantom-client python -m client.main check
```
The output is `LOCKED: debugger detected`, and the dashboard shows an ENVIRONMENT warning event.
> "Real anti-debug checks are trivially patched when the attacker owns the machine. Commercial
> tools only raise the cost. Our README lists these limitations."

## 7. CI/CD and cloud (1 to 2 minutes)

* Show the GitHub **Actions** tab: test, then config validation, then Docker build and smoke test.
* Show Render: Docker runtime, free plan, environment variables (secret values hidden), auto-deploy after checks pass.
* Open `https://<app>.onrender.com`. It is the same dashboard, served over HTTPS from the cloud.
* Explain the trade-off: Render's free disk is ephemeral. Licenses still verify after a restart
  because they are self-contained signed tokens, and persistent revocations come from an env var.

## Likely questions

| Question | Answer |
|---|---|
| Is Docker a hypervisor? | No. Containers are isolated processes on a shared kernel (namespaces and cgroups). Docker Desktop on Windows runs one WSL2 VM to provide a Linux kernel. |
| Why Ed25519 and not a shared key (HMAC)? | With a shared key, every client could also *create* licenses. Asymmetric keys let clients verify but not sign. |
| Can PHANTOM be cracked? | Yes, by removing the checks from the client code. Every client-side protection, Denuvo included, can be defeated eventually; it only adds time and cost. |
| What if the database is lost? | Licenses are self-verifying (stateless mode). Revocations can also be supplied via `PHANTOM_REVOKED_LICENSES`. Durable cloud storage would need PostgreSQL. |
| How is the admin endpoint protected? | Secret header with a constant-time compare, a rate limit of 30/min per IP, logged failures, and HTTPS on Render. |
