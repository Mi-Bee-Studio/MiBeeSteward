# Home Assistant add-on sources (#622)

This directory is the source pack for the standalone **add-on repository**
(`Mi-Bee-Studio/hassio-addons`): copy `mibee-steward/` and add a repository
`README.md`/`repository.json` there; the add-on image wraps the GHCR release
image with the `run.sh` entrypoint that maps HA options onto the center's
`MIBEE_*` env.

Key decisions (mirroring the issue constraints):

- **host_network: true** — a scanner is only as good as its LAN reach;
  ICMP/ARP/mDNS/SSDP need the physical segments the HA box sits on.
- **State on /data** — HA's managed volume; the config and SQLite database
  survive add-on updates (`/data/steward/`).
- **Secrets are options, blanks are secure defaults** — an empty
  `master_key` disables the v3 credential vault rather than inventing a weak
  key; an empty `jwt_secret` derives a stable per-install value so sessions
  survive restarts without the user managing one; the admin password is
  always created via the browser first-run setup.
- **Relationship to the distributed shape**: an HA-box center covers the LANs
  the box bridges. Multiple segments still want one agent per segment
  reporting to this center — see the distributed docs.
