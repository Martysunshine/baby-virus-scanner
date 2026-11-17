# Linux collectors (planned)

The Linux port produces the **same** `bvs.module/1` envelopes and `bvs.finding/1` findings as the
Windows collectors (see `docs/schema.md`). Because of that, the aggregator, the verdict logic and
the dashboard work unchanged.

**Implementation language:** Python 3 standard library, which is present on virtually every
distro. Use bash only for tiny glue.

| Module | Windows source | Linux equivalent |
|---|---|---|
| S01 persistence | Run keys, tasks, services, WMI | cron (`/etc/cron*`, `crontab -l` per user), systemd units and timers (system + `~/.config/systemd/user`), `~/.config/autostart`, `/etc/rc.local`, `/etc/profile.d`, shell rc files, `/etc/ld.so.preload`, `LD_PRELOAD`, PAM modules, kernel modules (`lsmod` vs signed), udev rules, at jobs |
| S02 processes & files | process table, MOTW, signatures | `/proc/*/exe` (deleted binaries), `/proc/*/cmdline`, files in `/tmp`, `/dev/shm`, `/var/tmp`, hidden dirs in `$HOME`, SUID/SGID binaries, recently changed binaries in `PATH`, package-manager verification (`dpkg --verify` / `rpm -Va`) |
| S03 accounts & posture | local users, RDP, RMM tools, root certs | `/etc/passwd` and `/etc/shadow` (UID 0 accounts, empty passwords), sudoers and `sudoers.d`, `authorized_keys` everywhere, sshd_config, CA bundle diff, firewall (`nft`/`iptables`/`ufw`), unattended-upgrades |
| S04 history & logs | PSReadLine, event logs | shell histories, `journalctl` (auth, sudo, sshd), `/var/log/auth.log` or `secure`, `last`/`lastb`, auditd |
| S05 AV evidence | Avast, MSRT, msert | ClamAV (`clamscan --no-summary`, report only), rkhunter/chkrootkit logs if installed |
| S06 browsers | Chrome/Edge profiles | `~/.config/google-chrome`, `~/.config/chromium`, `~/.config/microsoft-edge`, `~/.mozilla/firefox` (same parsers) |
| S07/S08 network | NetTCPConnection, firewall, Tailscale | `ss -tulpn`, `ip neigh`, `resolvectl`, `/etc/hosts`, `/etc/resolv.conf`, `upnpc -l`, `tailscale status` |
| S09/S10/S11/S12/S13 | AI tools, editors, supply chain, secrets, accounts | identical logic (same files under `~/.claude`, `~/.vscode`, `~/.npm`, venvs, `.env`, `~/.ssh`) |
