# PHP2Shell checker (CVE-2026-109618, CVE-2026-109619)

Check whether the PHP on your server is affected by **PHP2Shell** (CVE-2026-109618 and CVE-2026-109619), and which version or distribution package fixes it.

**Paste `php -v` or your phpinfo() in the browser instead:** https://fbuff.com/tools/php2shell-checker/ (runs locally, nothing is uploaded)

## What it is

PHP2Shell is the name for two critical bugs in PHP itself, published on October 21, 2026:

- **CVE-2026-109618:** memory corruption when PHP runs out of memory while setting up a request.
- **CVE-2026-109619:** state left over from one request reused by the next request on the same worker.

Both are rated 9.2 and can let an attacker run code on a web server without logging in. Attacks were seen in the wild from October 21. Every PHP setup that serves web pages is in scope: PHP-FPM, Apache mod_php, php-cgi, LiteSpeed and FrankenPHP.

## Fixed versions

| PHP branch | Fixed in |
|---|---|
| 8.2 | 8.2.35 |
| 8.3 | 8.3.36 |
| 8.4 | 8.4.27 |
| 8.5 | 8.5.12 |
| 7.4, 8.0, 8.1 | Source backports only; use a patched distribution build or upgrade |
| 7.3 and older | No fix |

Distributions backport the fix under their own numbers:

| System | Fixed package |
|---|---|
| Ubuntu 26.10 | php8.5 8.5.9-0ubuntu2.1 |
| Ubuntu 26.04 LTS | php8.5 8.5.4-0ubuntu1.5 |
| Ubuntu 24.04 LTS | php8.3 8.3.6-0ubuntu0.24.04.13 |
| Ubuntu 22.04 LTS | php8.1 8.1.2-1ubuntu2.28 |
| Debian 12 bookworm | php8.2 8.2.35-1~deb12u1 |
| Debian 13 trixie | php8.4 8.4.27-1~deb13u1 |
| AlmaLinux 9 (php:8.2 stream) | php-8.2.33-1.module_el9.8.0+327+37dfd4b4.alma.1 |

On Red Hat, AlmaLinux and Rocky, the PHP number stays the same; check the changelog: `rpm -q --changelog php-common | grep 109618`.

## Check from the command line

```sh
curl -fsSLO https://raw.githubusercontent.com/fbuff-tools/php2shell-checker/main/check.sh
sh check.sh
```

The script reads `PHP_VERSION`, the installed `php-common` package (dpkg or rpm) and `session.upload_progress.enabled`, prints a verdict and exits with 1 unless PHP is patched. It only reads versions and settings; nothing is sent or changed.

The command line and the website can run different PHP builds. Also check the web one: put `<?php phpinfo();` in a file in the site folder, open it, paste the page into the [online checker](https://fbuff.com/tools/php2shell-checker/), then delete the file.

## Fix

1. **Look for signs of compromise first**, since updating does not remove a backdoor: PHP files changed since October 20 (`find /var/www -name '*.php' -newermt 2026-10-20`), crashed PHP workers, new cron entries, users or SSH keys.
2. **Update PHP:** `sudo apt update && sudo apt upgrade` (Ubuntu, Debian) or `sudo dnf upgrade 'php*'` (AlmaLinux, Rocky, RHEL), or pull the fixed Docker tag.
3. **Restart every PHP worker** (`sudo systemctl restart php8.3-fpm`, or Apache for mod_php). Old workers keep running vulnerable code.

If you cannot update straight away, set `session.upload_progress.enabled = 0`, keep `post_max_size` small and limit request size at the web server. This reduces the risk; it does not remove it.

## Sources

- [PHP advisory GHSA-w8hw-w9fx-j79w (CVE-2026-109618)](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
- [PHP advisory GHSA-6wmf-4rv5-p3rp (CVE-2026-109619)](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
- [Ubuntu USN-8948-1](https://ubuntu.com/security/notices/USN-8948-1)
- [Debian security tracker](https://security-tracker.debian.org/tracker/CVE-2026-109618)
- [AlmaLinux: PHP2Shell patched packages](https://almalinux.org/blog/2026-10-21-php2shell-cve-2026-109618-cve-2026-109619/)
- [UK NCSC: Critical security issue affecting PHP](https://www.ncsc.gov.uk/news/critical-security-issue-affecting-php)

Related: [HTTP2Shell checker](https://github.com/fbuff-tools/http2shell-checker) for CVE-2026-111497 in Brotli, Node.js and Python.

Information as of October 25, 2026. MIT license. Made by [fbuff](https://fbuff.com).
