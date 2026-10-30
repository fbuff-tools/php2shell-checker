# PHP2Shell checker (CVE-2026-109618, CVE-2026-109619)

Understand and check **PHP2Shell**: two bugs in PHP itself (CVE-2026-109618 and CVE-2026-109619, CVSS 4.0 9.2) that let an attacker run code on a web server with ordinary HTTP requests, without logging in and without any bug in the site's own code. Find out what goes wrong, who is exposed, and which version or distribution package fixes it.

**Paste `php -v` or your phpinfo() in the browser instead:** https://fbuff.com/tools/php2shell-checker/ (runs locally, nothing is uploaded)

## What causes CVE-2026-109618: running out of memory at the wrong moment

When a request goes over `memory_limit`, PHP does not unwind step by step: it jumps straight out of whatever it was doing (`longjmp()`) and runs the request shutdown code. That is safe once a request is fully set up. The bug: the jump can also happen while PHP is still setting the request up, when some request memory is reserved but not yet initialized. Shutdown then reads and branches on that half-filled memory.

An attacker can push PHP there with a multipart POST before any script runs. PHP's advisory lists the ways: a body with no usable declared length passes the `post_max_size` check and keeps streaming; a part may carry any number of headers; empty file fields don't count toward `max_file_uploads` but still build the usual arrays; nested field names multiply the work.

It is like a fire alarm going off while the movers are halfway through unloading: whoever locks up afterwards assumes every box was put away.

**The fix** removes the jump: PHP now records a soft out-of-memory condition and stops at the next safe point, with a hard `_exit()` at a second, higher limit.

## What causes CVE-2026-109619: leftovers from the previous request

A worker serves many requests in a row and keeps some global bookkeeping that points into memory owned by the current request. When a request dies abruptly (fatal error, parse error, failed `require`, "Maximum execution time exceeded", out of memory), some of those pointers are not reset: the memory is freed, the pointers stay.

The next request on the same worker can use them before its own setup clears them. PHP names two early paths: INI warnings raised before the request starts (on Apache, `.htaccess` `php_value` lines are applied then), and **session upload progress**, which is on by default and runs even if the site never calls `session_start()`. On PHP 8.5, `fatal_error_backtraces` was the basis of the confirmed mod_php exploit.

Think of a hotel room where the previous guest's key card was left on the desk and now opens someone else's room.

## Who is exposed

Every PHP that serves web pages: PHP-FPM, Apache mod_php, php-cgi, LiteSpeed and FrankenPHP. **mod_php carries the most risk**: it runs the shutdown code even when request startup failed, and PHP validated full code execution there with default memory and input limits. On PHP-FPM, the leftover-state path was validated too; more workers only lower the odds per attempt. watchTowr reports exploitation in the wild since October 21, and Zscaler counted 1,156 attempts from 156 addresses in the first 48 hours.

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

## Look for signs of compromise first

Updating does not remove a backdoor. Copy logs, configuration and suspicious files somewhere safe, then look for:

- the web server or PHP process starting `sh`/`bash`, especially with `curl`, `wget`, `base64 -d` or `/dev/tcp`;
- PHP files changed since October 20: `find /var/www -name '*.php' -newermt 2026-10-20`;
- PHP code inside session files (`sess_*`);
- multipart POSTs with boundaries such as `shellflow-php2shell` or `--VERIFY`, and responses containing `PWNED::`;
- workers that crashed or hit the memory limit; new cron entries, users or SSH keys.

## Ways to protect a server

1. **Patch** (the only complete fix): `sudo apt update && sudo apt upgrade`, `sudo dnf upgrade 'php*'`, or pull the fixed Docker tag. Then **restart every PHP worker** (`sudo systemctl restart php8.3-fpm`, or Apache for mod_php): old workers keep running old code.
2. **Remove the triggers while you wait**, in `php.ini` or the FPM pool (not `ini_set()` or `.user.ini`, which apply too late), then restart workers:
   - `session.upload_progress.enabled = 0`
   - small `post_max_size`
   - PHP 8.5: `fatal_error_backtraces = 0`
   - `memory_limit = -1` enforced administratively: PHP's advisory names it as the main setting for CVE-2026-109618 (partial); don't cap memory with `RLIMIT_AS`/`RLIMIT_DATA`, which trigger the same jump
   - `pm.max_requests = 1` gives each request a fresh worker
3. **Limit the blast radius:** cap request size and multipart parts at the web server or WAF, fix pages that end in fatal errors or timeouts, and run PHP as a user that can't write to your code.
4. **Don't run random "exploits":** VulnCheck counted hundreds of PHP2Shell proof-of-concept repositories on GitHub, almost none real.

Hiding errors (`display_errors = Off`, `@`) does not help.

## Sources

- [PHP advisory GHSA-w8hw-w9fx-j79w (CVE-2026-109618)](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
- [PHP advisory GHSA-6wmf-4rv5-p3rp (CVE-2026-109619)](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
- [Zscaler: PHP2Shell exploitation attempts](https://www.zscaler.com/blogs/security-research/cve-2026-109618-and-cve-2026-109619-php-vulnerable-unauthenticated-rce)
- [Elastic Security Labs: PHP2Shell detection](https://www.elastic.co/security-labs/threat-command/php2shell-php-rce-detection)
- [VulnCheck: PHP2Shell vulnerabilities](https://www.vulncheck.com/blog/php2shell-vulnerabilities)
- [watchTowr: PHP2Shell FAQ](https://watchtowr.com/intelligence/php-cve-2026-109618-faq/)
- [Ubuntu USN-8948-1](https://ubuntu.com/security/notices/USN-8948-1)
- [Debian security tracker](https://security-tracker.debian.org/tracker/CVE-2026-109618)
- [AlmaLinux: PHP2Shell patched packages](https://almalinux.org/blog/2026-10-21-php2shell-cve-2026-109618-cve-2026-109619/)

Related: [HTTP2Shell checker](https://github.com/fbuff-tools/http2shell-checker), [KSMBD checker](https://github.com/fbuff-tools/ksmbd-checker), [CVE-2026-98432 checker](https://github.com/fbuff-tools/cve-2026-98432-checker).

Information as of October 30, 2026. MIT license. Made by [fbuff](https://fbuff.com).
