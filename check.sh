#!/bin/sh
# PHP2Shell (CVE-2026-109618, CVE-2026-109619) version check for the PHP command line on this server.
# It only reads versions and php.ini settings: nothing is sent anywhere and nothing is changed.
#
# Usage: sh check.sh
# The PHP your website runs can differ from the command line: also open a phpinfo() page and paste it into
# https://fbuff.com/tools/php2shell-checker/ (then delete the phpinfo file).

# Fixed upstream releases (October 21, 2026). Keep in sync with https://fbuff.com/tools/php2shell-checker/
FIXED_8_2=8.2.35
FIXED_8_3=8.3.36
FIXED_8_4=8.4.27
FIXED_8_5=8.5.12

if ! command -v php >/dev/null 2>&1; then
  echo "php not found on PATH. Paste your phpinfo() into https://fbuff.com/tools/php2shell-checker/"
  exit 2
fi

version_ge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n 1)" = "$2" ]; }

v=$(php -r 'echo PHP_VERSION;')
branch=$(echo "$v" | cut -d. -f1,2)
echo "PHP (command line): $v"

verdict=
case "$branch" in
  8.2) fixed=$FIXED_8_2 ;;
  8.3) fixed=$FIXED_8_3 ;;
  8.4) fixed=$FIXED_8_4 ;;
  8.5) fixed=$FIXED_8_5 ;;
  *) fixed= ;;
esac

# Distributions backport the fix without changing PHP_VERSION, so read the package too.
pkg=
if command -v dpkg-query >/dev/null 2>&1; then
  pkg=$(dpkg-query -W -f '${Version}' "php$branch-common" 2>/dev/null)
  [ -n "$pkg" ] && echo "Package php$branch-common: $pkg"
elif command -v rpm >/dev/null 2>&1; then
  if rpm -q --changelog php-common 2>/dev/null | grep -q 109618; then
    echo "Package php-common: changelog mentions CVE-2026-109618 (fix backported)"
    verdict=patched
  elif rpm -q php-common >/dev/null 2>&1; then
    echo "Package php-common: $(rpm -q php-common) (no CVE-2026-109618 in changelog)"
  fi
fi

if [ -z "$verdict" ]; then
  case "$branch" in
    5.*|7.0|7.1|7.2|7.3) verdict="NO FIX" ;;
  esac
fi
if [ -z "$verdict" ] && [ -n "$fixed" ] && version_ge "$v" "$fixed"; then verdict=patched; fi
if [ -z "$verdict" ] && [ -n "$pkg" ]; then verdict="CHECK PACKAGE"; fi
if [ -z "$verdict" ] && [ -n "$fixed" ]; then verdict=VULNERABLE; fi
[ -n "$verdict" ] || verdict="CHECK PACKAGE"

echo "Verdict: $verdict"
case "$verdict" in
  VULNERABLE) echo "Update to PHP $fixed or newer, then restart PHP-FPM / Apache." ;;
  "NO FIX") echo "PHP $branch gets no fix: move to PHP 8.2 or newer." ;;
  "CHECK PACKAGE") echo "Your distribution may have backported the fix. Compare the package with the table in README.md or paste phpinfo() into https://fbuff.com/tools/php2shell-checker/" ;;
esac

up=$(php -r 'echo ini_get("session.upload_progress.enabled") ? "On" : "Off";')
echo "session.upload_progress.enabled: $up"
[ "$up" = On ] && [ "$verdict" != patched ] && echo "Until you update, set session.upload_progress.enabled = 0 in php.ini or the FPM pool and restart workers."

[ "$verdict" = patched ] && exit 0
exit 1
