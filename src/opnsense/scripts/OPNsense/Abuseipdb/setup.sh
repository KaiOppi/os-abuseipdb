#!/bin/sh
# Trigger setup.php, then reload firewall so alias + rule become active.
/usr/local/bin/php /usr/local/opnsense/scripts/OPNsense/Abuseipdb/setup.php
/usr/local/sbin/configctl filter reload >/dev/null
