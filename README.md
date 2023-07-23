# Description

This is a dyndns script to be called from your router, like a Fritz!Box, to update your records at Hetzner.
The ipv4 record is set as is, while for ipv6 only the prefix is changed and the local part stays the same.

# Setup
* Setup your server to not log the requests, to not leak the access tokens by putting this into your .htaccess file.

      SetEnvIf Request_URI "/dyndns.php$" dontlog

* [Get an access token for your zone](https://dns.hetzner.com/settings/api-token).
* Find the zone id of your record. Go to the dashboard, where you can setup dns records. 

      https://dns.hetzner.com/zone/{your acces token}
* The script won't add new records and only update existing ones. Therefor you should create the records you want to update.


Go to your router dyndns settings. The specific setup is for a Fritz!Box, you may need to modify it, to fit your router.

    https://{your.domain}/dyndns.php?zone=<username>&password=<pass>&host={www}&ipv4=<ipaddr>&prefix=<ip6lanprefix>
This is the update url, change your.server to point to your webpage and {www} to the subdomain you want to update.
Enter your access token as password and the zone id as user.
The Domain name should point at the the full domain you are updating the records for. Note that the Fritz!Box doesn't like wildcards, in that case just point to "all.{your.domain}".

You may remove \<ipv4\> or \<prefix\> to only update either ipv4 or ipv6.

# Limitations
* The creation of the new ipv6 isn't pretty and can only handle cases, where the prefix length is a multiple of 4. It works for me, but you are welcome to open a PR to fix this.
* It is slow. It takes 250ms per request for me. No dealbreaker but that could be a lot faster in other languages or in other implementations.

# License 
This script is under the MIT License and you are welcome to send PR to improve the code.