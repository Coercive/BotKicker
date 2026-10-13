CHANGELOG
=========

0.1.0
-----

Breaking changes :

 * All concrete classes are now `final` (`AbstractKicker` and `AbstractLookUp` stay extendable)
 * Automatic inputs are read from `$_SERVER` instead of `filter_input(INPUT_SERVER)` (which may return null under FastCGI)
 * `HostLookUp::CMD` / `NsLookUp::CMD` : the host is escaped with `escapeshellarg()`, the `%s` is no longer quoted (custom `AbstractLookUp` children must remove their quotes too)
 * `AbstractLookUp::match()` / `matchNative()` : the domain must match on a label boundary (`crawl.evilgooglebot.com` no longer matches `googlebot.com`), case insensitive
 * `UrlKicker` : the query string is removed before decoding and trimming (`/page/?a=1` gives `/page`, was `/page/`)
 * `AbstractKicker::getDataFromFiles()` : a file that can not be opened is skipped (the whole list was returned empty), keys are reindexed

Other changes :

 * Compatible PHP 7.4 → 8.5 (requires PHP >= 7.4)
 * `strict_types`, `self` return types
 * Fix : `addToInputList()` added the items to the blacklist
 * Fix : `getDataFromFiles()` split the lines longer than 255 characters
 * Fix : `getFromASN()` shell injection with the ASN parameter, duplicate ranges removed
 * Fix : `getGoogle*List()` warning when the download fails (5 seconds timeout, as for Bing)
 * Fix : `getPayboxList()` duplicate IPs
 * Fix : `UrlKicker::find()` required ext-mbstring
 * Fix : `ModSecLogParser` lost a transaction when its `Z` separator was directly followed by the next transaction or by the end of file
 * Fix : `ModSecLogParser` took the `X-Forwarded-Host` (or any `*Host:` header) as host
 * Fix : `ModSecLogParser` IPv6 client address, lowercase method, HTTP/2 protocol, IPv6 host in `filterAccessByIp()`
 * Fix : `SyslogUfw` always threw "Can't read line" at the end of a file ending with a new line ; empty lines are skipped
 * Fix : `SyslogUfwEntity::isBlocked()` always true when ports were found (ports compared as strings)
 * README updated (removed methods `getCurrents()`, `setCurrents()`, `isBing()`)
 * PHPUnit tests

0.0.81
------

 * IpKicker: add Monetico ip range
