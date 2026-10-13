Coercive Security BotKicker
===========================

A simple detection based on black list

Get
---
```
composer require coercive/botkicker
```

Compatible PHP 7.4 → 8.5

Tests
-----
```
composer install
vendor/bin/phpunit
```

PHPUnit 12 requires PHP 8.3+ to run the tests ; the library itself still runs on PHP 7.4.

Some tests download the dynamic IP lists (Google, Bing, Facebook, LinkedIn : network and `whois` command needed), skip them with :
```
vendor/bin/phpunit --exclude-group network
```

List infos
----------

- PERISHABLE PRESS ULTIMATE USER-AGENT BLACKLIST 
https://perishablepress.com/4g-ultimate-user-agent-blacklist/

- PERISHABLE PRESS ULTIMATE REFERRER BLACKLIST 
https://perishablepress.com/4g-ultimate-referrer-blacklist/

- CHONGQED REFERER BLACKLIST 
http://blacklist.chongqed.org/

- MITCHELL KROG - BlackList file from apache set
https://github.com/mitchellkrogza

Warning info
------------

Some terms where placed in ambiguous list because of too large detection. You can find this ambiguous file are in each list directory. (work in progress)

List items are regular expressions (case insensitive, delimited by backticks).

Kicker system
-------------

| Kicker                | Automatic input (from `$_SERVER`, `$_GET`, `$_POST`) | Coercive lists                                                                                         |
|-----------------------|------------------------------------------------------|--------------------------------------------------------------------------------------------------------|
| `UserAgentKicker`     | `HTTP_USER_AGENT`                                    | `loadCoerciveLists()`, `loadCoerciveGraylist()`, `loadPerishableBlacklist()`, `loadMitchellKrogzaBlacklist()` |
| `RefererKicker`       | `HTTP_REFERER`                                       | `loadCoerciveList()`, `loadPerishableList()`, `loadChongqedList()`                                      |
| `RequestMethodKicker` | `REQUEST_METHOD`                                     | `loadCoerciveList()`                                                                                   |
| `UrlKicker`           | `REQUEST_URI` (or `SCRIPT_URL`), without query       | `loadCoerciveLists()`, `loadCoerciveGraylist()`                                                        |
| `InputKicker`         | `$_GET` and `$_POST` values                          | `loadCoerciveLists()`, `loadCoerciveGraylist()`                                                        |
| `IpKicker`            | none : use `setInputList()`                          | `loadCoerciveList()`                                                                                   |

Basics

```php
use Coercive\Security\BotKicker\UserAgentKicker;

# Get Instance
$kicker = new UserAgentKicker; // or other kicker

# Load a default list
$kicker->loadCoerciveLists();
# or load custom list...

# Basic bot detection
if(!$kicker->detect()->getStatus()) {
	echo 'a bot is detected';
}
else {
    # True if in whitelist or not in blacklist
}
```

You can detect if UA need the robots.txt

```php
if($kicker->isRobotsTxtRequested()) { /* do something */ }
```

(Dis)Allow empty
----------------

```php
# You can (dis)allow empty current detection
$kicker->allowEmpty( true | false );
```

Handle custom elements to verify
--------------------------------

```php
# Example of custom datas
$datas = ['bot1', 'bot2', 'bot3'];

# Override auto detection
$kicker->setInputList($datas);

# Or add to auto detection
$kicker->addToInputList($datas);

# Show detection result
$status = $kicker->detect();

var_dump( $status->getStatus() ); # bool if ok or not
var_dump( $status->getMatches() ); # array list of match elements
var_dump( $status->getInput() ); # string the input that match
var_dump( $status->getInputs() ); # array current datas
```

Handle custom list
------------------

You can set your own list (array format)
```php
$kicker->setBlackList([
	'bad',
	'bad too'
]);
$kicker->setWhiteList([
	'good',
	'good too'
]);
```

Or from file (txt brut format : one item per line, lines beginning with `#` are skipped)
```php
$kicker->setBlackListFromFiles([
	'/path/file1',
	'/path/file2'
]);
$kicker->setWhiteListFromFiles([
	'/path/file1',
	'/path/file2'
]);
```

If some list are already loaded, you can add some items like that
```php
$kicker->addToBlackList([
	'bad',
	'bad too'
]);
$kicker->addToWhiteList([
	'good',
	'good too'
]);
```

UrlKicker / InputKicker only
----------------------------

```php
use Coercive\Security\BotKicker\InputKicker;
use Coercive\Security\BotKicker\UrlKicker;

$url = new UrlKicker; # or new UrlKicker(false) without automatic detection
$url->setUrl('/some/url?query=1'); # cleaned to /some/url
$url->getUrl();
$url->getRawUrl();
$url->isMalformed(); # url with ellipsis "..." or ending with "/null"
$url->find('some');

$input = new InputKicker(true, false); # $_GET only
$input->isValidUtf8();
$input->containsUrl(); # the first url found or empty string
```

IpKicker only
-------------

IpKicker provides some IP / CIDR lists (static or dynamic), to use in your own firewall rules.

```php
use Coercive\Security\BotKicker\IpKicker;

$ipk = new IpKicker;

# Local files
$ipk->getBingList();
$ipk->getBrevoList();
$ipk->getCloudflareList();
$ipk->getLetsEncryptList();
$ipk->getMailjetList();
$ipk->getStripeList();

# Static
$ipk->getMoneticoList();
$ipk->getPayboxList();
$ipk->getPayPlugList();
$ipk->getProlexisList();

# Dynamic (download) : IPv4 by default, IPv6 with true
$ipk->getBingList(true); # throws RuntimeException on failure
$ipk->getGoogleBotList();
$ipk->getGoogleCloudList();
$ipk->getGoogleUserList();
$ipk->getGoogleSpecialCrawlersList();
$ipk->getGoogleUserTriggeredFetchersList();
$ipk->getGoogleUserTriggeredFetchersGoogleList();

# Dynamic (whois command)
$ipk->getFacebookList();
$ipk->getLinkedInList();
$ipk->getFromASN('AS32934'); # IPv4 and IPv6, or false (IPv4) / true (IPv6)
```

Host / Ns Look Up
-----------------

Get the domains list from IP
```php
use Coercive\Security\BotKicker\HostLookUp;
use Coercive\Security\BotKicker\NsLookUp;

$look = new HostLookUp;
# OR
$look = new NsLookUp;

$array = $look->getDomains('111.22.33.4');
```

Get the ip list from domain
```php
use Coercive\Security\BotKicker\HostLookUp;
use Coercive\Security\BotKicker\NsLookUp;

$look = new HostLookUp;
# OR
$look = new NsLookUp;

$array = $look->getIps('www.example.com.');
```

Match item
```php
use Coercive\Security\BotKicker\HostLookUp;
use Coercive\Security\BotKicker\NsLookUp;

$look = new HostLookUp;
# OR
$look = new NsLookUp;

# Match ip > domain (the domain itself or one of its subdomains)
$bool = $look->match('66.249.66.1', 'googlebot.com');

# OR match with reverse (match ip > domain first and domain > ip after)
$bool = $look->match('66.249.66.1', 'googlebot.com', true);

# OR with PHP native functions (IPv4 only, no shell command)
$bool = $look->matchNative('66.249.66.1', 'googlebot.com', true);
```

ModSecurity audit log
---------------------

```php
use Coercive\Security\BotKicker\ModSec\ModSecLogParser;

$parser = new ModSecLogParser('/var/log/apache2/modsec_audit.log');

foreach ($parser->filterUnallowedMethodRequests() as $entry) {
	echo $entry->getIp(), ' ', $entry->getMethod(), ' ', $entry->getHost(), $entry->getUri(), PHP_EOL;
}

# Also : getEntries(), search(callable), filterAccessByIp(), filterGetRequests(), filterPostRequests(), filterHeadRequests(), filterOptionsRequests()
```

UFW syslog
----------

```php
use Coercive\Security\BotKicker\Syslog\SyslogUfw;

$ufw = new SyslogUfw('/var/log/ufw.log');

foreach ($ufw->getMatches() as $ip => $entity) {
	if($entity->isBlocked()) {
		echo $ip, ' ', implode(',', $entity->getPorts()), PHP_EOL;
	}
}

# Unparsable lines
$ufw->getErrors();
```
