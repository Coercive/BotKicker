!!!!!!!!!!!!!!!!!!!!!!!!!!
==========================
WARNING : WORK IN PROGRESS
==========================
!!!!!!!!!!!!!!!!!!!!!!!!!!
==========================

Coercive Security BotKicker
===========================

A simple detection based on black list

Get
---
```
composer require coercive/botkicker
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

Kicker system
-------------

Basics

```php
use  Coercive\Security\BotKicker\UserAgentKicker;

# Get Instance
$kicker = new UserAgentKicker; // or othe kicker

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

HostKicker only
---------------

You can detect host name from an ip list

```php
# HostKicker only
$kicker = new HostKicker;

# Set your ip list
$kicker->setHostFromIp( [
	'xxx.xx.xx.x',
	'yy.yyy.y.y',
	'...',
] );
```

You can use the auto IP detection from IpKicker

```php
# Get auto Ip list detection
$list = (new IpKicker)->getCurrents();

# Set auto ip list
$kicker = new HostKicker;
$kicker->setHostFromIp($list);
```

Trigger on custom element
-------------------------

```php
# Example of custom datas
$datas = ['bot1', 'bot2', 'bot3'];

# Override auto detection
$kicker->setCurrents($datas);

# Show detection result
$status = $kicker->detect();
var_dump( $status->getList() );
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

Or from file (txt brut format)
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

Handle custom elements to verify
--------------------------------

```php
# Example of custom datas
$datas = ['bot1', 'bot2', 'bot3'];

# Override auto detection
$kicker->setCurrents($datas);

# Show detection result
$status = $kicker->detect();

var_dump( $status->getStatus() ); # bool if ok or not
var_dump( $status->getList() ); # array list of match elements
var_dump( $status->getCurrents() ); # array current datas
```