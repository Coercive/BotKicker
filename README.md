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

Warning info
------------

Some terms where placed in ambiguous list because of too large detection. You can find this ambiguous file are in each list directory. (work in progress)

Load
----
```php
use Coercive\Security\BotKicker;

# Get Instance
$bot = new UserAgentKicker;
// or $bot = new RefererKicker;

# Detect bot
if(!$bot->detect()->getStatus()) {
	die;
}

# You can set your own list
$bot->setBlackList([
	'bad',
	'bad too'
]);
$bot->setWhiteList([
	'good',
	'good too'
]);

# Or from file (txt brut format)
$bot->setBlackListFromFiles([
	'/path/file1',
	'/path/file2'
]);
$bot->setWhiteListFromFiles([
	'/path/file1',
	'/path/file2'
]);

# You can override base detection
$bot->setCurrent('this is my current referer');

# You can (dis)allow empty current detection
$bot->allowEmpty( true | false );

```
