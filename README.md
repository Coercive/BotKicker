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

# Or from file
$bot->setBlackListFromFiles([
	'/path/file.json',
	'/path/file.yml',
	'/path/file.yaml'
]);
$bot->setWhiteListFromFiles([
	'/path/file.json',
	'/path/file.yml',
	'/path/file.yaml'
]);

# You can override base detection
$bot->setCurrent('this is my current referer');

# You can (dis)allow empty current detection
$bot->allowEmpty( true | false );

```