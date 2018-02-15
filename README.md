Coercive Security Xss
=====================

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
$bot = new BotKicker;

# Detect bot
if(!$bot->detect()->getStatus()) {
	die;
}

# You can set your own list
$bot->setCustomReferers([
	'bad',
	'badtoo'
]);
$bot->setCustomUserAgents([
	'bad',
	'badtoo'
]);

# Or from file
$bot->setReferersFromFiles([
	'/path/file.json',
	'/path/file.yml',
	'/path/file.yaml'
]);
$bot->setUserAgentsFromFiles([
	'/path/file.json',
	'/path/file.yml',
	'/path/file.yaml'
]);

# You can override base detection
$bot->setReferer('this is my current referer');
$bot->setUserAgent('this is my current user agent');

```