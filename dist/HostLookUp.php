<?php
namespace Coercive\Security\BotKicker;

/**
 * Host (linux cmd)
 *
 * @package		Coercive\Security\BotKicker
 * @link		https://github.com/Coercive/BotKicker
 *
 * @author  	Anthony Moral <contact@coercive.fr>
 * @copyright   (c) 2023 Anthony Moral
 * @license 	MIT
 */
class HostLookUp extends AbstractLookUp
{
	const CMD = 'host -W %d -R %d "%s"';

	const REGEX_DOMAIN = '`^[a-z0-9\._-]+\s+domain name pointer\s+(?P<domain>[a-z0-9\._-]+\.)$`';

	const REGEX_ADDRESS = '`^[a-z0-9\._-]+\.?\s+has (?:IPv6 )?address\s+(?P<ip>[a-z0-9\.:]+)$`';
}