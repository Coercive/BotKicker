<?php
namespace Coercive\Security\BotKicker;

/**
 * NsLookUp
 *
 * @package		Coercive\Security\BotKicker
 * @link		https://github.com/Coercive/BotKicker
 *
 * @author  	Anthony Moral <contact@coercive.fr>
 * @copyright   (c) 2023 Anthony Moral
 * @license 	MIT
 */
class NsLookUp extends AbstractLookUp
{
	const CMD = 'nslookup -timeout=%d -retry=%d "%s"';

	const REGEX_DOMAIN = '`^[a-z0-9\._-]+\sname\s*=\s*(?P<domain>[a-z0-9\._-]+\.)$`';

	const REGEX_ADDRESS = '`^Address:\s*(?P<ip>[a-z0-9\.:]+)$`';

	/**
	 * NsLookUp constructor.
	 *
	 * @return void
	 */
	public function __construct()
	{
		$this->nsLookUpHeaders = true;
	}
}