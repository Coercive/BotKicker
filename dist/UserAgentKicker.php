<?php
namespace Coercive\Security\BotKicker;

/**
 * BOT KICKER
 *
 * @package		Coercive\Security\BotKicker
 * @link		@link https://github.com/Coercive/BotKicker
 *
 * @author  	Anthony Moral <contact@coercive.fr>
 * @copyright   (c) 2018 Anthony Moral
 * @license 	MIT
 */
class UserAgentKicker extends AbstractKicker
{
	const DEFAULT_FILES = [
		self::COERCIVE_BLACK_FILE,
		self::MITCHELLKROGZA_FILE,
		self::PERISHABLE_FILE
	];

	const AMBIGUOUS_FILE = __DIR__ . '/../list/useragent/ambiguous';
	const COERCIVE_BLACK_FILE = __DIR__ . '/../list/useragent/coercive_black';
	const COERCIVE_WHITE_FILE = __DIR__ . '/../list/useragent/coercive_white';
	const MITCHELLKROGZA_FILE = __DIR__ . '/../list/useragent/mitchellkrogza';
	const PERISHABLE_FILE = __DIR__ . '/../list/useragent/perishable';

	/**
	 * UserAgentKicker constructor.
	 */
	public function __construct()
	{
		$this->current = $_SERVER['HTTP_USER_AGENT'] ?? '';
		$this->default = self::DEFAULT_FILES;
	}
}
