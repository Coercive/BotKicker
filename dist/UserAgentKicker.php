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

	/** @var string The requested script url */
	private $url = '';

	/**
	 * UserAgentKicker constructor.
	 */
	public function __construct()
	{
		$agent = $_SERVER['HTTP_USER_AGENT'] ?? '';
		$this->currents = $agent ? [$agent] : [];
		$this->url = $_SERVER['SCRIPT_URL'] ?? ($_SERVER['REQUEST_URI'] ?? '');
		$this->default = self::DEFAULT_FILES;
	}

	/**
	 * Detect if the UA request the robots.txt file
	 *
	 * @return bool
	 */
	public function requestedRobotsTxt(): bool
	{
		return false !== strpos($this->url, 'robots.txt');
	}
}
