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
class HostKicker extends AbstractKicker
{
	const DEFAULT_FILES = [
		self::COERCIVE_FILE,
	];

	const COERCIVE_FILE = __DIR__ . '/../list/host/coercive';

	/**
	 * HostKicker constructor.
	 */
	public function __construct()
	{
		$this->default = self::DEFAULT_FILES;
	}

	/**
	 * Detect host from ip list
	 *
	 * @param array $list
	 * @return $this
	 */
	public function setHostFromIp(array $list): HostKicker
	{
		foreach ($list as $ip) {
			$host = gethostbyaddr($ip);
			if($ip === $host) { continue; }
			$this->currents[] = $host;
		}
		return $this;
	}
}