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
class RefererKicker extends AbstractKicker
{
	const DEFAULT_FILES = [
		self::CHONGQED_FILE,
		self::COERCIVE_FILE,
		self::PERISHABLE_FILE
	];

	const CHONGQED_FILE = __DIR__ . '/../list/referer/chongqed';
	const COERCIVE_FILE = __DIR__ . '/../list/referer/coercive';
	const PERISHABLE_FILE = __DIR__ . '/../list/referer/perishable';

	/**
	 * RefererKicker constructor.
	 */
	public function __construct()
	{
		$referer = $_SERVER['HTTP_REFERER'] ?? '';
		$this->currents = $referer ? [$referer] : [];
		$this->default = self::DEFAULT_FILES;
	}
}
