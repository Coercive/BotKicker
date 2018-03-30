<?php
namespace Coercive\Security\BotKicker;

/**
 * BOT KICKER
 *
 * @package		Coercive\Security\BotKicker
 * @link		@link https://github.com/Coercive/BotKicker
 *
 * @author  	Anthony Moral <contact@coercive.fr>
 * @copyright   2018 Anthony Moral
 * @license 	MIT
 */
class RequestMethodKicker extends AbstractKicker
{
	const DEFAULT_FILES = [
		self::COERCIVE_FILE
	];

	const COERCIVE_FILE = __DIR__ . '/../list/method/coercive';

	/**
	 * RequestMethodKicker constructor.
	 */
	public function __construct()
	{
		$method = (string) filter_input(INPUT_SERVER, 'REQUEST_METHOD', FILTER_SANITIZE_FULL_SPECIAL_CHARS);
		$this->currents = $method ? [$method] : [];
		$this->default = self::DEFAULT_FILES;
	}
}
