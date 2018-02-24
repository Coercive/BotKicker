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
	const DEFAULT_FILE = __DIR__ . '/../list/referer.yml';

	/**
	 * RefererKicker constructor.
	 */
	public function __construct()
	{
		$this->current = $_SERVER['HTTP_REFERER'] ?? '';
		$this->default = [self::DEFAULT_FILE];
	}

}