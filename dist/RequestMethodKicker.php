<?php
namespace Coercive\Security\BotKicker;

/**
 * BOT KICKER
 *
 * @package		Coercive\Security\BotKicker
 * @link		https://github.com/Coercive/BotKicker
 *
 * @author  	Anthony Moral <contact@coercive.fr>
 * @copyright   2018 Anthony Moral
 * @license 	MIT
 */
class RequestMethodKicker extends AbstractKicker
{
	const COERCIVE_FILE = __DIR__ . '/../list/method/coercive';

	/**
	 * RequestMethodKicker constructor.
	 *
	 * @return void
	 */
	public function __construct()
	{
		$method = (string) filter_input(INPUT_SERVER, 'REQUEST_METHOD', FILTER_SANITIZE_FULL_SPECIAL_CHARS);
		if($method) {
			$this->setInputList([$method]);
		}
	}

	/**
	 * @return $this
	 */
	public function loadCoerciveList(): RequestMethodKicker
	{
		$this->setBlackListFromFiles([self::COERCIVE_FILE]);
		return $this;
	}
}
