<?php
namespace Coercive\Security\BotKicker;

/**
 * BOT KICKER
 *
 * @package		Coercive\Security\BotKicker
 * @link		https://github.com/Coercive/BotKicker
 *
 * @author  	Anthony Moral <contact@coercive.fr>
 * @copyright   (c) 2018 Anthony Moral
 * @license 	MIT
 */
class RefererKicker extends AbstractKicker
{
	const CHONGQED_FILE = __DIR__ . '/../list/referer/chongqed';
	const COERCIVE_FILE = __DIR__ . '/../list/referer/coercive';
	const PERISHABLE_FILE = __DIR__ . '/../list/referer/perishable';

	/**
	 * RefererKicker constructor.
	 *
	 * @return void
	 */
	public function __construct()
	{
		$referer = (string) filter_input(INPUT_SERVER, 'HTTP_REFERER');
		if($referer) {
			$this->setInputList([$referer]);
		}
	}

	/**
	 * @return $this
	 */
	public function loadCoerciveList(): RefererKicker
	{
		$this->setBlackListFromFiles([self::COERCIVE_FILE]);
		return $this;
	}

	/**
	 * PERISHABLE PRESS ULTIMATE REFERRER BLACKLIST
	 *
	 * @link https://perishablepress.com/4g-ultimate-referrer-blacklist/
	 *
	 * @return $this
	 */
	public function loadPerishableList(): RefererKicker
	{
		$this->setBlackListFromFiles([self::PERISHABLE_FILE]);
		return $this;
	}

	/**
	 * URL blacklist from the chongqed.org database
	 * it is available from http://blacklist.chongqed.org/
	 *
	 * @return $this
	 */
	public function loadChongqedList(): RefererKicker
	{
		$this->setBlackListFromFiles([self::CHONGQED_FILE]);
		return $this;
	}
}
