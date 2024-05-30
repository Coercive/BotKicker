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
class UserAgentKicker extends AbstractKicker
{
	const AMBIGUOUS_FILE = __DIR__ . '/../list/useragent/ambiguous';
	const COERCIVE_BLACK_FILE = __DIR__ . '/../list/useragent/coercive_black';
	const COERCIVE_GRAY_FILE = __DIR__ . '/../list/useragent/coercive_gray';
	const COERCIVE_WHITE_FILE = __DIR__ . '/../list/useragent/coercive_white';
	const MITCHELLKROGZA_FILE = __DIR__ . '/../list/useragent/mitchellkrogza';
	const PERISHABLE_FILE = __DIR__ . '/../list/useragent/perishable';

	/**
	 * UserAgentKicker constructor.
	 *
	 * @return void
	 */
	public function __construct()
	{
		$agent = (string) filter_input(INPUT_SERVER, 'HTTP_USER_AGENT');
		if($agent) {
			$this->setInputList([$agent]);
		}
	}

	/**
	 * @return $this
	 */
	public function loadCoerciveLists(): UserAgentKicker
	{
		$this->loadCoerciveWhitelist();
		$this->loadCoerciveBlacklist();
		return $this;
	}

	/**
	 * @return $this
	 */
	public function loadCoerciveWhitelist(): UserAgentKicker
	{
		$this->setWhiteListFromFiles([self::COERCIVE_WHITE_FILE]);
		return $this;
	}

	/**
	 * @return $this
	 */
	public function loadCoerciveGraylist(): UserAgentKicker
	{
		$this->setBlackListFromFiles([self::COERCIVE_GRAY_FILE]);
		return $this;
	}

	/**
	 * @return $this
	 */
	public function loadCoerciveBlacklist(): UserAgentKicker
	{
		$this->setBlackListFromFiles([self::COERCIVE_BLACK_FILE]);
		return $this;
	}

	/**
	 * PERISHABLE PRESS ULTIMATE USER-AGENT BLACKLIST
	 *
	 * @link https://perishablepress.com/4g-ultimate-user-agent-blacklist/
	 *
	 * @return $this
	 */
	public function loadPerishableBlacklist(): UserAgentKicker
	{
		$this->setBlackListFromFiles([self::PERISHABLE_FILE]);
		return $this;
	}

	/**
	 * Mitchell Krogza | The Apache Ultimate Bot Blocker
	 *
	 * @link https://github\.com/mitchellkrogza/apache-ultimate-bad-bot-blocker/blob/master/Apache_2\.4/custom\.d/globalblacklist\.conf
	 *
	 * @return $this
	 */
	public function loadMitchellKrogzaBlacklist(): UserAgentKicker
	{
		$this->setBlackListFromFiles([self::MITCHELLKROGZA_FILE]);
		return $this;
	}
}
