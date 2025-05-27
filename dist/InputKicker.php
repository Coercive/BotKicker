<?php
namespace Coercive\Security\BotKicker;

/**
 * INPUT KICKER
 *
 * @package		Coercive\Security\BotKicker
 * @link		https://github.com/Coercive/BotKicker
 *
 * @author  	Anthony Moral <contact@coercive.fr>
 * @copyright   (c) 2025 Anthony Moral
 * @license 	MIT
 */
class InputKicker extends AbstractKicker
{
	const COERCIVE_BLACK_FILE = __DIR__ . '/../list/input/coercive_black';
	const COERCIVE_GRAY_FILE = __DIR__ . '/../list/input/coercive_gray';
	const COERCIVE_WHITE_FILE = __DIR__ . '/../list/input/coercive_white';

	/**
	 * InputKicker constructor.
	 *
	 * @return void
	 */
	public function __construct(bool $GET = true, bool $POST = true)
	{
		$arrays = [];
		if($GET) {
			$arrays[] = $_GET;
		}
		if($POST) {
			$arrays[] = $_POST;
		}
		if($arrays) {
			$list = self::flattenMerge($arrays);
			$this->setInputList($list);
		}
	}

	/**
	 * @return $this
	 */
	public function loadCoerciveLists(): InputKicker
	{
		$this->loadCoerciveWhitelist();
		$this->loadCoerciveBlacklist();
		return $this;
	}

	/**
	 * @return $this
	 */
	public function loadCoerciveWhitelist(): InputKicker
	{
		$this->setWhiteListFromFiles([self::COERCIVE_WHITE_FILE]);
		return $this;
	}

	/**
	 * @return $this
	 */
	public function loadCoerciveGraylist(): InputKicker
	{
		$this->setBlackListFromFiles([self::COERCIVE_GRAY_FILE]);
		return $this;
	}

	/**
	 * @return $this
	 */
	public function loadCoerciveBlacklist(): InputKicker
	{
		$this->setBlackListFromFiles([self::COERCIVE_BLACK_FILE]);
		return $this;
	}

	/**
	 * Check if invalid UTF-8 string encountered in input's values.
	 *
	 * @return bool
	 */
	public function isValidUtf8(): bool
	{
		foreach ($this->inputlist as $value) {
			if(is_string($value) && !preg_match('//u', $value)) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Check if inputs contains an url.
	 *
	 * @return string The first founded.
	 */
	public function containsUrl(): string
	{
		foreach ($this->inputlist as $value) {
			if(is_string($value) && filter_var($value, FILTER_VALIDATE_URL)) {
				return $value;
			}
		}
		return '';
	}
}
