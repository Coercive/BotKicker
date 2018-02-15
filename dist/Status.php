<?php
namespace Coercive\Security\BotKicker;

/**
 * BOT KICKER STATUS HANDLER
 *
 * @package		Coercive\Security\BotKicker
 * @link		@link https://github.com/Coercive/BotKicker
 *
 * @author  	Anthony Moral <contact@coercive.fr>
 * @copyright   (c) 2018 Anthony Moral
 * @license 	MIT
 */
class Status {

	/** @var bool BotKicker state */
	private $state = false;

	/** @var string Current check */
	private $current = '';

	/** @var array Current blacklist element that trigger error */
	private $black = '';

	/**
	 * Status constructor.
	 *
	 * @param bool $state
	 * @param string $current [optional]
	 * @param string $black [optional]
	 */
	public function __construct(bool $state, string $current = '', string $black = '')
	{
		$this->state = $state;
		$this->current = $current;
		$this->black = $black;
	}

	/**
	 * @return bool
	 */
	public function getStatus(): bool
	{
		return $this->state;
	}

	/**
	 * @return string
	 */
	public function getCurrent(): string
	{
		return $this->current;
	}

	/**
	 * @return string
	 */
	public function getBlack(): string
	{
		return $this->black;
	}

}