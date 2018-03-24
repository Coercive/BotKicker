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
class Status
{
	/** @var bool BotKicker state */
	private $state = false;

	/** @var array Current check */
	private $currents = [];

	/** @var array Current list elements that match */
	private $list = [];

	/**
	 * Status constructor.
	 *
	 * @param bool $state
	 * @param array $currents [optional]
	 * @param array $list [optional]
	 */
	public function __construct(bool $state, array $currents = [], array $list = [])
	{
		$this->state = $state;
		$this->currents = $currents;
		$this->list = $list;
	}

	/**
	 * @return bool
	 */
	public function getStatus(): bool
	{
		return $this->state;
	}

	/**
	 * @return array
	 */
	public function getCurrents(): array
	{
		return $this->currents;
	}

	/**
	 * @return array
	 */
	public function getList(): array
	{
		return $this->list;
	}
}