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

	/** @var array Current list elements that match */
	private $list = [];

	/**
	 * Status constructor.
	 *
	 * @param bool $state
	 * @param string $current [optional]
	 * @param array $list [optional]
	 */
	public function __construct(bool $state, string $current = '', array $list = [])
	{
		$this->state = $state;
		$this->current = $current;
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
	 * @return string
	 */
	public function getCurrent(): string
	{
		return $this->current;
	}

	/**
	 * @return array
	 */
	public function getList(): array
	{
		return $this->list;
	}

}