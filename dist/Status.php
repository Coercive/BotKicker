<?php
namespace Coercive\Security\BotKicker;

/**
 * BOT KICKER STATUS HANDLER
 *
 * @package		Coercive\Security\BotKicker
 * @link		https://github.com/Coercive/BotKicker
 *
 * @author  	Anthony Moral <contact@coercive.fr>
 * @copyright   (c) 2018 Anthony Moral
 * @license 	MIT
 */
class Status
{
	/** @var bool BotKicker state */
	private bool $state;

	/** @var array Current input list */
	private array $inputs;

	/** @var string Current input checked */
	private string $input;

	/** @var array Current list elements that match */
	private array $matches;

	/**
	 * Status constructor.
	 *
	 * @param bool $state
	 * @param array $inputs [optional]
	 * @param string $input [optional]
	 * @param array $matches [optional]
	 */
	public function __construct(bool $state, array $inputs = [], string $input = '', array $matches = [])
	{
		$this->state = $state;
		$this->inputs = $inputs;
		$this->input = $input;
		$this->matches = $matches;
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
	public function getInputs(): array
	{
		return $this->inputs;
	}

	/**
	 * @return string
	 */
	public function getInput(): string
	{
		return $this->input;
	}

	/**
	 * @return array
	 */
	public function getMatches(): array
	{
		return $this->matches;
	}
}