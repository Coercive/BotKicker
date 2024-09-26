<?php
namespace Coercive\Security\BotKicker\Syslog;

/**
 * Syslog UFW entity
 *
 * @package		Coercive\Security\BotKicker
 * @link		https://github.com/Coercive/BotKicker
 *
 * @author  	Anthony Moral <contact@coercive.fr>
 * @copyright   (c) 2024 Anthony Moral
 * @license 	MIT
 */
class SyslogUfwEntity
{
	private string $ip;

	private array $protocols = [];

	private array $ports = [];

	private int $count = 0;

	private int $reset = 0;

	/**
	 * SyslogUfwEntity constructor.
	 *
	 * @param string $ip
	 * @return void
	 */
	public function __construct(string $ip)
	{
		$this->ip = $ip;
	}

	/**
	 * @return string
	 */
	public function getIp(): string
	{
		return $this->ip;
	}

	/**
	 * @param string $protocol
	 * @return $this
	 */
	public function addProtocol(string $protocol): self
	{
		if($protocol) {
			$this->protocols[$protocol] = $protocol;
		}
		return $this;
	}

	/**
	 * @return array
	 */
	public function getProtocols(): array
	{
		return $this->protocols;
	}

	/**
	 * @return int
	 */
	public function countProtocols(): int
	{
		return count($this->protocols);
	}

	/**
	 * @param string $port
	 * @return $this
	 */
	public function addPort(string $port): self
	{
		if($port) {
			$this->ports[$port] = $port;
		}
		return $this;
	}

	/**
	 * @return array
	 */
	public function getPorts(): array
	{
		return $this->ports;
	}

	/**
	 * @return int
	 */
	public function countPorts(): int
	{
		return count($this->ports);
	}

	/**
	 * @return $this
	 */
	public function count(): self
	{
		$this->count++;
		return $this;
	}

	/**
	 * @return int
	 */
	public function getCount(): int
	{
		return $this->count;
	}

	/**
	 * @return $this
	 */
	public function reset(): self
	{
		$this->reset++;
		return $this;
	}

	/**
	 * @return int
	 */
	public function getReset(): int
	{
		return $this->reset;
	}

	/**
	 * @return bool
	 */
	public function isBlocked(): bool
	{
		# Only if not just a reset attempt
		if(!$this->getCount()) {
			return false;
		}

		# If only one ICMPv6 protocal, it's maybe just a check
		foreach ($this->protocols as $protocol) {
			if(count($this->protocols) === 1 && $protocol === 'ICMPv6') {
				return false;
			}
			break;
		}

		# Get out everything that is not TCP
		foreach ($this->protocols as $protocol) {
			if(!in_array($protocol, ['TCP', 'ICMPv6'], true)) {
				return true;
			}
		}

		# Get out everything that is not 80 / 443
		foreach ($this->ports as $port) {
			if(!in_array($port, ['80', '443'], true)) {
				return true;
			}
		}

		return false;
	}
}