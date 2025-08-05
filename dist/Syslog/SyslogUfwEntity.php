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
	/** @var SyslogUfwLineEntity[] */
	private array $lines = [];

	private string $ip;

	private array $protocols = [];

	private array $ports = [];

	private int $count = 0;

	private int $reset = 0;

	private int $in = 0;

	private int $out = 0;

	private int $fw = 0;

	/**
	 * @param string $protocol
	 * @return $this
	 */
	private function addProtocol(string $protocol): self
	{
		if($protocol) {
			$this->protocols[$protocol] = $protocol;
		}
		return $this;
	}

	/**
	 * @param int|null $port
	 * @return $this
	 */
	private function addPort(? int $port): self
	{
		if($port) {
			$this->ports[$port] = $port;
		}
		return $this;
	}

	/**
	 * @return $this
	 */
	private function reset(): self
	{
		$this->reset++;
		return $this;
	}

	/**
	 * @return $this
	 */
	private function in(): self
	{
		$this->in++;
		return $this;
	}

	/**
	 * @return $this
	 */
	private function out(): self
	{
		$this->out++;
		return $this;
	}

	/**
	 * @return $this
	 */
	private function fw(): self
	{
		$this->fw++;
		return $this;
	}

	/**
	 * @return $this
	 */
	private function count(): self
	{
		$this->count++;
		return $this;
	}

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
	 * @param SyslogUfwLineEntity $line
	 * @return $this
	 */
	public function addLine(SyslogUfwLineEntity $line):self
	{
		$this->lines[] = $line;

		if($line->getReset()) {
			$this->reset();
		}
		else {
			if($line->isIncoming()) {
				$this->in();
			}
			elseif($line->isOutgoing()) {
				$this->out();
			}
			elseif($line->isForwarded()) {
				$this->fw();
			}
			$this
				->addProtocol($line->getProtocol())
				->addPort($line->getDestinationPort())
				->count();
		}

		return $this;
	}

	/**
	 * @return SyslogUfwLineEntity[]
	 */
	public function getLines(): array
	{
		return $this->lines;
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
	 * @return int
	 */
	public function getCount(): int
	{
		return $this->count;
	}

	/**
	 * @return int
	 */
	public function getIn(): int
	{
		return $this->in;
	}

	/**
	 * @return int
	 */
	public function getOut(): int
	{
		return $this->out;
	}

	/**
	 * @return int
	 */
	public function getFw(): int
	{
		return $this->fw;
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

		# If only one ICMP / ICMPv6 protocal, it's maybe just a check
		foreach ($this->protocols as $protocol) {
			if(count($this->protocols) === 1 && in_array($protocol, ['ICMP', 'ICMPv6'], true)) {
				return false;
			}
			break;
		}

		# Get out everything that is not TCP / ICMP
		foreach ($this->protocols as $protocol) {
			if(!in_array($protocol, ['TCP', 'ICMP', 'ICMPv6'], true)) {
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