<?php
namespace Coercive\Security\BotKicker\Syslog;

use Exception;

/**
 * Syslog UFW line entity
 *
 * @package		Coercive\Security\BotKicker
 * @link		https://github.com/Coercive/BotKicker
 *
 * @author  	Anthony Moral <contact@coercive.fr>
 * @copyright   (c) 2025 Anthony Moral
 * @license 	MIT
 */
class SyslogUfwLineEntity
{
	const reg_ip = "`\sSRC=([a-f\d.:]+)\s`i";
	const reg_protocol = "`\sPROTO=(\w+)\s`i";
	const reg_source_port = "`\sSPT=(\d+)\s`i";
	const reg_destination_port = "`\sDPT=(\d+)\s`i";
	const reg_flag_RST = "`\s(RST)\s`i";
	const reg_interface_IN = "`\sIN=([\w@:.\-]+)\s`i";
	const reg_interface_OUT = "`\sOUT=([\w@:.\-]+)\s`i";

	private string $line;

	private string $ip = '';

	private string $in = '';

	private string $out = '';

	private string $protocol = '';

	private ? int $srcPort = null;

	private ? int $dstPort = null;

	private bool $reset = false;

	/** @var Exception[] */
	private array $errors = [];

	private function parse(): void
	{
		preg_match(self::reg_ip, $this->line, $m);
		if(!$this->ip = $m[1] ?? '') {
			$this->errors[] = new Exception('Empty IP');
		}

		preg_match(self::reg_interface_IN, $this->line, $m);
		$this->in = $m[1] ?? '';

		preg_match(self::reg_interface_OUT, $this->line, $m);
		$this->out = $m[1] ?? '';

		preg_match(self::reg_protocol, $this->line, $m);
		if(!$this->protocol = $m[1] ?? '') {
			$this->errors[] = new Exception('Empty protocol');
		}

		preg_match(self::reg_source_port, $this->line, $m);
		$this->srcPort = isset($m[1]) ? intval($m[1]) : null;

		preg_match(self::reg_destination_port, $this->line, $m);
		$this->dstPort = isset($m[1]) ? intval($m[1]) : null;

		preg_match(self::reg_flag_RST, $this->line, $m);
		$this->reset = boolval($m[1] ?? false);
	}

	/**
	 * SyslogUfwLineEntity constructor.
	 *
	 * @param string $line
	 * @return void
	 */
	public function __construct(string $line)
	{
		$this->line = $line;
		$this->parse();
	}

	/**
	 * @return string
	 */
	public function getLine(): string
	{
		return $this->line;
	}

	/**
	 * @return Exception[]
	 */
	public function getErrors(): array
	{
		return $this->errors;
	}

	/**
	 * @return string
	 */
	public function getIp(): string
	{
		return $this->ip;
	}

	/**
	 * @return string
	 */
	public function getProtocol(): string
	{
		return $this->protocol;
	}

	/**
	 * @return int|null
	 */
	public function getSourcePort(): ? int
	{
		return $this->srcPort;
	}

	/**
	 * @return int|null
	 */
	public function getDestinationPort(): ? int
	{
		return $this->dstPort;
	}

	/**
	 * @return bool
	 */
	public function isIncoming(): bool
	{
		return $this->in && !$this->out;
	}

	/**
	 * @return bool
	 */
	public function isOutgoing(): bool
	{
		return !$this->in && $this->out;
	}

	/**
	 * @return bool
	 */
	public function isForwarded(): bool
	{
		return $this->in && $this->out;
	}

	/**
	 * @return bool
	 */
	public function getReset(): bool
	{
		return $this->reset;
	}
}