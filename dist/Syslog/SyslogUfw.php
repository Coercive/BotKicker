<?php
namespace Coercive\Security\BotKicker\Syslog;

use Exception;

/**
 * Syslog UFW
 *
 * @package		Coercive\Security\BotKicker
 * @link		https://github.com/Coercive/BotKicker
 *
 * @author  	Anthony Moral <contact@coercive.fr>
 * @copyright   (c) 2024 Anthony Moral
 * @license 	MIT
 */
class SyslogUfw
{
	const reg_ip = "`\sSRC=([a-f\d.:]+)\s`i";
	const reg_protocol = "`\sPROTO=(\w+)\s`i";
	const reg_port = "`\sDPT=(\d+)\s`i";
	const reg_flag_RST = "`\s(RST)\s`i";

	private string $path;

	/** @var SyslogUfwEntity[]  */
	private array $matches = [];

	/** @var string[] */
	private array $errors = [];

	/**
	 * @param string $ip
	 * @return SyslogUfwEntity
	 */
	private function getEntity(string $ip): SyslogUfwEntity
	{
		if(!isset($this->matches[$ip])) {
			$this->matches[$ip] = new SyslogUfwEntity($ip);
		}
		return $this->matches[$ip];
	}

	/**
	 * @return void
	 * @throws Exception
	 */
	private function load()
	{
		# Reset containers
		$this->matches = [];
		$this->errors = [];

		# Open file
		$fh = fopen($this->path, 'r');
		if(false === $fh) {
			throw new Exception("Can't read file: {$this->path}");
		}

		while (!feof($fh)) {
			$row = fgets($fh);
			if(false === $row) {
				throw new Exception("Can't read line");
			}

			# Retrieve needed parts
			preg_match(self::reg_ip, $row, $m);
			$ip = $m[1] ?? '';
			preg_match(self::reg_protocol, $row, $m);
			$protocol = $m[1] ?? '';
			preg_match(self::reg_port, $row, $m);
			$port = $m[1] ?? '';
			preg_match(self::reg_flag_RST, $row, $m);
			$reset = boolval($m[1] ?? false);
			if(!$ip || !$protocol) {
				$this->errors[] = $row;
				continue;
			}

			# Adding data, except for reset
			$entity = $this->getEntity($ip);
			if($reset) {
				$entity->reset();
			}
			else {
				$entity->addProtocol($protocol)
					->addPort($port)
					->count();
			}
		}

		# Close file
		fclose($fh);
	}

	/**
	 * SyslogUFW constructor.
	 *
	 * @param string $filepath
	 * @return void
	 * @throws Exception
	 */
	public function __construct(string $filepath)
	{
		if(!is_file($filepath) || !is_readable($filepath)) {
			throw new Exception("Can't read file: $filepath");
		}
		$this->path = $filepath;
		$this->load();
	}

	/**
	 * @return SyslogUfwEntity[]
	 */
	public function getMatches(): array
	{
		return $this->matches;
	}

	/**
	 * @return string[]
	 */
	public function getErrors(): array
	{
		return $this->errors;
	}
}