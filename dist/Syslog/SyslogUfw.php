<?php
declare(strict_types=1);

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
final class SyslogUfw
{
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
	private function load(): void
	{
		# Reset containers
		$this->matches = [];
		$this->errors = [];

		# Open file
		$fh = @fopen($this->path, 'r');
		if(false === $fh) {
			throw new Exception("Can't read file: {$this->path}");
		}

		while (false !== ($row = fgets($fh))) {

			# Skip empty lines
			if('' === trim($row)) {
				continue;
			}

			# Retrieve needed parts
			$line = new SyslogUfwLineEntity($row);
			if($line->getErrors()) {
				$this->errors[] = $row;
				continue;
			}

			# Adding data, except for reset
			$entity = $this->getEntity($line->getIp());
			$entity->addLine($line);
		}

		# Read error before the end of file
		$eof = feof($fh);
		fclose($fh);
		if(!$eof) {
			throw new Exception("Can't read line");
		}
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
