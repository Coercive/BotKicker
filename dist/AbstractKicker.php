<?php
declare(strict_types=1);

namespace Coercive\Security\BotKicker;

/**
 * BOT KICKER
 *
 * @package		Coercive\Security\BotKicker
 * @link		https://github.com/Coercive/BotKicker
 *
 * @author  	Anthony Moral <contact@coercive.fr>
 * @copyright   (c) 2018 Anthony Moral
 * @license 	MIT
 */
abstract class AbstractKicker
{
	/** @var bool Allow empty current haystack */
	protected bool $empty = false;

	/** @var array Blacklist to compare */
	protected array $blacklist = [];

	/** @var array Whitelist to compare */
	protected array $whitelist = [];

	/** @var array List for match */
	protected array $inputlist = [];

	/**
	 * Flatten the given arrays (recursively) into a single list of scalar values
	 *
	 * @param mixed ...$arrays
	 * @return array
	 */
	public static function flattenMerge(...$arrays): array
	{
		$result = [];

		$flatten = function (array $input) use (&$flatten, &$result) {
			foreach ($input as $value) {
				if (is_array($value)) {
					$flatten($value);
				}
				elseif (is_scalar($value)) {
					$result[] = $value;
				}
			}
		};

		foreach ($arrays as $array) {
			if (!is_array($array)) {
				$array = [$array];
			}
			$flatten($array);
		}

		return $result;
	}

	/**
	 * GET DATA FROM FILE
	 *
	 * Get array datas from raw file list : one item per line, empty lines and lines beginning with "#" are skipped.
	 * A missing or unreadable file is skipped.
	 *
	 * @param array $paths
	 * @return array
	 */
	public static function getDataFromFiles(array $paths): array
	{
		$list = [];
		foreach ($paths as $path) {

			# No File : Skip
			if(!is_file($path)) {
				continue;
			}

			# Load file
			$resource = @fopen($path, 'r');
			if(!$resource) {
				continue;
			}

			# Parse
			$datas = [];
			while (false !== ($buffer = fgets($resource))) {
				$item = trim($buffer);
				if('' === $item || 0 === strpos($item, '#')) {
					continue;
				}
				$datas[] = $item;
			}

			# Fail to parse datas : skip this file
			if (!feof($resource)) {
				$datas = [];
			}

			fclose($resource);

			$list = array_merge($list, $datas);
		}

		return array_values(array_unique($list));
	}

	/**
	 * MATCH ITEM IN LIST
	 *
	 * @param string $haystack
	 * @param array $list
	 * @return array
	 */
	protected function match(string $haystack, array $list): array
	{
		$match = [];
		foreach ($list as $needle) {
			if(preg_match("`$needle`i", $haystack)) {
				$match[] = $needle;
			}
		}
		return $match;
	}

	/**
	 * Allow empty haystack (no detection => return true Status)
	 * Or disallow empty haystack (no detection => return false Status)
	 *
	 * @param bool $state
	 * @return $this
	 */
	public function allowEmpty(bool $state): self
	{
		$this->empty = $state;
		return $this;
	}

	/**
	 * @param array $list
	 * @return $this
	 */
	public function setInputList(array $list): self
	{
		$this->inputlist = $list;
		return $this;
	}

	/**
	 * @return array
	 */
	public function getInputList(): array
	{
		return $this->inputlist;
	}

	/**
	 * @param array $list
	 * @return $this
	 */
	public function addToInputList(array $list): self
	{
		$this->inputlist = array_values(array_unique(array_merge($this->inputlist, $list)));
		return $this;
	}

	/**
	 * @param array $list
	 * @return $this
	 */
	public function setBlackList(array $list): self
	{
		$this->blacklist = $list;
		return $this;
	}

	/**
	 * @return array
	 */
	public function getBlackList(): array
	{
		return $this->blacklist;
	}

	/**
	 * @param array $list
	 * @return $this
	 */
	public function addToBlackList(array $list): self
	{
		$this->blacklist = array_values(array_unique(array_merge($this->blacklist, $list)));
		return $this;
	}

	/**
	 * @param array $list
	 * @return $this
	 */
	public function setWhiteList(array $list): self
	{
		$this->whitelist = $list;
		return $this;
	}

	/**
	 * @return array
	 */
	public function getWhiteList(): array
	{
		return $this->whitelist;
	}

	/**
	 * @param array $list
	 * @return $this
	 */
	public function addToWhiteList(array $list): self
	{
		$this->whitelist = array_values(array_unique(array_merge($this->whitelist, $list)));
		return $this;
	}

	/**
	 * @param array $paths
	 * @return $this
	 */
	public function setBlackListFromFiles(array $paths): self
	{
		$this->blacklist = self::getDataFromFiles($paths);
		return $this;
	}

	/**
	 * @param array $paths
	 * @return $this
	 */
	public function setWhiteListFromFiles(array $paths): self
	{
		$this->whitelist = self::getDataFromFiles($paths);
		return $this;
	}

	/**
	 * LIST DETECT
	 *
	 * Whitelist first (true status), then blacklist (false status).
	 *
	 * @return Status
	 */
	public function detect(): Status
	{
		# (Dis)Allow empty haystack
		if(!$this->inputlist) {
			return new Status($this->empty);
		}

		# Detect if current haystack is in whitelist
		if($this->whitelist) {
			foreach ($this->inputlist as $input) {
				if($matches = $this->match((string) $input, $this->whitelist)) {
					return new Status(true, $this->inputlist, (string) $input, $matches);
				}
			}
		}

		# Detect if current haystack is in black list
		if($this->blacklist) {
			foreach ($this->inputlist as $input) {
				if($matches = $this->match((string) $input, $this->blacklist)) {
					return new Status(false, $this->inputlist, (string) $input, $matches);
				}
			}
		}

		# No bl it's ok
		return new Status(true, $this->inputlist);
	}

	/**
	 * Detect if the robots.txt file is requested
	 *
	 * @return bool
	 */
	public function isRobotsTxtRequested(): bool
	{
		$url = (string) ($_SERVER['SCRIPT_URL'] ?? ($_SERVER['REQUEST_URI'] ?? ''));
		return false !== strpos($url, '/robots.txt');
	}
}
