<?php
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
	 * @param ...$arrays
	 * @return array
	 */
	static function flattenMerge(...$arrays): array
	{
		$result = [];

		$flatten = function ($input) use (&$flatten, &$result) {
			foreach ($input as $value) {
				if (is_array($value)) {
					$flatten($value);
				}
				elseif (is_scalar($value) || is_string($value)) {
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
	 * Get array datas from json or yaml file list
	 *
	 * @param array $paths
	 * @return array
	 */
	static public function getDataFromFiles(array $paths): array
	{
		# No path
		if(!$paths) {
			return [];
		}

		# Retrieve list
		$list = [];
		foreach ($paths as $path) {

			# No File : Skip
			if(!is_file($path)) {
				continue;
			}

			# Init empty datas
			$datas = [];

			# Load file
			$resource = @fopen($path, 'r');
			if(!$resource) {
				return $datas;
			}

			# Parse
			while (false !== ($buffer = fgets($resource, 256))) {
				$item = trim($buffer);
				if(!$item || strpos($item, '#') === 0) {
					continue;
				}
				$datas[] = $item;
			}

			# Fail to parse datas : reinit
			if (!feof($resource)) {
				$datas = [];
			}

			# Close resource
			fclose($resource);

			# Merge
			$list = array_merge($list, $datas);
		}

		# Deduplication
		$list = array_unique($list);

		# Return the full list
		return $list;
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
	public function allowEmpty(bool $state): AbstractKicker
	{
		$this->empty = $state;
		return $this;
	}

	/**
	 * Set inputlist
	 *
	 * @param array $list
	 * @return $this
	 */
	public function setInputList(array $list): AbstractKicker
	{
		$this->inputlist = $list;
		return $this;
	}

	/**
	 * Get inputlist
	 *
	 * @return array
	 */
	public function getInputList(): array
	{
		return $this->inputlist;
	}

	/**
	 * Add to blacklist
	 *
	 * @param array $list
	 * @return $this
	 */
	public function addToInputList(array $list): AbstractKicker
	{
		$this->blacklist = array_merge($this->blacklist, $list);
		$this->blacklist = array_unique($this->blacklist);
		return $this;
	}

	/**
	 * Set blacklist
	 *
	 * @param array $list
	 * @return $this
	 */
	public function setBlackList(array $list): AbstractKicker
	{
		$this->blacklist = $list;
		return $this;
	}

	/**
	 * Get blacklist
	 *
	 * @return array
	 */
	public function getBlackList(): array
	{
		return $this->blacklist ?: [];
	}

	/**
	 * Add to blacklist
	 *
	 * @param array $list
	 * @return $this
	 */
	public function addToBlackList(array $list): AbstractKicker
	{
		$this->blacklist = array_merge($this->blacklist, $list);
		$this->blacklist = array_unique($this->blacklist);
		return $this;
	}

	/**
	 * Set a custom white list from array
	 *
	 * @param array $list
	 * @return $this
	 */
	public function setWhiteList(array $list): AbstractKicker
	{
		$this->whitelist = $list;
		return $this;
	}

	/**
	 * Get white list as array
	 *
	 * @return array
	 */
	public function getWhiteList(): array
	{
		return $this->whitelist ?: [];
	}

	/**
	 * Add to white list
	 *
	 * @param array $list
	 * @return $this
	 */
	public function addToWhiteList(array $list): AbstractKicker
	{
		$this->whitelist = array_merge($this->whitelist, $list);
		$this->whitelist = array_unique($this->whitelist);
		return $this;
	}

	/**
	 * Set a black list from files list
	 *
	 * @param array $paths
	 * @return $this
	 */
	public function setBlackListFromFiles(array $paths): AbstractKicker
	{
		$this->blacklist = $this->getDataFromFiles($paths);
		return $this;
	}

	/**
	 * Set a white list from files list
	 *
	 * @param array $paths
	 * @return $this
	 */
	public function setWhiteListFromFiles(array $paths): AbstractKicker
	{
		$this->whitelist = $this->getDataFromFiles($paths);
		return $this;
	}

	/**
	 * LIST DETECT
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
		if($wl = $this->getWhiteList()) {
			foreach ($this->inputlist as $input) {
				if($matches = $this->match($input, $wl)) {
					return new Status(true, $this->inputlist, $input, $matches);
				}
			}
		}

		# Detect if current haystack is in black list
		if($bl = $this->getBlackList()) {
			foreach ($this->inputlist as $input) {
				if($matches = $this->match($input, $bl)) {
					return new Status(false, $this->inputlist, $input, $matches);
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
		$url = $_SERVER['SCRIPT_URL'] ?? ($_SERVER['REQUEST_URI'] ?? '');
		return false !== strpos($url, '/robots.txt');
	}
}