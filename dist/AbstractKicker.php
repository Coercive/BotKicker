<?php
namespace Coercive\Security\BotKicker;

use Exception;

/**
 * BOT KICKER
 *
 * @package		Coercive\Security\BotKicker
 * @link		@link https://github.com/Coercive/BotKicker
 *
 * @author  	Anthony Moral <contact@coercive.fr>
 * @copyright   (c) 2018 Anthony Moral
 * @license 	MIT
 */
abstract class AbstractKicker
{
	/** @var array Default file list */
	protected $default = [];

	/** @var bool Allow empty current haystack */
	protected $empty = false;

	/** @var string Current haystack for detect */
	protected $current = '';

	/** @var array|null */
	protected $blacklist = null;

	/** @var array|null */
	protected $whitelist = null;

	/**
	 * GET DATA FROM FILE
	 *
	 * Get array datas from json or yaml file list
	 *
	 * @param array $paths
	 * @return array
	 * @throws Exception
	 */
	protected function getDataFromFiles(array $paths): array
	{
		# No path
		if(!$paths) { throw new Exception('No Yaml files found'); }

		# Retrieve list
		$list = [];
		foreach ($paths as $path) {

			# No File : Skip
			if(!is_file($path)) { throw new Exception("File does not exist : $path"); }

			# Init empty datas
			$datas = [];

			# Load file
			$resource = @fopen($path, 'r');
			if(!$resource) { return $datas; }

			# Parse
			while (false !== ($buffer = fgets($resource, 256))) {
				$item = trim($buffer);
				if(!$item || strpos($item, '#') === 0) { continue; }
				$datas[] = $item;
			}

			# Fail to parse datas : reinit
			if (!feof($resource)) {
				$datas = [];
			}

			# Close resource
			fclose($resource);

			# Merge
			$list = array_merge_recursive($list, $datas);
		}

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
	public function allowEmpty(bool $state)
	{
		$this->empty = $state;
		return $this;
	}

	/**
	 * Set a custom current item for detection in list
	 *
	 * @param string $name
	 * @return $this
	 */
	public function setCurrent(string $name)
	{
		$this->current = $name;
		return $this;
	}

	/**
	 * Set a custom black list from array
	 *
	 * @param array $list
	 * @return $this
	 */
	public function setBlackList(array $list)
	{
		$this->blacklist = $list;
		return $this;
	}

	/**
	 * Get black list as array
	 *
	 * @return array
	 */
	public function getBlackList(): array
	{
		return $this->blacklist ?: [];
	}

	/**
	 * Set a custom white list from array
	 *
	 * @param array $list
	 * @return $this
	 */
	public function setWhiteList(array $list)
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
	 * Set a black list from files list
	 *
	 * @param array $paths
	 * @return $this
	 * @throws Exception
	 */
	public function setBlackListFromFiles(array $paths)
	{
		$this->blacklist = $this->getDataFromFiles($paths);
		return $this;
	}

	/**
	 * Set a white list from files list
	 *
	 * @param array $paths
	 * @return $this
	 * @throws Exception
	 */
	public function setWhiteListFromFiles(array $paths)
	{
		$this->whitelist = $this->getDataFromFiles($paths);
		return $this;
	}

	/**
	 * LIST DETECT
	 *
	 * @return Status
	 * @throws Exception
	 */
	public function detect(): Status
	{
		# Autoload default files
		if(null === $this->blacklist && $this->default) { $this->setBlackListFromFiles($this->default); }

		# (Dis)Allow empty haystack
		if(!$this->current) {
			return new Status($this->empty);
		}

		# Detect if current haystack is in white list
		if($this->whitelist && ($list = $this->match($this->current, $this->whitelist))) {
			return new Status(true, $this->current, $list);
		}

		# Detect if current haystack is in black list
		if($this->blacklist && ($list = $this->match($this->current, $this->blacklist))) {
			return new Status(false, $this->current, $list);
		}

		# No bl it's ok
		return new Status(true, $this->current);
	}
}