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

	/** @var array Currents haystack for detect */
	protected $currents = [];

	/** @var array|null */
	protected $blacklist = null;

	/** @var array */
	protected $custom_bl = [];

	/** @var array|null */
	protected $whitelist = null;

	/** @var array */
	protected $custom_wl = [];

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
	 * Set custom currents items for detection in list
	 *
	 * @param array $list
	 * @return $this
	 */
	public function setCurrents(array $list)
	{
		$this->currents = $list;
		return $this;
	}

	/**
	 * Get currents haystack
	 *
	 * @return array
	 */
	public function getCurrents(): array
	{
		return $this->currents;
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
		return array_merge($this->blacklist ?: [], $this->custom_bl);
	}

	/**
	 * Add to black list
	 *
	 * @param array $list
	 * @return $this
	 */
	public function addToBlackList(array $list)
	{
		$this->custom_bl = array_merge_recursive($this->custom_bl, $list);
		return $this;
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
		return array_merge($this->whitelist ?: [], $this->custom_wl);
	}

	/**
	 * Add to white list
	 *
	 * @param array $list
	 * @return $this
	 */
	public function addToWhiteList(array $list)
	{
		$this->custom_wl = array_merge_recursive($this->custom_wl, $list);
		return $this;
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
		if(!$this->currents) {
			return new Status($this->empty);
		}

		# Detect if current haystack is in white list
		$wl = $this->getWhiteList();
		if($wl) foreach ($this->currents as $current) {
			if($list = $this->match($current, $wl)) {
				return new Status(true, $this->currents, $list);
			}
		}

		# Detect if current haystack is in black list
		$bl = $this->getBlackList();
		if($bl) foreach ($this->currents as $current) {
			if($list = $this->match($current, $bl)) {
				return new Status(false, $this->currents, $list);
			}
		}

		# No bl it's ok
		return new Status(true, $this->currents);
	}

	/**
	 * Detect if the robots.txt file is requested
	 *
	 * @return bool
	 */
	public function isRobotsTxtRequested(): bool
	{
		$url = $_SERVER['SCRIPT_URL'] ?? ($_SERVER['REQUEST_URI'] ?? '');
		return false !== strpos($url, 'robots.txt');
	}
}