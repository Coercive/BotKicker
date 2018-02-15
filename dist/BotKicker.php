<?php
namespace Coercive\Security\BotKicker;

use Exception;
use Symfony\Component\Yaml\Parser as YamlParser;

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
class BotKicker {

	const DEFAULT_USERAGENTS = __DIR__ . '/user_agent.yml';
	const DEFAULT_REFERERS = __DIR__ . '/referer.yml';

	/** @var string Current http user agent */
	private $useragent = '';

	/** @var string Current http referer */
	private $referer = '';

	/** @var array Black list of user agents */
	private $useragents = null;

	/** @var array Black list of referers */
	private $referers = null;

	/**
	 * GET DATA FROM FILE
	 *
	 * Get array datas from json or yaml file list
	 *
	 * @param array $paths
	 * @return array
	 * @throws Exception
	 */
	private function getDataFromFile(array $paths): array
	{
		# No path
		if(!$paths) { throw new Exception('No Yaml files found'); }

		# Retrieve list
		$list = [];
		$yaml = new YamlParser;
		foreach ($paths as $path) {

			# No File : Skip
			if(!is_file($path)) { throw new Exception("File does not exist : $path"); }

			# Type
			preg_match('`\.(?P<type>json|yml|yaml)$`i', $path, $matches);
			$type = $matches['type'] ?? '';

			# Process file type
			switch ($type) {

				case 'json':
					$data = json_decode(file_get_contents($path));
					break;

				case 'yml':
				case 'yaml':
					$data = $yaml->parse(file_get_contents($path));
					break;

				default:
					throw new Exception("Unknowed file type : $type");

			}

			# Merge
			$list = array_merge_recursive($list, $data);
		}

		# Return the full list
		return $list;
	}

	/**
	 * BotKicker constructor.
	 *
	 * Load current agent and referer
	 */
	public function __construct()
	{
		$this->useragent = $_SERVER['HTTP_USER_AGENT'] ?? '';
		$this->referer = $_SERVER['HTTP_REFERER'] ?? '';
	}

	/**
	 * @param string $name
	 * @return BotKicker
	 */
	public function setReferer(string $name): BotKicker
	{
		$this->referer = $name;
		return $this;
	}

	/**
	 * @param string $name
	 * @return BotKicker
	 */
	public function setUserAgent(string $name): BotKicker
	{
		$this->useragent = $name;
		return $this;
	}

	/**
	 * @param array $list
	 * @return BotKicker
	 */
	public function setCustomReferers(array $list): BotKicker
	{
		$this->referers = $list;
		return $this;
	}

	/**
	 * @param array $list
	 * @return BotKicker
	 */
	public function setCustomUserAgents(array $list): BotKicker
	{
		$this->useragents = $list;
		return $this;
	}

	/**
	 * @param array $paths
	 * @return BotKicker
	 * @throws Exception
	 */
	public function setReferersFromFiles(array $paths): BotKicker
	{
		$this->referers = $this->getDataFromFile($paths);
		return $this;
	}

	/**
	 * @param array $paths
	 * @return BotKicker
	 * @throws Exception
	 */
	public function setUserAgentsFromFiles(array $paths): BotKicker
	{
		$this->useragents = $this->getDataFromFile($paths);;
		return $this;
	}

	/**
	 * BLACK LIST DETECT
	 *
	 * @return Status
	 * @throws Exception
	 */
	public function detect(): Status
	{
		# Autoload default files
		if(null === $this->referers) { $this->setReferersFromFiles([self::DEFAULT_REFERERS]); }
		if(null === $this->useragents) { $this->setUserAgentsFromFiles([self::DEFAULT_USERAGENTS]); }

		# Detect if current user agent is in black list
		foreach ($this->useragents as $useragent) {
			$quote = preg_quote($useragent, '`');
			if(preg_match("`$quote`i", $this->useragent)) {
				return new Status(false, $this->useragent, $useragent);
			}
		}

		# Detect if current referer is in black list
		foreach ($this->referers as $referer) {
			$quote = preg_quote($referer, '`');
			if(preg_match("`$quote`i", $this->referer)) {
				return new Status(false, $this->referer, $referer);
			}
		}

		# No bl it's ok
		return new Status(true);
	}

}