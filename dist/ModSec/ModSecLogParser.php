<?php
namespace Coercive\Security\BotKicker\ModSec;

use InvalidArgumentException;
use RuntimeException;

/**
 * ModSecurity Log Parser
 *
 * @package		Coercive\Security\BotKicker
 * @link		https://github.com/Coercive/BotKicker
 *
 * @author  	Anthony Moral <contact@coercive.fr>
 * @copyright   (c) 2025 Anthony Moral
 * @license 	MIT
 */
class ModSecLogParser
{
	private string $logPath;

	/** @var ModSecLogEntity[] */
	private array $entries = [];

	/**
	 * ModSecLogParser constructor.
	 *
	 * @param string $filepath
	 * @return void
	 */
	public function __construct(string $filepath)
	{
		if (!is_file($filepath)) {
			throw new InvalidArgumentException("File not found, or permission denied: $filepath");
		}
		$this->logPath = $filepath;
		$this->parseLog();
	}

	/**
	 * @return void
	 */
	private function parseLog(): void
	{
		$handle = fopen($this->logPath, 'r');
		if (!$handle) {
			throw new RuntimeException("Can't open file : $this->logPath");
		}

		$id = null;
		$section = null;

		/** @var ModSecLogEntity[] $entries */
		$entries = [];

		while (($line = fgets($handle)) !== false) {
			$line = rtrim($line, "\r\n");

			# New section separator
			if (preg_match('`^--([a-zA-Z0-9]+)-([A-Z])--$`', $line, $match)) {
				$id = $match[1];
				$section = $match[2];

				if ($section === 'A' && !isset($entries['id'])) {
					$entries[$id] = new ModSecLogEntity($id);
				}

				continue;
			}

			# Add content
			if ($id && $section && isset($entries[$id])) {
				$entries[$id]->addSection($section, $line);

				# Get calling IP
				if ($section === 'A' && !$entries[$id]->getIp()) {
					if (preg_match('`^\[[^\]]+\]\s+\S+\s+(\d{1,3}(?:\.\d{1,3}){3})`', $line, $ipMatch)) {
						$entries[$id]->setIp($ipMatch[1]);
					}
				}

				# Access method / URI / and protocol
				if ($section === 'B' && !$entries[$id]->getMethod()
					&& preg_match('`^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE)\s+(\S+)\s+(HTTP/\d\.\d)`i', $line, $match)
				) {
					$entries[$id]
						->setMethod($match[1])
						->setUri($match[2])
						->setProtocol($match[3]);
				}

				# Host called
				if ($section === 'B' && !$entries[$id]->getHost()
					&& preg_match('`Host:\s*(.+)`', $line, $match)) {
					$entries[$id]->setHost(trim($match[1]));
				}

				# User-Agent
				if ($section === 'B' && !$entries[$id]->getUserAgent()
					&& preg_match('`^User-Agent:\s*(.+)`i', $line, $match)) {
					$entries[$id]->setUserAgent(trim($match[1]));
				}
			}

			# End of transaction
			if ($section === 'Z' && isset($entries[$id])) {
				$entries[$id]->setCompletedStatus();
				$this->entries[] = $entries[$id];
				unset($entries[$id]);
				$id = null;
				$section = null;
			}
		}

		fclose($handle);
	}

	/**
	 * @return ModSecLogEntity[]
	 */
	public function getEntries(): array
	{
		return $this->entries;
	}

	/**
	 * @param callable $callback
	 * @return ModSecLogEntity[]
	 */
	public function search(callable $callback): array
	{
		$results = [];
		foreach ($this->entries as $id => $entry) {
			if ($callback($entry)) {
				$results[$id] = $entry;
			}
		}
		return $results;
	}

	/**
	 * @return ModSecLogEntity[]
	 */
	public function filterAccessByIp(): array
	{
		return $this->search(function (ModSecLogEntity $entry) {
			$host = $entry->getHost();
			if ($host && filter_var($host, FILTER_VALIDATE_IP)) {
				return true;
			}
			return false;
		});
	}

	/**
	 * @return ModSecLogEntity[]
	 */
	public function filterGetRequests(): array
	{
		return $this->search(function (ModSecLogEntity $entry) {
			return $entry->getMethod() === 'GET';
		});
	}

	/**
	 * @return ModSecLogEntity[]
	 */
	public function filterPostRequests(): array
	{
		return $this->search(function (ModSecLogEntity $entry) {
			return $entry->getMethod() === 'POST';
		});
	}

	/**
	 * @return ModSecLogEntity[]
	 */
	public function filterHeadRequests(): array
	{
		return $this->search(function (ModSecLogEntity $entry) {
			return $entry->getMethod() === 'HEAD';
		});
	}

	/**
	 * @return ModSecLogEntity[]
	 */
	public function filterOptionsRequests(): array
	{
		return $this->search(function (ModSecLogEntity $entry) {
			return $entry->getMethod() === 'OPTIONS';
		});
	}

	/**
	 * @return ModSecLogEntity[]
	 */
	public function filterUnallowedMethodRequests(): array
	{
		return $this->search(function (ModSecLogEntity $entry) {
			return !in_array($entry->getMethod(), ['GET', 'HEAD', 'POST', 'OPTIONS'], true);
		});
	}
}