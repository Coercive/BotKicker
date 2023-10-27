<?php
namespace Coercive\Security\BotKicker;

/**
 * NsLookUp
 *
 * @package		Coercive\Security\BotKicker
 * @link		https://github.com/Coercive/BotKicker
 *
 * @author  	Anthony Moral <contact@coercive.fr>
 * @copyright   (c) 2023 Anthony Moral
 * @license 	MIT
 */
class NsLookUp
{
	const CMD = 'nslookup -timeout=%d -retry=%d "%s"';

	const REGEX_DOMAIN = '`^[a-z0-9\._-]+\sname\s*=\s*(?P<domain>[a-z0-9\._-]+\.)$`';

	const REGEX_ADDRESS = '`^Address:\s*(?P<ip>[a-z0-9\.:]+)$`';

	/**
	 * @var int nslookup timeout
	 */
	private int $timeout = 1;

	/**
	 * @var int nslookup retry
	 */
	private int $retry = 1;

	/**
	 * @param string $host
	 * @return array
	 */
	private function exec(string $host): array
	{
		$cmd = sprintf(self::CMD, $this->timeout, $this->retry, escapeshellcmd($host));
		exec($cmd, $output);

		return $output ?: [];
	}

	/**
	 * Set nslookup timeout
	 *
	 * @param int $i
	 * @return $this
	 */
	public function setTimeout(int $i): self
	{
		$this->timeout = $i;
		return $this;
	}

	/**
	 * Set nslookup retry
	 *
	 * @param int $i
	 * @return $this
	 */
	public function setRetry(int $i): self
	{
		$this->retry = $i;
		return $this;
	}

	/**
	 * Get IP list from domain
	 *
	 * @param string $domain
	 * @return array
	 */
	public function getIps(string $domain): array
	{
		if(!$lines = $this->exec($domain)) {
			return [];
		}

		$stack = [];
		$start = false;
		foreach ($lines as $line) {

			# Skip dns info header
			if(!$start) {
				$start = 0 === strpos($line, 'Name:');
				continue;
			}

			if(preg_match(self::REGEX_ADDRESS, $line, $matches)) {
				$stack[] = $matches['ip'];
			}
		}

		return $stack;
	}

	/**
	 * Get domains list from ip
	 *
	 * @param string $ip
	 * @return array
	 */
	public function getDomains(string $ip): array
	{
		if(!$lines = $this->exec($ip)) {
			return [];
		}

		$stack = [];
		foreach ($lines as $line) {
			if(preg_match(self::REGEX_DOMAIN, $line, $matches)) {
				$stack[] = $matches['domain'];
			}
		}

		return $stack;
	}

	/**
	 * Check if is a valid IP
	 *
	 * @param string $ip
	 * @return bool
	 */
	public function isValidIp(string $ip): bool
	{
		return (bool) filter_var($ip, FILTER_VALIDATE_IP);
	}

	/**
	 * Match ip vs domain
	 *
	 * @param string $ip
	 * @param string $domain
	 * @param bool $reverse [optional]
	 * @return bool
	 */
	public function match(string $ip, string $domain, bool $reverse = false): bool
	{
		# Search by domain
		$match = false;
		$foundedDoms = [];
		$domain = trim($domain, ' .') . '.';
		foreach ($this->getDomains($ip) as $foundedDom) {

			# Match the end of the domain only
			if(strlen($foundedDom) - strlen($domain) === strrpos($foundedDom, $domain)) {
				$foundedDoms[] = $foundedDom;
				$match = true;
				break;
			}
		}

		# If not found or reverse search active
		if(!$foundedDoms || !$reverse) {
			return $match;
		}

		# Reverse search by ip
		$match = false;
		foreach ($foundedDoms as $foundedDom) {
			if($foundedIps = $this->getIps($foundedDom)) {
				if(in_array($ip, $foundedIps, true)) {
					$match = true;
					break;
				}
			}
		}

		return $match;
	}
}