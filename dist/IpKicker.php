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
class IpKicker extends AbstractKicker
{
	const COERCIVE_FILE = __DIR__ . '/../list/ip/coercive';
	const GOOGLE_FILE = __DIR__ . '/../list/ip/google';
	const GOOGLEBOT_FILE = __DIR__ . '/../list/ip/googlebot';
	const FACEBOOKBOT_FILE = __DIR__ . '/../list/ip/facebookbot';
	const BREVO_FILE = __DIR__ . '/../list/ip/brevo';
	const LETSENCRYPT_FILE = __DIR__ . '/../list/ip/letsencrypt';

	const MAILJET_FILE = __DIR__ . '/../list/ip/mailjet';
	const STRIPE_FILE = __DIR__ . '/../list/ip/stripe';

	/**
	 * GET IP(s)
	 *
	 * @return void
	 */
	private function initIps()
	{
		# Get remote and forwarded
		$remote = (string) filter_input(INPUT_SERVER, 'REMOTE_ADDR', FILTER_SANITIZE_FULL_SPECIAL_CHARS);
		$forwarded = (string) filter_input(INPUT_SERVER, 'HTTP_X_FORWARDED_FOR', FILTER_SANITIZE_FULL_SPECIAL_CHARS);
		$list = [];

		# Process forwarded ips
		if($forwarded) {

			# Remove spaces
			$forwarded = str_replace(' ', '', $forwarded);

			# List all ips as array
			$list = explode(',', $forwarded) ?: [];
		}

		# Add the basic remote
		if($remote) {
			$list[] = $remote;
		}

		# Unique and not empty
		$list = array_filter(array_unique($list));
		if($list) {
			$this->setInputList($list);
		}
	}

	/**
	 * IpKicker constructor.
	 *
	 * @return void
	 */
	public function __construct()
	{
		$this->initIps();
	}

	/**
	 * @return $this
	 */
	public function loadCoerciveList(): IpKicker
	{
		$this->setBlackListFromFiles([self::COERCIVE_FILE]);
		return $this;
	}

	/**
	 * @return array
	 */
	public function getMailjetList(): array
	{
		return $this->getDataFromFiles([self::MAILJET_FILE]);
	}

	/**
	 * @return array
	 */
	public function getStripeList(): array
	{
		return $this->getDataFromFiles([self::STRIPE_FILE]);
	}

	/**
	 * @return array
	 */
	public function getBrevoList(): array
	{
		return $this->getDataFromFiles([self::BREVO_FILE]);
	}

	/**
	 * @return array
	 */
	public function getLetsEncryptList(): array
	{
		return $this->getDataFromFiles([self::LETSENCRYPT_FILE]);
	}

	/**
	 * @param string $url
	 * @param bool $ipv6
	 * @return array
	 */
	private function extractGoogleList(string $url, bool $ipv6): array
	{
		$json = file_get_contents($url);
		if (!$json) {
			return [];
		}

		$data = json_decode($json, true);
		if ($data === null || !isset($data['prefixes'])) {
			return [];
		}

		$ipList = [];
		foreach ($data['prefixes'] as $prefix) {
			if (!$ipv6 && isset($prefix['ipv4Prefix'])) {
				$ipList[] = $prefix['ipv4Prefix'];
			}
			elseif ($ipv6 & isset($prefix['ipv6Prefix'])) {
				$ipList[] = $prefix['ipv6Prefix'];
			}
		}
		return $ipList;
	}

	/**
	 * Retrieve dynamicaly all IPv4 & IPv6 from Google User
	 *
	 * @param bool $ipv6 [optional]
	 * @return array
	 */
	public function getGoogleUserList(bool $ipv6 = false): array
	{
		$url = 'https://www.gstatic.com/ipranges/goog.json';
		return $this->extractGoogleList($url, $ipv6);
	}

	/**
	 * Retrieve dynamicaly all IPv4 & IPv6 from Google Cloud
	 *
	 * @param bool $ipv6 [optional]
	 * @return array
	 */
	public function getGoogleCloudList(bool $ipv6 = false): array
	{
		$url = 'https://www.gstatic.com/ipranges/cloud.json';
		return $this->extractGoogleList($url, $ipv6);
	}

	/**
	 * Retrieve dynamicaly all IPv4 & IPv6 from Google Bot
	 * @doc https://developers.google.com/search/docs/crawling-indexing/verifying-googlebot
	 *
	 * @param bool $ipv6 [optional]
	 * @return array
	 */
	public function getGoogleBotList(bool $ipv6 = false): array
	{
		$url = 'https://developers.google.com/static/search/apis/ipranges/googlebot.json';
		return $this->extractGoogleList($url, $ipv6);
	}

	/**
	 * Retrieve dynamicaly all IPv4 & IPv6 from Google Special Crawlers
	 * @doc https://developers.google.com/search/docs/crawling-indexing/verifying-googlebot
	 *
	 * @param bool $ipv6 [optional]
	 * @return array
	 */
	public function getGoogleSpecialCrawlersList(bool $ipv6 = false): array
	{
		$url = 'https://developers.google.com/search/apis/ipranges/special-crawlers.json';
		return $this->extractGoogleList($url, $ipv6);
	}

	/**
	 * Retrieve dynamicaly all IPv4 & IPv6 from Google User Triggered Fetchers
	 * @doc https://developers.google.com/search/docs/crawling-indexing/verifying-googlebot
	 *
	 * @param bool $ipv6 [optional]
	 * @return array
	 */
	public function getGoogleUserTriggeredFetchersList(bool $ipv6 = false): array
	{
		$url = 'https://developers.google.com/search/apis/ipranges/user-triggered-fetchers.json';
		return $this->extractGoogleList($url, $ipv6);
	}

	/**
	 * Retrieve dynamicaly all IPv4 & IPv6 from Google User Triggered Fetchers Google
	 * @doc https://developers.google.com/search/docs/crawling-indexing/verifying-googlebot
	 *
	 * @param bool $ipv6 [optional]
	 * @return array
	 */
	public function getGoogleUserTriggeredFetchersGoogleList(bool $ipv6 = false): array
	{
		$url = 'https://developers.google.com/search/apis/ipranges/user-triggered-fetchers-google.json';
		return $this->extractGoogleList($url, $ipv6);
	}

	/**
	 * Retrieve dynamicaly all IPv4 & IPv6 from Facebook
	 *
	 * @link https://developers.facebook.com/docs/sharing/webmasters/crawler/
	 *
	 * @param bool $ipv6 [optional]
	 * @return string[]
	 */
	public function getFacebookList(bool $ipv6 = false): array
	{
		return $this->getFromASN('AS32934', $ipv6);
	}

	/**
	 * Retrieve dynamicaly all IPv4 & IPv6 from LinkedIn
	 *
	 * @doc Search LinkedIn ASN from bgp.he.net or www.cidr-report.org
	 *
	 * @param bool $ipv6 [optional]
	 * @return string[]
	 */
	public function getLinkedInList(bool $ipv6 = false): array
	{
		# Retrieved from https://bgp.he.net/search?search%5Bsearch%5D=LINKEDIN&commit=Search
		$asns = ['AS13443', 'AS14413', 'AS20049', 'AS20366', 'AS40793', 'AS55163', 'AS132406', 'AS132466', 'AS137709', 'AS202745'];

		$ips = [];
		foreach ($asns as $asn) {
			$list = $this->getFromASN($asn, $ipv6);
			$ips = array_merge($ips, $list);
		}
		return $ips;
	}

	/**
	 * Get all IPv4 from PayPlug webhook payment notification
	 *
	 * @return string[]
	 */
	public function getPayPlugList(): array
	{
		return [
			'52.17.55.154',
			'52.209.87.92',
			'54.77.126.191',
			'15.188.38.112',
			'13.36.216.58',
		];
	}

	/**
	 * Get all IPv4 from Prolexis
	 *
	 * @return string[]
	 */
	public function getProlexisList(): array
	{
		return [
			'54.36.182.4',
		];
	}

	/**
	 * Get all IPv4 from Paybox
	 *
	 * @link https://www.paybox.com/espace-integrateur-documentation/la-solution-paybox-system/urls-dappels-et-adresses-ip/
	 *
	 * @return string[]
	 */
	public function getPayboxList(): array
	{
		return [
			'195.25.7.146',
			'195.25.67.22',
			'194.2.160.80',
			'194.2.160.82',
			'194.2.160.91',
			'195.25.67.0',
			'195.25.67.2',
			'195.25.67.11',
			'195.25.7.146',
			'194.2.122.190',
			'195.25.67.22',
		];
	}

	/**
	 * Detect if Bingbot, based on domain 'search.msn.com'
	 *
	 * @link https://www.bing.com/webmasters/help/how-to-verify-bingbot-3905dc26
	 *
	 * @param string $ip
	 * @param bool $linux [optional]
	 * @return Status
	 */
	public function isBing(string $ip, bool $linux = false): Status
	{
		# Linux cmd host
		if($linux) {
			$lk = new HostLookUp;
		}

		# Microsoft cmd nslookup
		else {
			$lk = new NsLookUp;
		}
		$bing = $lk->match($ip, 'search.msn.com', true);

		return new Status($bing, $this->inputlist, [$ip]);
	}

	/**
	 * Retrieve dynamicaly all IPv4 & IPv6 from "Autonomous System Numbers" (ASN)
	 *
	 * @param string $asn
	 * @param bool|null $ipv6 [optional]
	 * @return string[]
	 */
	public function getFromASN(string $asn, ? bool $ipv6 = null): array
	{
		$list = [];
		$cmd = "whois -h whois.radb.net -- '-i origin $asn' | grep ^route" . ($ipv6 === true ? '6' : '') . ($ipv6 !== null ? ':' : '');
		if(exec($cmd, $output)) {
			foreach ($output as $line) {
				$list[] = preg_replace('`route\d?:\s+`', '', $line);
			}
		}
		return $list;
	}
}