<?php
namespace Coercive\Security\BotKicker;

/**
 * URL KICKER
 *
 * @package		Coercive\Security\BotKicker
 * @link		https://github.com/Coercive/BotKicker
 *
 * @author  	Anthony Moral <contact@coercive.fr>
 * @copyright   (c) 2023 Anthony Moral
 * @license 	MIT
 */
class UrlKicker extends AbstractKicker
{
	const COERCIVE_BLACK_FILE = __DIR__ . '/../list/url/coercive_black';
	const COERCIVE_GRAY_FILE = __DIR__ . '/../list/url/coercive_gray';

	/**
	 * @var string Input IP
	 */
    private string $ip = '';

	/**
	 * @var string User agent
	 */
    private string $agent = '';

	/**
	 * @var string Url before clear
	 */
    private string $rawUrl = '';

	/**
	 * @var string Url after clear
	 */
    private string $url = '';

	/**
	 * @param string $url
	 * @return string
	 */
	private function clearUrl(string $url): string
	{
		if(false !== strpos($url, '%')) {
			$url = urldecode($url);
		}

		$url = '/' . trim($url, '/');

		if(false !== strpos($url, '?')) {
			$url = (string) strstr($url, '?', true);
		}

		return $url;
	}

	/**
	 * UrlKicker constructor.
	 *
	 * @param bool $automatic [optional]
	 * @return void
	 */
	public function __construct(bool $automatic = true)
	{
		if($automatic) {
			$this->automatic();
			$this->setInputList([$this->url]);
		}
	}

	/**
	 * @return $this
	 */
	public function loadCoerciveLists(): self
	{
		$this->loadCoerciveBlacklist();
		return $this;
	}

	/**
	 * @return $this
	 */
	public function loadCoerciveBlacklist(): self
	{
		$this->setBlackListFromFiles([self::COERCIVE_BLACK_FILE]);
		return $this;
	}

	/**
	 * @return $this
	 */
	public function loadCoerciveGraylist(): self
	{
		$this->setBlackListFromFiles([self::COERCIVE_GRAY_FILE]);
		return $this;
	}

	/**
	 * Retrieve automaticaly IP, UA, URL from $_SERVER
	 *
	 * @return $this
	 */
    public function automatic(): self
	{
        return $this
            ->detectAgent()
            ->detectIp()
            ->detectUrl();
    }

	/**
	 * Get IP from $_SERVER
	 *
	 * @return $this
	 */
    public function detectIp(): self
	{
		$this->ip = (string) filter_input(INPUT_SERVER, 'REMOTE_ADDR', FILTER_SANITIZE_FULL_SPECIAL_CHARS);
        return $this;
    }

	/**
	 * @param string $ip
	 * @return $this
	 */
    public function setIp(string $ip): self
	{
		$this->ip = $ip;
        return $this;
    }

	/**
	 * @return string
	 */
    public function getIp(): string
	{
        return $this->ip;
    }

	/**
	 * Get UAGENT from $_SERVER
	 *
	 * @return $this
	 */
    public function detectAgent(): self
	{
		$this->agent = (string) filter_input(INPUT_SERVER, 'HTTP_USER_AGENT', FILTER_SANITIZE_FULL_SPECIAL_CHARS);
		return $this;
    }

	/**
	 * @param string $agent
	 * @return $this
	 */
	public function setAgent(string $agent): self
	{
		$this->agent = $agent;
		return $this;
	}

	/**
	 * @return string
	 */
	public function getAgent(): string
	{
		return $this->agent;
	}

	/**
	 * Get URL from $_SERVER
	 *
	 * @return $this
	 */
    public function detectUrl(): self
	{
		$url = (string) filter_input(INPUT_SERVER, 'REQUEST_URI', FILTER_SANITIZE_FULL_SPECIAL_CHARS);
        if(!$url) {
			$url = (string) filter_input(INPUT_SERVER, 'SCRIPT_URL', FILTER_SANITIZE_FULL_SPECIAL_CHARS);
        }
		$this->rawUrl = $url;
		$this->url = $this->clearUrl($url);
		return $this;
    }

	/**
	 * @param string $url
	 * @param bool $clean
	 * @return $this
	 */
	public function setUrl(string $url, bool $clean = true): self
	{
		$this->rawUrl = $url;
		if($clean) {
			$this->url = $this->clearUrl($url);
		}
		else {
			$this->url = $url;
		}
		return $this;
	}

	/**
	 * @return string
	 */
	public function getUrl(): string
	{
		return $this->url;
	}

	/**
	 * @return string
	 */
	public function getRawUrl(): string
	{
		return $this->rawUrl;
	}
}