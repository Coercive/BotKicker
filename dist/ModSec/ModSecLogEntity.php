<?php
namespace Coercive\Security\BotKicker\ModSec;

/**
 * ModSecurity Log Entity
 *
 * @package		Coercive\Security\BotKicker
 * @link		https://github.com/Coercive/BotKicker
 *
 * @author  	Anthony Moral <contact@coercive.fr>
 * @copyright   (c) 2025 Anthony Moral
 * @license 	MIT
 */
class ModSecLogEntity
{
	private string $id;

	private string $ip = '';

	private array $sections = [];

	private bool $completed = false;

	private string $method = '';

	private string $uri = '';

	private string $protocol = '';

	private string $host = '';

	private string $userAgent = '';

	private array $custom = [];

	/**
	 * @param string $id
	 * @return void
	 */
	public function __construct(string $id)
	{
		$this->id = $id;
	}

	/**
	 * @return string
	 */
	public function getId(): string
	{
		return $this->id;
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
	 * @param string $section
	 * @param string $content [optional]
	 * @return $this
	 */
	public function addSection(string $section, string $content = ''): self
	{
		$this->sections[$section] = ($this->sections[$section] ?? '') . $content . ($content ? "\n" : '');
		return $this;
	}

	/**
	 * @param string $section
	 * @return string
	 */
	public function getSection(string $section): string
	{
		return $this->sections[$section] ?? '';
	}

	/**
	 * @return array
	 */
	public function getSections(): array
	{
		return $this->sections;
	}

	/**
	 * @return $this
	 */
	public function clearSections(): self
	{
		$this->sections = [];
		return $this;
	}

	/**
	 * @param bool $status
	 * @return $this
	 */
	public function setCompletedStatus(bool $status = true): self
	{
		$this->completed = $status;
		return $this;
	}

	/**
	 * @return bool
	 */
	public function isCompleted(): bool
	{
		return $this->completed;
	}

	/**
	 * @param string $method
	 * @return $this
	 */
	public function setMethod(string $method): self
	{
		$this->method = $method;
		return $this;
	}

	/**
	 * @return string
	 */
	public function getMethod(): string
	{
		return $this->method;
	}

	/**
	 * @param string $uri
	 * @return $this
	 */
	public function setUri(string $uri): self
	{
		$this->uri = $uri;
		return $this;
	}

	/**
	 * @return string
	 */
	public function getUri(): string
	{
		return $this->uri;
	}

	/**
	 * @param string $protocol
	 * @return $this
	 */
	public function setProtocol(string $protocol): self
	{
		$this->protocol = $protocol;
		return $this;
	}

	/**
	 * @return string
	 */
	public function getProtocol(): string
	{
		return $this->protocol;
	}

	/**
	 * @param string $host
	 * @return $this
	 */
	public function setHost(string $host): self
	{
		$this->host = $host;
		return $this;
	}

	/**
	 * @return string
	 */
	public function getHost(): string
	{
		return $this->host;
	}

	/**
	 * @param string $ua
	 * @return $this
	 */
	public function setUserAgent(string $ua): self
	{
		$this->userAgent = $ua;
		return $this;
	}

	/**
	 * @return string
	 */
	public function getUserAgent(): string
	{
		return $this->userAgent;
	}

	/**
	 * @param string $name
	 * @param mixed $value
	 * @return $this
	 */
	public function set(string $name, $value): self
	{
		$this->custom[$name] = $value;
		return $this;
	}

	/**
	 * @param string $name
	 * @return mixed|null
	 */
	public function get(string $name)
	{
		return $this->custom[$name] ?? null;
	}

	/**
	 * @return array
	 */
	public function getCustoms(): array
	{
		return $this->custom;
	}
}