<?php
namespace Coercive\Security\BotKicker\Tests;

use Coercive\Security\BotKicker\AbstractLookUp;
use Coercive\Security\BotKicker\HostLookUp;
use Coercive\Security\BotKicker\NsLookUp;
use PHPUnit\Framework\TestCase;

final class LookUpTest extends TestCase
{
	/**
	 * Host command fake output
	 *
	 * @param array $outputs [host => lines]
	 * @return AbstractLookUp
	 */
	private function host(array $outputs): AbstractLookUp
	{
		return new class($outputs) extends AbstractLookUp
		{
			const REGEX_DOMAIN = HostLookUp::REGEX_DOMAIN;
			const REGEX_ADDRESS = HostLookUp::REGEX_ADDRESS;

			private array $outputs;

			public function __construct(array $outputs)
			{
				$this->outputs = $outputs;
			}

			protected function exec(string $host): array
			{
				return $this->outputs[$host] ?? [];
			}
		};
	}

	public function testHostParsing(): void
	{
		$look = $this->host([
			'66.249.66.1' => ['1.66.249.66.in-addr.arpa domain name pointer crawl-66-249-66-1.googlebot.com.'],
			'crawl-66-249-66-1.googlebot.com.' => [
				'crawl-66-249-66-1.googlebot.com has address 66.249.66.1',
				'crawl-66-249-66-1.googlebot.com has IPv6 address 2001:4860:4801:2::1',
			],
		]);
		$this->assertSame(['crawl-66-249-66-1.googlebot.com.'], $look->getDomains('66.249.66.1'));
		$this->assertSame(['66.249.66.1', '2001:4860:4801:2::1'], $look->getIps('crawl-66-249-66-1.googlebot.com.'));
		$this->assertSame([], $look->getIps('unknown'));

		$this->assertTrue($look->match('66.249.66.1', 'googlebot.com'));
		$this->assertTrue($look->match('66.249.66.1', 'googlebot.com.', true));
		$this->assertTrue($look->match('66.249.66.1', 'GoogleBot.com'));
		$this->assertFalse($look->match('66.249.66.1', 'google.com'));
		$this->assertFalse($look->match('1.2.3.4', 'googlebot.com'));
	}

	public function testMatchDomainBoundary(): void
	{
		$look = $this->host([
			'6.6.6.6' => ['6.6.6.6.in-addr.arpa domain name pointer crawl.evilgooglebot.com.'],
			'crawl.evilgooglebot.com.' => ['crawl.evilgooglebot.com has address 6.6.6.6'],
		]);
		$this->assertFalse($look->match('6.6.6.6', 'googlebot.com'));
		$this->assertTrue($look->match('6.6.6.6', 'evilgooglebot.com', true));
	}

	public function testReverseMismatch(): void
	{
		$look = $this->host([
			'6.6.6.6' => ['6.6.6.6.in-addr.arpa domain name pointer fake.googlebot.com.'],
			'fake.googlebot.com.' => ['fake.googlebot.com has address 66.249.66.1'],
		]);
		$this->assertTrue($look->match('6.6.6.6', 'googlebot.com'));
		$this->assertFalse($look->match('6.6.6.6', 'googlebot.com', true));
	}

	public function testNsLookUpParsing(): void
	{
		$look = new class extends AbstractLookUp
		{
			const REGEX_DOMAIN = NsLookUp::REGEX_DOMAIN;
			const REGEX_ADDRESS = NsLookUp::REGEX_ADDRESS;

			protected bool $nsLookUpHeaders = true;

			protected function exec(string $host): array
			{
				return [
					'Server:		192.168.1.1',
					'Address:	192.168.1.1#53',
					'',
					'Non-authoritative answer:',
					'1.66.249.66.in-addr.arpa	name = crawl-66-249-66-1.googlebot.com.',
					'Name:	crawl-66-249-66-1.googlebot.com',
					'Address: 66.249.66.1',
				];
			}
		};
		$this->assertSame(['crawl-66-249-66-1.googlebot.com.'], $look->getDomains('66.249.66.1'));
		$this->assertSame(['66.249.66.1'], $look->getIps('crawl-66-249-66-1.googlebot.com'));
	}

	public function testHelpers(): void
	{
		$look = (new HostLookUp)->setTimeout(2)->setRetry(0);
		$this->assertTrue($look->isValidIp('1.2.3.4'));
		$this->assertTrue($look->isValidIp('::1'));
		$this->assertFalse($look->isValidIp('1.2.3'));
		$this->assertFalse($look->matchNative('not an ip', 'example.com'));
		$this->assertInstanceOf(NsLookUp::class, (new NsLookUp)->setTimeout(1));
	}
}
