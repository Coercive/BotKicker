<?php
namespace Coercive\Security\BotKicker\Tests;

use Coercive\Security\BotKicker\ModSec\ModSecLogEntity;
use Coercive\Security\BotKicker\ModSec\ModSecLogParser;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;

final class ModSecLogParserTest extends TestCase
{
	private string $path;

	protected function setUp(): void
	{
		$this->path = tempnam(sys_get_temp_dir(), 'modsec');
		file_put_contents($this->path, implode("\n", [
			'--aaa111-A--',
			'[13/Oct/2026:10:00:00.123456 +0200] aaa111 1.2.3.4 54321 5.6.7.8 443',
			'--aaa111-B--',
			'GET /wp-login.php HTTP/1.1',
			'X-Forwarded-Host: proxy.example.com',
			'Host: 5.6.7.8:443',
			'User-Agent: BadBot/1.0',
			'',
			'--aaa111-H--',
			'Message: Access denied',
			'--aaa111-Z--',
			'--bbb222-A--',
			'[13/Oct/2026:10:00:01 +0200] bbb222 2001:db8::1 54321 5.6.7.8 443',
			'--bbb222-B--',
			'post / HTTP/2.0',
			'Host: example.com',
			'--bbb222-Z--',
			'--ccc333-A--',
			'[13/Oct/2026:10:00:02 +0200] ccc333 9.9.9.9 54321 5.6.7.8 443',
			'--ccc333-B--',
			'PROPFIND / HTTP/1.1',
			'Host: [2001:db8::2]:443',
			'--ccc333-Z--',
			'--ddd444-A--',
			'[13/Oct/2026:10:00:03 +0200] ddd444 8.8.8.8 54321 5.6.7.8 443',
		]));
	}

	protected function tearDown(): void
	{
		@unlink($this->path);
	}

	public function testParse(): void
	{
		$entries = (new ModSecLogParser($this->path))->getEntries();
		$this->assertCount(3, $entries);

		$a = $entries[0];
		$this->assertSame('aaa111', $a->getId());
		$this->assertTrue($a->isCompleted());
		$this->assertSame('1.2.3.4', $a->getIp());
		$this->assertSame('GET', $a->getMethod());
		$this->assertSame('/wp-login.php', $a->getUri());
		$this->assertSame('HTTP/1.1', $a->getProtocol());
		$this->assertSame('5.6.7.8:443', $a->getHost());
		$this->assertSame('BadBot/1.0', $a->getUserAgent());
		$this->assertSame("Message: Access denied\n", $a->getSection('H'));
		$this->assertSame(['A', 'B', 'H'], array_keys($a->getSections()));

		$b = $entries[1];
		$this->assertSame('2001:db8::1', $b->getIp());
		$this->assertSame('POST', $b->getMethod());
		$this->assertSame('HTTP/2.0', $b->getProtocol());
		$this->assertSame('example.com', $b->getHost());

		$this->assertSame('', $entries[2]->getMethod());
	}

	public function testFilters(): void
	{
		$parser = new ModSecLogParser($this->path);
		$ids = function (array $entries): array {
			return array_values(array_map(function (ModSecLogEntity $e) { return $e->getId(); }, $entries));
		};
		$this->assertSame(['aaa111', 'ccc333'], $ids($parser->filterAccessByIp()));
		$this->assertSame(['aaa111'], $ids($parser->filterGetRequests()));
		$this->assertSame(['bbb222'], $ids($parser->filterPostRequests()));
		$this->assertSame([], $ids($parser->filterHeadRequests()));
		$this->assertSame([], $ids($parser->filterOptionsRequests()));
		$this->assertSame(['ccc333'], $ids($parser->filterUnallowedMethodRequests()));
	}

	public function testEntityCustoms(): void
	{
		$entity = (new ModSecLogEntity('x'))->set('score', 5);
		$this->assertSame(5, $entity->get('score'));
		$this->assertNull($entity->get('none'));
		$this->assertSame(['score' => 5], $entity->getCustoms());
		$this->assertSame([], $entity->addSection('A', 'a')->clearSections()->getSections());
	}

	public function testMissingFile(): void
	{
		$this->expectException(InvalidArgumentException::class);
		new ModSecLogParser('/not/a/file');
	}
}
