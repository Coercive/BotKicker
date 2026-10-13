<?php
namespace Coercive\Security\BotKicker\Tests;

use Coercive\Security\BotKicker\AbstractKicker;
use Coercive\Security\BotKicker\UserAgentKicker;
use PHPUnit\Framework\TestCase;

final class AbstractKickerTest extends TestCase
{
	private array $files = [];

	private function file(string $content): string
	{
		$path = tempnam(sys_get_temp_dir(), 'botkicker');
		file_put_contents($path, $content);
		return $this->files[] = $path;
	}

	protected function setUp(): void
	{
		unset($_SERVER['HTTP_USER_AGENT'], $_SERVER['SCRIPT_URL'], $_SERVER['REQUEST_URI']);
	}

	protected function tearDown(): void
	{
		foreach ($this->files as $file) {
			@unlink($file);
		}
	}

	public function testFlattenMerge(): void
	{
		$this->assertSame(['a', 1, 'b', true, 'c', 'd'], AbstractKicker::flattenMerge(['a', 1, ['b', [true, null]]], 'c', [['d']]));
	}

	public function testGetDataFromFiles(): void
	{
		$long = str_repeat('x', 300);
		$a = $this->file("# comment\n\nfoo\n  bar  \n$long\nfoo");
		$b = $this->file("baz\nfoo\n");

		$list = AbstractKicker::getDataFromFiles([$a, '/not/a/file', $b]);
		$this->assertSame(['foo', 'bar', $long, 'baz'], $list);
		$this->assertSame([], AbstractKicker::getDataFromFiles([]));
	}

	public function testDetect(): void
	{
		$kicker = (new UserAgentKicker)
			->setWhiteList(['googlebot'])
			->setBlackList(['bot', 'crawler']);

		# Empty input
		$this->assertFalse($kicker->detect()->getStatus());
		$this->assertTrue($kicker->allowEmpty(true)->detect()->getStatus());

		# Whitelist first
		$status = $kicker->setInputList(['Mozilla Googlebot/2.1'])->detect();
		$this->assertTrue($status->getStatus());
		$this->assertSame('Mozilla Googlebot/2.1', $status->getInput());
		$this->assertSame(['googlebot'], $status->getMatches());

		# Blacklist
		$status = $kicker->setInputList(['Mozilla', 'Some crawler bot'])->detect();
		$this->assertFalse($status->getStatus());
		$this->assertSame(['Mozilla', 'Some crawler bot'], $status->getInputs());
		$this->assertSame('Some crawler bot', $status->getInput());
		$this->assertSame(['bot', 'crawler'], $status->getMatches());

		# Not listed
		$status = $kicker->setInputList(['Mozilla'])->detect();
		$this->assertTrue($status->getStatus());
		$this->assertSame([], $status->getMatches());

		# Scalar inputs (from InputKicker)
		$status = $kicker->setBlackList(['^42$'])->setInputList([42, 1.5, true])->detect();
		$this->assertFalse($status->getStatus());
		$this->assertSame('42', $status->getInput());
	}

	public function testListHandlers(): void
	{
		$kicker = new UserAgentKicker;

		$kicker->setInputList(['a'])->addToInputList(['b', 'a']);
		$this->assertSame(['a', 'b'], $kicker->getInputList());
		$this->assertSame([], $kicker->getBlackList());

		$kicker->setBlackList(['x'])->addToBlackList(['y', 'x']);
		$this->assertSame(['x', 'y'], $kicker->getBlackList());

		$kicker->setWhiteList(['w'])->addToWhiteList(['v']);
		$this->assertSame(['w', 'v'], $kicker->getWhiteList());

		$kicker->setBlackListFromFiles([$this->file("one\ntwo")]);
		$this->assertSame(['one', 'two'], $kicker->getBlackList());

		$kicker->setWhiteListFromFiles([$this->file("three")]);
		$this->assertSame(['three'], $kicker->getWhiteList());
	}

	public function testIsRobotsTxtRequested(): void
	{
		$kicker = new UserAgentKicker;
		$this->assertFalse($kicker->isRobotsTxtRequested());

		$_SERVER['REQUEST_URI'] = '/robots.txt';
		$this->assertTrue($kicker->isRobotsTxtRequested());

		$_SERVER['SCRIPT_URL'] = '/index.php';
		$this->assertFalse($kicker->isRobotsTxtRequested());
	}
}
