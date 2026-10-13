<?php
namespace Coercive\Security\BotKicker\Tests;

use Coercive\Security\BotKicker\InputKicker;
use Coercive\Security\BotKicker\RefererKicker;
use Coercive\Security\BotKicker\RequestMethodKicker;
use Coercive\Security\BotKicker\UrlKicker;
use Coercive\Security\BotKicker\UserAgentKicker;
use PHPUnit\Framework\TestCase;

final class KickersTest extends TestCase
{
	protected function setUp(): void
	{
		unset(
			$_SERVER['HTTP_USER_AGENT'],
			$_SERVER['HTTP_REFERER'],
			$_SERVER['REQUEST_METHOD'],
			$_SERVER['REQUEST_URI'],
			$_SERVER['SCRIPT_URL']
		);
		$_GET = [];
		$_POST = [];
	}

	public function testUserAgentKicker(): void
	{
		$this->assertSame([], (new UserAgentKicker)->getInputList());

		$_SERVER['HTTP_USER_AGENT'] = 'Mozilla/5.0 (compatible; MJ12bot/v1.4.8; http://mj12bot.com/)';
		$kicker = (new UserAgentKicker)->loadCoerciveLists();
		$this->assertSame([$_SERVER['HTTP_USER_AGENT']], $kicker->getInputList());
		$this->assertNotEmpty($kicker->getWhiteList());
		$this->assertNotEmpty($kicker->getBlackList());
		$this->assertFalse($kicker->detect()->getStatus());

		$_SERVER['HTTP_USER_AGENT'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36';
		$this->assertTrue((new UserAgentKicker)->loadCoerciveLists()->detect()->getStatus());

		foreach (['loadCoerciveGraylist', 'loadPerishableBlacklist', 'loadMitchellKrogzaBlacklist'] as $method) {
			$this->assertNotEmpty((new UserAgentKicker)->$method()->getBlackList(), $method);
		}
	}

	public function testRefererKicker(): void
	{
		$this->assertSame([], (new RefererKicker)->getInputList());

		$_SERVER['HTTP_REFERER'] = 'https://example.com/page';
		$kicker = new RefererKicker;
		$this->assertSame(['https://example.com/page'], $kicker->getInputList());

		foreach (['loadCoerciveList', 'loadPerishableList', 'loadChongqedList'] as $method) {
			$this->assertNotEmpty((new RefererKicker)->$method()->getBlackList(), $method);
		}
	}

	public function testRequestMethodKicker(): void
	{
		$this->assertSame([], (new RequestMethodKicker)->getInputList());

		$_SERVER['REQUEST_METHOD'] = 'GET';
		$this->assertTrue((new RequestMethodKicker)->loadCoerciveList()->detect()->getStatus());

		$_SERVER['REQUEST_METHOD'] = 'TRACE';
		$this->assertFalse((new RequestMethodKicker)->loadCoerciveList()->detect()->getStatus());
	}

	public function testUrlKicker(): void
	{
		$this->assertSame(['/'], (new UrlKicker)->getInputList());
		$this->assertSame([], (new UrlKicker(false))->getInputList());

		$_SERVER['REQUEST_URI'] = '/wp-admin/setup-config.php?step=1';
		$kicker = new UrlKicker;
		$this->assertSame('/wp-admin/setup-config.php?step=1', $kicker->getRawUrl());
		$this->assertSame('/wp-admin/setup-config.php', $kicker->getUrl());
		$this->assertSame(['/wp-admin/setup-config.php'], $kicker->getInputList());
		$this->assertTrue($kicker->find('setup-config'));
		$this->assertFalse($kicker->find('nothing'));

		$kicker = (new UrlKicker(false))->setUrl('/a/b%20c/?x=1');
		$this->assertSame('/a/b c', $kicker->getUrl());
		$this->assertSame('/a/b%20c/?x=1', $kicker->setUrl('/a/b%20c/?x=1', false)->getUrl());

		$this->assertFalse((new UrlKicker(false))->setUrl('/page')->isMalformed());
		$this->assertTrue((new UrlKicker(false))->setUrl('/page...')->isMalformed());
		$this->assertTrue((new UrlKicker(false))->setUrl('/page/null')->isMalformed());

		$this->assertNotEmpty((new UrlKicker(false))->loadCoerciveLists()->getBlackList());
		$this->assertNotEmpty((new UrlKicker(false))->loadCoerciveGraylist()->getBlackList());
	}

	public function testInputKicker(): void
	{
		$this->assertSame([], (new InputKicker)->getInputList());

		$_GET = ['a' => 'one', 'b' => ['two', ['three']]];
		$_POST = ['c' => 4];
		$this->assertSame(['one', 'two', 'three', 4], (new InputKicker)->getInputList());
		$this->assertSame([4], (new InputKicker(false))->getInputList());
		$this->assertSame(['one', 'two', 'three'], (new InputKicker(true, false))->getInputList());

		$kicker = new InputKicker;
		$this->assertTrue($kicker->isValidUtf8());
		$this->assertSame('', $kicker->containsUrl());
		$this->assertNotEmpty($kicker->loadCoerciveLists()->getBlackList());
		$this->assertSame([], $kicker->loadCoerciveGraylist()->getBlackList());

		$_POST = ['c' => "\xC3\x28", 'd' => 'https://example.com/spam'];
		$kicker = new InputKicker;
		$this->assertFalse($kicker->isValidUtf8());
		$this->assertSame('https://example.com/spam', $kicker->containsUrl());
	}
}
