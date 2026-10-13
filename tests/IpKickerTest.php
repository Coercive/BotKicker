<?php
namespace Coercive\Security\BotKicker\Tests;

use Coercive\Security\BotKicker\IpKicker;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\TestCase;

final class IpKickerTest extends TestCase
{
	public function testStaticLists(): void
	{
		$ipk = new IpKicker;

		# Payplug (on OVH server)
		$this->assertContains('54.77.126.191', $ipk->getPayPlugList());

		# Paybox (on ORANGE cloud services)
		$this->assertContains('194.2.160.91', $ipk->getPayboxList());
		$this->assertSame(array_values(array_unique($ipk->getPayboxList())), $ipk->getPayboxList());

		# Prolexis (on OVH server)
		$this->assertContains('54.36.182.4', $ipk->getProlexisList());

		# Monetico
		$this->assertContains('145.226.0.0/16', $ipk->getMoneticoList());

		# Let's Encrypt (on AMAZON server)
		$this->assertContains('52.89.215.165', $ipk->getLetsEncryptList());

		# Mailjet (Mailgun server)
		$this->assertContains('143.55.237.0/24', $ipk->getMailjetList());

		# Stripe (on AMAZON server)
		$this->assertContains('13.56.126.253', $ipk->getStripeList());

		# Brevo (on SENDINBLUE server)
		$this->assertContains('212.146.244.0/24', $ipk->getBrevoList());

		# Cloudflare / Bing
		$this->assertNotEmpty($ipk->getCloudflareList());
		$this->assertNotEmpty($ipk->getBingList());

		foreach ([$ipk->getLetsEncryptList(), $ipk->getStripeList(), $ipk->getBingList()] as $list) {
			$this->assertNotContains('1.2.3.4', $list);
		}
	}

	public function testCoerciveList(): void
	{
		$ipk = (new IpKicker)->loadCoerciveList();
		$this->assertFalse($ipk->setInputList(['223.1.2.3'])->detect()->getStatus());
		$this->assertTrue($ipk->setInputList(['1.2.3.4'])->detect()->getStatus());
	}

	#[Group('network')]
	public function testDynamicLists(): void
	{
		$ipk = new IpKicker;

		# FaceBook
		$list = $ipk->getFacebookList();
		$this->assertContains('57.144.40.0/23', $list);
		$this->assertNotContains('1.2.3.4', $list);

		# LinkedIn
		$this->assertContains('45.42.65.0/24', $ipk->getLinkedInList());

		# Bing
		$this->assertNotEmpty($ipk->getBingList(true));

		# GoogleBot
		$this->assertContains('66.249.71.224/27', $ipk->getGoogleBotList());
		$this->assertNotEmpty($ipk->getGoogleBotList(true));
		$this->assertStringContainsString(':', $ipk->getGoogleBotList(true)[0]);

		# Google Cloud
		$this->assertContains('35.220.32.0/21', $ipk->getGoogleCloudList());

		# Google User
		$this->assertContains('34.3.0.0/23', $ipk->getGoogleUserList());

		# Google Special Crawlers
		$this->assertContains('66.249.91.64/27', $ipk->getGoogleSpecialCrawlersList());

		# Google User Triggered Fetchers
		$this->assertContains('107.178.224.224/27', $ipk->getGoogleUserTriggeredFetchersList());

		# Google Triggered Fetchers
		$this->assertContains('192.178.9.32/27', $ipk->getGoogleUserTriggeredFetchersGoogleList());
	}
}
