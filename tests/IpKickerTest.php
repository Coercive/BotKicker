<?php declare(strict_types=1);

use Coercive\Security\BotKicker\IpKicker;
use PHPUnit\Framework\TestCase;

final class IpKickerTest extends TestCase
{
	public function testList(): void
	{
        $ipk = new IpKicker(false);

        # Payplug (on OVH server)
        $this->assertTrue(in_array('54.77.126.191', $ipk->getPayPlugList()));
        $this->assertFalse(in_array('1.2.3.4', $ipk->getPayPlugList()));

        # Paybox (on ORANGE cloud services)
        $this->assertTrue(in_array('194.2.160.91', $ipk->getPayboxList()));
        $this->assertFalse(in_array('1.2.3.4', $ipk->getPayboxList()));

        # Prolexis (on OVH server)
        $this->assertTrue(in_array('54.36.182.4', $ipk->getProlexisList()));
        $this->assertFalse(in_array('1.2.3.4', $ipk->getProlexisList()));

        # Let's Encrypt (on AMAZON server)
        $this->assertTrue(in_array('52.89.215.165', $ipk->getLetsEncryptList()));
        $this->assertFalse(in_array('1.2.3.4', $ipk->getLetsEncryptList()));

        # FaceBook
        $list = $ipk->getFacebookList();
        $this->assertTrue(in_array('57.144.40.0/23', $list));
        $this->assertFalse(in_array('1.2.3.4', $list));

        # LinkedIn
        $list = $ipk->getLinkedInList();
        $this->assertTrue(in_array('45.42.65.0/24', $list));
        $this->assertFalse(in_array('1.2.3.4', $list));

        # GoogleBot
        $list = $ipk->getGoogleBotList();
        $this->assertTrue(in_array('66.249.71.224/27', $list));
        $this->assertFalse(in_array('1.2.3.4', $list));

        # Google Cloud
        $list = $ipk->getGoogleCloudList();
        $this->assertTrue(in_array('35.220.32.0/21', $list));
        $this->assertFalse(in_array('1.2.3.4', $list));

        # Google User
        $list = $ipk->getGoogleUserList();
        $this->assertTrue(in_array('34.3.0.0/23', $list));
        $this->assertFalse(in_array('1.2.3.4', $list));

        # Google Special Crawlers
        $list = $ipk->getGoogleSpecialCrawlersList();
        $this->assertTrue(in_array('66.249.91.64/27', $list));
        $this->assertFalse(in_array('1.2.3.4', $list));

        # Google User Triggered Fetchers
        $list = $ipk->getGoogleUserTriggeredFetchersList();
        $this->assertTrue(in_array('107.178.224.224/27', $list));
        $this->assertFalse(in_array('1.2.3.4', $list));

        # Google Triggered Fetchers
        $list = $ipk->getGoogleUserTriggeredFetchersGoogleList();
        $this->assertTrue(in_array('192.178.9.32/27', $list));
        $this->assertFalse(in_array('1.2.3.4', $list));

        # Mailjet (Mailgun server)
        $list = $ipk->getMailjetList();
        $this->assertTrue(in_array('143.55.237.0/24', $list));
        $this->assertFalse(in_array('1.2.3.4', $list));

        # Stripe (on AMAZON server)
        $list = $ipk->getStripeList();
        $this->assertTrue(in_array('13.56.126.253', $list));
        $this->assertFalse(in_array('1.2.3.4', $list));

        # Brevo (on SENDINBLUE server)
        $list = $ipk->getBrevoList();
        $this->assertTrue(in_array('212.146.244.0/24', $list));
        $this->assertFalse(in_array('1.2.3.4', $list));
	}
}