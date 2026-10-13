<?php
namespace Coercive\Security\BotKicker\Tests;

use Coercive\Security\BotKicker\Syslog\SyslogUfw;
use Coercive\Security\BotKicker\Syslog\SyslogUfwLineEntity;
use Exception;
use PHPUnit\Framework\TestCase;

final class SyslogUfwTest extends TestCase
{
	private string $path;

	private function line(string $src, string $proto, ? int $dpt, string $in = 'eth0', string $out = '', string $flags = 'SYN'): string
	{
		return "Oct 13 10:00:00 server kernel: [UFW BLOCK] IN=$in OUT=$out MAC=00:00 SRC=$src DST=5.6.7.8 LEN=40 TTL=50 ID=0 PROTO=$proto"
			. ($dpt !== null ? " SPT=12345 DPT=$dpt WINDOW=1024 RES=0x00" : ' TYPE=8 CODE=0')
			. " $flags URGP=0 ";
	}

	protected function setUp(): void
	{
		$this->path = tempnam(sys_get_temp_dir(), 'ufw');
		file_put_contents($this->path, implode("\n", [
			$this->line('1.1.1.1', 'TCP', 443),
			$this->line('1.1.1.1', 'TCP', 80),
			$this->line('2.2.2.2', 'TCP', 22),
			$this->line('3.3.3.3', 'ICMP', null),
			$this->line('4.4.4.4', 'UDP', 443),
			$this->line('5.5.5.5', 'TCP', 443, 'eth0', '', 'ACK RST'),
			$this->line('6.6.6.6', 'TCP', 443, '', 'eth0'),
			$this->line('6.6.6.6', 'TCP', 443, 'eth0', 'eth1'),
			'',
			'garbage line',
		]) . "\n");
	}

	protected function tearDown(): void
	{
		@unlink($this->path);
	}

	public function testLoad(): void
	{
		$ufw = new SyslogUfw($this->path);
		$matches = $ufw->getMatches();

		$this->assertSame(['1.1.1.1', '2.2.2.2', '3.3.3.3', '4.4.4.4', '5.5.5.5', '6.6.6.6'], array_keys($matches));
		$this->assertSame(["garbage line\n"], $ufw->getErrors());

		$this->assertFalse($matches['1.1.1.1']->isBlocked());
		$this->assertSame(2, $matches['1.1.1.1']->getCount());
		$this->assertSame(2, $matches['1.1.1.1']->getIn());
		$this->assertSame([443 => 443, 80 => 80], $matches['1.1.1.1']->getPorts());
		$this->assertSame(1, $matches['1.1.1.1']->countProtocols());

		$this->assertTrue($matches['2.2.2.2']->isBlocked());
		$this->assertFalse($matches['3.3.3.3']->isBlocked());
		$this->assertTrue($matches['4.4.4.4']->isBlocked());

		$this->assertFalse($matches['5.5.5.5']->isBlocked());
		$this->assertSame(1, $matches['5.5.5.5']->getReset());
		$this->assertSame(0, $matches['5.5.5.5']->getCount());

		$this->assertSame(1, $matches['6.6.6.6']->getOut());
		$this->assertSame(1, $matches['6.6.6.6']->getFw());
		$this->assertCount(2, $matches['6.6.6.6']->getLines());
	}

	public function testLineEntity(): void
	{
		$line = new SyslogUfwLineEntity($this->line('2001:db8::1', 'TCP', 22));
		$this->assertSame([], $line->getErrors());
		$this->assertSame('2001:db8::1', $line->getIp());
		$this->assertSame('TCP', $line->getProtocol());
		$this->assertSame(12345, $line->getSourcePort());
		$this->assertSame(22, $line->getDestinationPort());
		$this->assertTrue($line->isIncoming());
		$this->assertFalse($line->getReset());

		$this->assertCount(2, (new SyslogUfwLineEntity('nothing'))->getErrors());
	}

	public function testMissingFile(): void
	{
		$this->expectException(Exception::class);
		new SyslogUfw('/not/a/file');
	}
}
