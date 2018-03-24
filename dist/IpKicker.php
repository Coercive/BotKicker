<?php
namespace Coercive\Security\BotKicker;

/**
 * BOT KICKER
 *
 * @package		Coercive\Security\BotKicker
 * @link		@link https://github.com/Coercive/BotKicker
 *
 * @author  	Anthony Moral <contact@coercive.fr>
 * @copyright   (c) 2018 Anthony Moral
 * @license 	MIT
 */
class IpKicker extends AbstractKicker
{
	const DEFAULT_FILES = [
		self::COERCIVE_FILE,
	];

	const COERCIVE_FILE = __DIR__ . '/../list/ip/coercive';

	/**
	 * GET IP(s)
	 *
	 * @return void
	 */
	private function initIps()
	{
		# Get remote and forwarded
		$remote = filter_input(INPUT_SERVER, 'REMOTE_ADDR', FILTER_SANITIZE_FULL_SPECIAL_CHARS) ?: '';
		$forwarded = filter_input(INPUT_SERVER, 'HTTP_X_FORWARDED_FOR', FILTER_SANITIZE_FULL_SPECIAL_CHARS ?: '');
		$list = [];

		# Process forwarded ips
		if($forwarded) {

			# Remove spaces
			$forwarded = str_replace(' ', '', $forwarded);

			# List all ips as array
			$list = explode(',', $forwarded);
		}

		# Add the basic remote
		if($remote) { $list[] = $remote; }

		# Unique and not empty
		$this->currents = array_filter(array_unique($list));
	}

	/**
	 * UserAgentKicker constructor.
	 */
	public function __construct()
	{
		$this->initIps();
		$this->default = self::DEFAULT_FILES;
	}
}