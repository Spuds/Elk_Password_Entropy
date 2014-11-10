<?php

/**
 * @package PWEntropy
 * @author Spuds
 * @copyright (c) 2011-2014 Spuds
 * @license This Source Code is subject to the terms of the Mozilla Public License
 * version 1.1 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/1.1/.
 *
 * @version 1.0
 *
 */

namespace ZxcvbnPhp;

/**
 * The library uses some late static autoloading, this should take care
 * of that for this namespace
 */
spl_autoload_register(function ($class) {
	$class = str_replace('\\', '/', $class);
    include_once EXTDIR . '/' . $class . '.php';
});

/**
 * Quick class to interface to the library to enable password checking
 *
 * - Just load this class and do a
 * - $zxcvbn = new \ZxcvbnPhp\ZxcvbnPhp_Checker("some_string");
 * - $result = $zxcvbn->pwentropy_response;
 */
class ZxcvbnPhp_Checker
{
	/**
	 * password to check
	 * @var string
	 */
	protected $_passwd = '';

	/**
	 * Response from the entropy library
	 * @var mixed[]
	 */
	public $pwentropy_response = '';

	/**
	 * Load the passed string and run the checks
	 * @param string $pw
	 */
	public function __construct($pw)
	{
		$this->_passwd = $pw;
		$this->check();
	}

	/**
	 * Simply loads the library and gets the results
	 *
	 * @return mixed[]
	 */
	public function check()
	{
		// Going to need the library
		require_once(EXTDIR . '/ZxcvbnPhp/Zxcvbn.php');

		// Start up the checker
		$zxcvbn = new Zxcvbn();
		$this->pwentropy_response = $zxcvbn->passwordStrength($this->_passwd);

		return $this->pwentropy_response;
	}
}