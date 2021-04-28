<?php

/**
 * @package PWEntropy
 * @author Spuds
 * @copyright (c) 2011-2021 Spuds
 * @license This Source Code is subject to the terms of the Mozilla Public License
 * version 1.1 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/1.1/.
 *
 * @version 1.0.1
 *
 */

use ZxcvbnPhp\ZxcvbnPhp_Checker;


/**
 * This class handles the checking of a passwords entropy level
 *
 * - based on https://tech.dropbox.com/2012/04/zxcvbn-realistic-password-strength-estimation/
 *
 * @uses the ZxcvbnPhp library to do the checks
 */
class Pwentropy_Controller extends Action_Controller
{
	/**
	 * Holds the ajax response
	 *
	 * @var string[]
	 */
	protected $_pwentropy_response = array();

	/**
	 * If this was an ajax request or not
	 *
	 * @var boolean
	 */
	protected $_api = false;

	/**
	 * The password string being checked
	 *
	 * @var string
	 */
	protected $_passwd = null;

	/**
	 * PWEntopy settings form
	 *
	 * @var Settings_Form
	 */
	protected $_pweSettings;

	/**
	 * Default action method, if a specific methods wasn't
	 * directly called already. Simply forwards to check.
	 *
	 * @see Action_Controller::action_index()
	 */
	public function action_index()
	{
		// Going to check you out, that's right, uh-hu
		$this->action_check();
	}

	/**
	 * Checking a password via ajax, then _api will be added to the sa=
	 * and this method will be called
	 *
	 * - Calls the standard check method and then the api return method
	 */
	public function action_check_api()
	{
		$this->_api = true;
		$this->_passwd = !empty($_REQUEST['passwd']) ? $_REQUEST['passwd'] : '';
		$this->action_check();
	}

	/**
	 * Checking a password from a passed string
	 *
	 * - Calls the standard check method and then returns
	 *
	 * @param string $passwd password string to test
	 * @return array of response keys
	 */
	public function check_passed($passwd)
	{
		$this->_passwd = !empty($passwd) ? $passwd : '';
		$this->action_check();

		return $this->_pwentropy_response;
	}

	/**
	 * Checks a password string using the ZxcvbnPhp library
	 *
	 * - It is accessed via ?action=pwentropy;sa=check
	 */
	public function action_check()
	{
		global $modSettings;

		// If pwentropy is disabled, we don't go any further
		if (empty($modSettings['pwentropy_enabled']) && $_REQUEST['sa'] !== 'action_settings')
		{
			return [];
		}

		// Don't waste cycles on short passwords
		if (strlen($this->_passwd) > 3)
		{
			// Going to need to access library
			require_once(SUBSDIR . '/Pwentropy.class.php');

			// Run a check
			$zxcvbn = new ZxcvbnPhp_Checker($this->_passwd);
			$this->_pwentropy_response = $zxcvbn->pwentropy_response;
		}
		// Generic poor password response
		else
		{
			$this->_pwentropy_response = array(
				'score' => 0,
				'entropy' => 1,
				'crack_time' => 1,
			);
		}

		// Load in any pass/fail/error data to finish this
		$this->_min_required();
		$this->_finialize_results();

		// Back we go
		if ($this->_api)
		{
			$this->EntropyResponse();
		}

		return $this->_pwentropy_response;
	}

	/**
	 * When checking via ajax
	 *
	 * - Clears the templates
	 * - Returns a json response to the page
	 */
	private function EntropyResponse()
	{
		global $context;

		// Clear the templates
		$template_layers = Template_Layers::getInstance();
		$template_layers->removeAll();

		// Make room for ajax
		loadTemplate('Json');
		$context['sub_template'] = 'send_json';

		// Provide the response
		$context['json_data'] = $this->_pwentropy_response;
	}

	/**
	 * Loads the final details for the response
	 *
	 * - Loads the 'result' key and if possible the 'crack_time_display' key
	 */
	private function _finialize_results()
	{
		// Place the final touches in to the response array
		if (empty($this->_pwentropy_response))
		{
			$this->_pwentropy_response = array('result' => false);
		}
		else
		{
			$this->_pwentropy_response += array(
				'result' => true,
				'crack_time_display' => $this->_crack_time_to_display()
			);
		}
	}

	/**
	 * If we are enforcing a minimum score level, this checks it
	 *
	 * - Add in the 'valid' key to the response
	 */
	private function _min_required()
	{
		global $modSettings, $user_info;

		// If we can't check for some reason, no need to block them
		if (empty($this->_pwentropy_response))
		{
			$this->_pwentropy_response['valid'] = true;
		}

		// Determine a min level, if there is one at all
		$min_level = 0;
		if (($user_info['is_mod'] || $user_info['is_admin']) && !empty($modSettings['pwentropy_admin_mod']))
		{
			$min_level = $modSettings['pwentropy_admin_mod'];
		}
		elseif (!empty($modSettings['pwentropy_users']))
		{
			$min_level = $modSettings['pwentropy_users'];
		}

		// Does this pass or vail
		if (empty($min_level))
		{
			$this->_pwentropy_response['valid'] = true;
		}
		elseif ($this->_pwentropy_response['score'] >= $min_level)
		{
			$this->_pwentropy_response['valid'] = true;
		}
		else
		{
			$this->_pwentropy_response['valid'] = false;
		}
	}

	/**
	 * Converts the time to crack in to something readable
	 *
	 * - Crack_time is provided in seconds, this converts it to a weeks/months/years etc
	 */
	private function _crack_time_to_display()
	{
		global $txt;

		loadLanguage('pwentropy');

		// Time is a constant, relatively speaking
		$minute = 60;
		$hour = ($minute * 60);
		$day = ($hour * 24);
		$month = ($day * 31);
		$year = ($month * 12);
		$century = ($year * 100);

		// Pick a crack time, there are slow online to fast offline.
		// Slow: online_throttling_100_per_hour -> online_throttling_10_per_second -> offline_slow_hashing_1e4_per_second
		$crackTime = $this->_pwentropy_response['crack_times_seconds']['offline_slow_hashing_1e4_per_second'];

		// Provide a text response based on the seconds needed to crack a password
		if ($crackTime < $minute)
		{
			return $txt['pwentropy_instant'];
		}

		if ($crackTime < $hour)
		{
			return (1 + ceil($crackTime / $minute)) . ' ' . $txt['pwentropy_minutes'];
		}

		if ($crackTime < $day)
		{
			return (1 + ceil($crackTime / $hour)) . ' ' . $txt['pwentropy_hours'];
		}

		if ($crackTime < $month)
		{
			return (1 + ceil($crackTime / $day)) . ' ' . $txt['pwentropy_days'];
		}

		if ($crackTime < $year)
		{
			return (1 + ceil($crackTime / $month)) . ' ' . $txt['pwentropy_months'];
		}

		if ($crackTime < $century)
		{
			return (1 + ceil($crackTime / $year)) . ' ' . $txt['pwentropy_years'];
		}

		return $txt['pwentropy_centuries'];
	}

	/**
	 * This function handles pwentropy settings
	 *
	 * - General pwentropy settings.
	 * - Accessed by ?action=admin;area=regcenter;sa=pwentropy
	 * - Requires the admin_forum permission.
	 */
	public function action_pwentropySettings_display()
	{
		global $txt, $context, $scripturl;

		// Initialize the form
		$this->_init_pwentropySettingsForm();

		// Load the config vars
		$config_vars = $this->_pweSettings->settings();

		// Save if asked
		if (isset($_GET['save']))
		{
			checkSession();

			Settings_Form::save_db($config_vars);

			redirectexit('action=admin;area=regcenter;sa=pwentropy');
		}

		// Show the template otherwise
		$context['sub_template'] = 'show_settings';
		$context['settings_title'] = $txt['pwentropy_name'];
		$context['page_title'] = $context['settings_title'] = $txt['pwentropy_settings'];
		$context['post_url'] = $scripturl . '?action=admin;area=regcenter;sa=pwentropy;save';
		$context[$context['admin_menu_name']]['tab_data']['tabs']['pwentropy']['description'] = $txt['pwentropy_desc'];

		Settings_Form::prepare_db($config_vars);
	}

	/**
	 * Initialize settings form with the configuration settings for new members registration.
	 */
	private function _init_pwentropySettingsForm()
	{
		// This is really quite wanting.
		require_once(SUBSDIR . '/SettingsForm.class.php');

		// Instantiate the form
		$this->_pweSettings = new Settings_Form();

		// Initialize it with our settings
		$config_vars = $this->_settings();

		return $this->_pweSettings->settings($config_vars);
	}

	/**
	 * Return configuration settings for new members registration.
	 */
	private function _settings()
	{
		global $txt;

		// All the options, well at least some of them, ok just 3 right now
		return array(
			array('desc', 'pwentropy_note'),
			array('check', 'pwentropy_enabled'),
			array('select', 'pwentropy_admin_mod', array($txt['pwentropy_none'], $txt['pwentropy_weak'], $txt['pwentropy_ok'], $txt['pwentropy_strong'], $txt['pwentropy_excellent'])),
			array('select', 'pwentropy_users', array($txt['pwentropy_none'], $txt['pwentropy_weak'], $txt['pwentropy_ok'], $txt['pwentropy_strong'], $txt['pwentropy_excellent']), 'postinput' => $txt['pwentropy_users_note']),
		);
	}
}