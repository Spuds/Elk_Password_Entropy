<?php

/**
 * @package PWEntropy
 * @author Spuds
 * @copyright (c) 2011-2013 Spuds
 * @license This Source Code is subject to the terms of the Mozilla Public License
 * version 1.1 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/1.1/.
 *
 * @version 1.0
 *
 */

if (!defined('ELK'))
	die('No access...');

/**
 * irc_pwentropy()
 *
 * - integrate_register_check, called from members.subs
 * - adds additional registration checks in place, here password score checking
 *
 * @param mixed[] $regOptions
 * @param object $reg_errors
 */
function irc_pwentropy(&$regOptions, &$reg_errors)
{
	global $modSettings;

	if (empty($modSettings['pwentropy_enabled']))
		return;

	// Going to need to access library
	require_once(CONTROLLERDIR . '/Pwentropy.controller.php');

	// Run a check
	$entropy = new Pwentropy_Controller();
	$pwentropy_response = $entropy->check_passed($regOptions['password']);

	// If its does not meet the requirements set an error
	if (empty($pwentropy_response['valid']))
	{
		loadLanguage('pwentropy');
		$reg_errors->addError('pwentropy_error_password');
	}
}

/**
 *  imr_pwentropy()
 *
 * - integrate_manage_registrations, Called from ManageRegistration.controller
 * - Used to add items to the registration subAction array
 *
 * @param mixed[] $subActions
 */
function imr_pwentropy(&$subActions)
{
	global $context, $txt, $modSettings;

	if (empty($modSettings['pwentropy_enabled']))
		return;

	loadLanguage('pwentropy');

	// Registering a new member, add the strength meter to the template
	if (isset($_REQUEST['sa']) && $_REQUEST['sa'] === 'register')
	{
		loadJavascriptFile('pwentropy.js');
		loadCSSFile('pwentropy.css');
		load_pwentropy_js('password_input', 'password_input');
	}

	// Add the strength meter settings panel
	$subActions['pwentropy'] = array(
		'file' => 'Pwentropy.controller.php',
		'dir' => CONTROLLERDIR,
		'controller' => 'Pwentropy_Controller',
		'function' => 'action_pwentropySettings_display',
		'permission' => 'admin_forum'
	);

	$context[$context['admin_menu_name']]['tab_data']['tabs']['pwentropy'] = array(
		'description' => $txt['pwentropy_desc'],
	);
}

/**
 * iaa_pwentropy()
 *
 * - Admin Hook, integrate_admin_areas, called from Admin.php
 * - used to add/modify admin menu areas
 *
 * @param mixed[] $admin_areas
 */
function iaa_pwentropy(&$admin_areas)
{
	global $txt, $modSettings, $scripturl;

	loadlanguage('pwentropy');

	// Load the admin menu, set the URL to force the execution path through action_index
	$admin_areas['members']['areas']['regcenter']['subsections']['pwentropy'] = array(
		$txt['pwentropy_name'],
		'admin_forum',
		'enabled' => !empty($modSettings['pwentropy_enabled']),
		'url' => $scripturl . '?action=admin;area=regcenter;sa=pwentropy');
}

/**
 * irb_pwentropy
 *
 * - integrate_register_before, called from Dispatcher.class
 * - generic integration hook to enable items before a controller is called
 *
 * @param string $action
 */
function irb_pwentropy($action)
{
	global $modSettings;

	if (empty($modSettings['pwentropy_enabled']))
		return;

	// Attach our meter if they are a new registration
	if ($action === 'action_register' || $action === 'action_register2')
	{
		loadJavascriptFile('pwentropy.js');
		loadCSSFile('pwentropy.css');
		load_pwentropy_js('elk_autov_pwmain');
	}
}

/**
 * ipb_pwentropy
 *
 * - integrate_profile_before, called from Dispatcher.class
 * - generic integration hook to enable items before a controller is called
 *
 * @param string $action
 */
function ipb_pwentropy($action)
{
	global $modSettings;

	if (empty($modSettings['pwentropy_enabled']))
		return;

	// Attach our JS if they are changing authentication passwords
	if (isset($_GET['area']) && $_GET['area'] === 'authentication')
	{
		loadJavascriptFile('pwentropy.js');
		loadCSSFile('pwentropy.css');
		load_pwentropy_js('elk_autov_pwmain');
	}
}

/**
 * Loads the javascript that enables the strength meter on a page
 *
 * @param string $area id of the field that has the password to check
 * @param string $container id of the container that the strength meter will be
 * added after
 */
function load_pwentropy_js($area, $container = 'elk_autov_pwmain_div')
{
	global $txt;

	loadLanguage('pwentropy');

	// Load the strength meter basics
	addInlineJavascript('
		var pweTextStrings = {
			"error_occurred": "' . $txt['pwentropy_error'] . '",
			"poor": "' . $txt['pwentropy_poor'] . '",
			"weak": "' . $txt['pwentropy_weak'] . '",
			"ok": "' . $txt['pwentropy_ok'] . '",
			"strong": "' . $txt['pwentropy_strong'] . '",
			"excellent": "' . $txt['pwentropy_excellent'] . '",
			"timetocrack": "' . $txt['pwentropy_timetocrack'] . '"
		};

		elkEntropy.prototype.init("' . $area . '", 3, pweTextStrings, "' . $container . '");', true);
}

/**
 * ilpf_pwenropy()
 *
 * - integrate_load_profile_fields, called from profile.subs
 * - used to inject our validation requirements in the input_valid functions
 * - Ugly, just like profile fields
 *
 * @param type $profile_fields
 */
function ilpf_pwentropy(&$profile_fields)
{
	// There is the ability for admins to change a password of a user,
	// this does not check that value
	$profile_fields['passwrd1']['input_validate'] = create_function('&$value', '
				global $user_info, $cur_profile, $modSettings, $txt;

				$db = database();

				// If we didn\'t try it then ignore it!
				if ($value == \'\')
					return false;

				// Do the two entries for the password even match?
				if (!isset($_POST[\'passwrd2\']) || $value != $_POST[\'passwrd2\'])
					return \'bad_new_password\';

				// Let\'s get the validation function into play...
				require_once(SUBSDIR . \'/Auth.subs.php\');
				$passwordErrors = validatePassword($value, $cur_profile[\'member_name\'], array($cur_profile[\'real_name\'], $user_info[\'username\'], $user_info[\'name\'], $user_info[\'email\']));

				// Were there errors?
				if ($passwordErrors != null)
					return \'password_\' . $passwordErrors;

				if (!empty($modSettings[\'pwentropy_enabled\']))
				{
					// Run a entropy score check
					require_once(CONTROLLERDIR . \'/Pwentropy.controller.php\');
					$entropy = new Pwentropy_Controller();
					$pwentropy_response = $entropy->check_passed($value);

					// If its does not meet the requirments set an error
					if (empty($pwentropy_response[\'valid\']))
					{
						loadLanguage(\'pwentropy\');
						return $txt[\'pwentropy_error_password\'];
					}
				}

				// Set up the new password variable... ready for storage.
				require_once(SUBSDIR . \'/Auth.subs.php\');
				$value = validateLoginPassword($value, \'\', $cur_profile[\'member_name\'], true);
				return true;');
}

/**
 * Profile fields hook, integrate_' . $hook . '_profile_fields
 *
 * - Called from Profile.subs.php / setupProfileContext
 * - Used to add additional sections to the profile context areas
 * - Here we inject JS when the account page is loaded.
 *
 * @param mixed[] $fields
 */
function iapf_pwentropy(&$fields)
{
	global $modSettings;

	if (empty($modSettings['pwentropy_enabled']))
		return;

	// Attach our JS if they are changing authentication passwords
	loadJavascriptFile('pwentropy.js');
	loadCSSFile('pwentropy.css');
	load_pwentropy_js('passwrd1', 'passwrd1');
}