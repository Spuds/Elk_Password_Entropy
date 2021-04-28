/**
 * @package PWEntropy
 * @author Spuds
 * @copyright (c) 2011-2021 Spuds
 * @license This Source Code is subject to the terms of the Mozilla Public License
 * version 1.1 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/1.1/.
 *
 * @version 1.0
 *
 */

/**
 * Elk Password Entropy class
 */
(function ()
{
	function elkEntropy()
	{
	}

	elkEntropy.prototype = function ()
	{
		// global vars
		var passwd = null,
			EntropyLevels = {},
			TextStrings = {},
			shown = false,
			ajax_infobar = null,
			pwContainer = null,
			color_map = [
				"",
				"#C81818",
				"#FFAC1D",
				"#A6C060",
				"#27B30F"
			],
			word_map = [
				"poor",
				"weak",
				"ok",
				"strong",
				"excellent"
			],
			str = $('<div class="entropy_bar" title=""><div class="full_strength"></div><div class="current_percent">&nbsp;</div></div>'),

			/**
			 * Initializing function
			 *
			 * Moves passes params in to global function use
			 *
			 * @param {type} checkID id of the password field
			 * @param {type} pweEntropyLevel minimum score to pass
			 * @param {type} pweTextStrings text strings
			 */
			init = function (checkID, pweEntropyLevel, pweTextStrings, container)
			{
				passwd = $('#' + checkID);
				TextStrings = pweTextStrings ? pweTextStrings : [];
				EntropyLevel = pweEntropyLevel ? pweEntropyLevel : 3;
				pwContainer = container ? container : 'elk_autov_pwmain_div';

				// Bind to the input box
				passwd.on("keyup", function (e)
				{
					e.preventDefault();
					check();
				});

				// Divs to show an error if needed
				ajax_infobar = document.createElement('div');

				// Prepare the infobar to show an error
				$(ajax_infobar).css({'position': 'fixed', 'top': '0', 'left': '0', 'width': '100%'});
				$("body").append(ajax_infobar);
				$(ajax_infobar).slideUp();
			},

			// This is a field which requires some form of verification check.
			check = function ()
			{
				// Need to know what we are checking of course
				var values = {
					'passwd': passwd.val()
				};

				// Don't bother asking if its to short
				if (passwd.val().length < 4)
				{
					return;
				}

				// Make the ajax call to the entropy system
				$.ajax({
					url: elk_scripturl + '?action=pwentropy;sa=check;api;' + elk_session_var + '=' + elk_session_id,
					type: 'POST',
					dataType: 'json',
					data: values,
					cache: false
				})
					.done(function (resp)
					{
						// json response from the server says success?
						if (resp.result === true)
						{
							// Update the strength meter with the results
							updateUi({
								'entropy': resp.entropy,
								'crack_time': resp.crack_time,
								'score': resp.score,
								'crack_time_display': resp.crack_time_display
							});
						}
						// Some failure trying to process the request
						else
						{
							handleError(resp);
						}
					})
					.fail(function (err, textStatus, errorThrown)
					{
						// Some failure sending the request, this generally means some html in
						// the output from php error or access denied fatal errors etc
						err.data = TextStrings.error_occurred + ' : ' + errorThrown;
						handleError(err);
					});
			},

			/**
			 * Show a non modal error box when something goes wrong with
			 * sending the request or processing it
			 *
			 * @param {type} params
			 */
			handleError = function (params)
			{
				// Load and show the hidden div
				$(ajax_infobar).attr('class', 'infobox');
				$(ajax_infobar).html(params.data).slideDown('fast');
				setTimeout(function ()
				{
					$(ajax_infobar).slideUp();
				}, 3500);
			},

			/**
			 * Does the actual update to the strength meter
			 *
			 * @param {object} params object of new values from the ajax request
			 */
			updateUi = function (params)
			{
				// If we have not added the strength meter, nows a good time
				if (!shown)
				{
					$('#' + pwContainer).after(str);
					shown = true;
				}

				// Add in the time to crack as some hover text
				$('.entropy_bar').attr("title", TextStrings.timetocrack + ' : ' + params.crack_time_display);

				// Use the 0-4 score thats returned to update the strength meter text
				$(str).find('.full_strength').text(passwd.length ? TextStrings[word_map[params.score]] : "&nbsp;");

				// Set the width and color of the bar
				if (params.score === 0)
				{
					$(str).find('.current_percent').css({'width': '0%', 'background-color': color_map[params.score]});
				}
				else
				{
					$(str).find('.current_percent').css({
						'width': (params.score * 25) + "%",
						'background-color': color_map[params.score]
					});
				}
			};

		return {
			init: init,
			elkEntropy: elkEntropy
		};
	}();

	// Start it up
	this.elkEntropy = elkEntropy;
}());