## Password Entropy Version 1.0

###License
 - This ElkArte addon is released under a MPL V1.1 license, a copy of it with its provisions is included with the package.
 - This addon uses the [Zxcbvn](https://github.com/bjeavons/zxcvbn-php]zxcvbn-php) library which is released under the GNU GENERAL PUBLIC LICENSE Version 3

###Introduction
This measures the effectiveness of a password in resisting guessing and brute-force attacks. In its usual form, it estimates how many trials an attacker who does not have direct access to the password would need, on average, to guess it correctly. The strength of a password is a function of length, complexity, and unpredictability.

Unlike basic entropy checks which grades based on the set of symbols (a-zA-A0-9etc) in potential use at each position, this goes further and takes in to account patterns that people will tend to follow and also compares entered passwords against a list of know common passwords that are in use and therefore vulnerable to attacks.

More information can be found [here](https://tech.dropbox.com/2012/04/zxcvbn-realistic-password-strength-estimation/)

###Features
 - Enable or disable the addon from the control panel
 - Require users to enter a password that meets a set threshold (good/strong/etc)
 - Show a strength meter on most pages where a password can be reset (profile, authentication, registration)
 - Hovering over the password meter will show the estimated time for a computer to crack a given password with a brute force attack