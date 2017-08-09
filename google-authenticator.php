<?php
/*
Plugin Name: 2-Factor Authentication
Plugin URI: http://henrik.schack.dk/google-authenticator-for-wordpress
Description: Two-Factor Authentication for WordPress using the Android/iPhone/Blackberry app as One Time Password generator.
Author: Henrik Schack
Version: 0.48
Author URI: http://henrik.schack.dk/
Compatibility: WordPress 4.5
Text Domain: google-authenticator
Domain Path: /lang

----------------------------------------------------------------------------

	Thanks to Bryan Ruiz for his Base32 encode/decode class, found at php.net.
	Thanks to Tobias Bäthge for his major code rewrite and German translation.
	Thanks to Pascal de Bruijn for his relaxed mode idea.
	Thanks to Daniel Werl for his usability tips.
	Thanks to Dion Hulse for his bugfixes.
	Thanks to Aldo Latino for his Italian translation.
	Thanks to Kaijia Feng for his Simplified Chinese translation.
	Thanks to Ian Dunn for fixing some depricated function calls.
	Thanks to Kimmo Suominen for fixing the iPhone description issue.
	Thanks to Alex Concha for some security tips.
	Thanks to Sébastien Prunier for his Spanish and French translations.

----------------------------------------------------------------------------

    Copyright 2013  Henrik Schack  (email : henrik@schack.dk)

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

class GoogleAuthenticator {

	static $instance; // to store a reference to the plugin, allows other plugins to remove actions

	/**
	 * Constructor, entry point of the plugin
	 */
	function __construct() {
	    self::$instance = $this;
	    add_action( 'init', array( $this, 'init' ) );
	}

	/**
	 * Initialization, Hooks, and localization
	 */
	function init() {
		require_once( 'base32.php' );

		add_action( 'login_form', array( $this, 'loginform' ) );
		add_action( 'login_footer', array( $this, 'loginfooter' ) );
		add_filter( 'authenticate', array( $this, 'is_authenticator_enabled' ), 50, 3 );
		add_filter( 'authenticate', array( $this, 'check_otp' ), 60, 3 );

		if ( is_admin() ) {
			add_action( 'profile_personal_options', array( $this, 'profile_personal_options' ) );
			add_action( 'personal_options_update', array( $this, 'personal_options_update' ) );
			add_action( 'edit_user_profile', array( $this, 'edit_user_profile' ) );
			add_action( 'edit_user_profile_update', array( $this, 'edit_user_profile_update' ) );
		}

		if ( defined( 'DOING_AJAX' ) && DOING_AJAX ) {
		    add_action( 'wp_ajax_GoogleAuthenticator_action', array( $this, 'ajax_callback' ) );

		    add_action( 'wp_ajax_personal_options_ajax_submit_otp', array( $this, 'ajax_personal_options_submit_otp_callback' ) );
			add_action( 'wp_ajax_nopriv_personal_options_ajax_submit_otp', array( $this, 'ajax_personal_options_submit_otp_callback' ) );
			
			add_action( 'wp_ajax_remote_hipwee_GA_app_password', array( $this, 'ajax_GA_app_password_callback' ) );
			add_action( 'wp_ajax_GoogleAuthenticator_generate_new_password', array( $this, 'GoogleAuthenticator_generate_new_password_callback' ) );
		}

		add_action( 'admin_footer', array($this, 'ga_embed_footer_scripts') );
		add_action( 'wp_footer', array($this, 'ga_embed_footer_scripts') );

		add_action( 'admin_menu', array( $this, 'setting_menu' ) );

		add_action( 'admin_notices', array($this, 'hipwee_google_authenticator_sample_admin_notice') );

		$plugin = plugin_basename( __FILE__ );
		add_filter( "plugin_action_links_$plugin", array($this, 'plugin_add_settings_link') );

		add_action( 'admin_enqueue_scripts', array($this, 'add_qrcode_script') );
		add_action( 'login_enqueue_scripts', array($this, 'login_script') );

		load_plugin_textdomain( 'google-authenticator', false, basename( dirname( __FILE__ ) ) . '/lang' );
	}

	/**
	 * Add settings button on plugin actions
	 */
	function plugin_add_settings_link( $links ) {
		$settings_link = '<a href="options-general.php?page=google-authenticator">' . __( 'Settings' ) . '</a>';
		array_unshift( $links, $settings_link );
		return $links;
	}

	/**
	 * Check the verification code entered by the user.
	 */
	function verify( $secretkey, $thistry, $relaxedmode, $lasttimeslot ) {

		// Did the user enter 6 digits ?
		if ( strlen( $thistry ) != 6) {
			return false;
		} else {
			$thistry = intval ( $thistry );
		}

		// If user is running in relaxed mode, we allow more time drifting
		// ±2 min, as opposed to ± 30 seconds in normal mode.
		if ( $relaxedmode == 'enabled' ) {
			$firstcount = -4;
			$lastcount  =  4; 
		} else {
			$firstcount = -1;
			$lastcount  =  1; 	
		}
		
		$tm = floor( time() / 30 );
		
		$secretkey=Base32::decode($secretkey);
		// Keys from 30 seconds before and after are valid aswell.
		for ($i=$firstcount; $i<=$lastcount; $i++) {
			// Pack time into binary string
			$time = chr(0).chr(0).chr(0).chr(0).pack('N*',$tm+$i);
			// Hash it with users secret key
			$hm = hash_hmac( 'SHA1', $time, $secretkey, true );
			// Use last nipple of result as index/offset
			$offset = ord(substr($hm,-1)) & 0x0F;
			// grab 4 bytes of the result
			$hashpart = substr($hm,$offset,4);
			// Unpak binary value
			$value = unpack("N",$hashpart);
			$value = $value[1];
			// Only 32 bits
			$value = $value & 0x7FFFFFFF;
			$value = $value % 1000000;
			if ( $value === $thistry ) {
				/** 
				 * Check for replay (Man-in-the-middle) attack.
				 * Since this is not Star Trek, time can only move forward,
				 * meaning current login attempt has to be in the future compared to
				 * last successful login.
				 */
				if ( $lasttimeslot >= ($tm+$i) ) {
					error_log("2-Factor Authentication plugin: Man-in-the-middle attack detected (Could also be 2 legit login attempts within the same 30 second period)");
					return false;
				}

				// Return timeslot in which login happened.
				return $tm+$i;
			}
		}

		return false;
	}

	/**
	 * Create a new random secret for the 2-Factor Authentication app.
	 * 16 characters, randomly chosen from the allowed Base32 characters
	 * equals 10 bytes = 80 bits, as 256^10 = 32^16 = 2^80
	 */ 
	function create_secret() {
		$chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'; // allowed characters in Base32
		$secret = '';
		for ( $i = 0; $i < 16; $i++ ) {
			$secret .= substr( $chars, wp_rand( 0, strlen( $chars ) - 1 ), 1 );
		}
		return $secret;
	}

	/**
	 * Add the script to generate QR codes.
	 */
	function add_qrcode_script() {
		wp_enqueue_script( 'jquery' );

		wp_register_script( 'qrcode_script', plugins_url('jquery.qrcode.min.js', __FILE__), array("jquery" ) );
		wp_enqueue_script( 'qrcode_script' );

		wp_enqueue_style( 'google_auth', plugins_url('admin-style.css', __FILE__) );

		wp_register_script( 'GA_SCRIPT', plugins_url('js/scripts.js', __FILE__), array("jquery" ) );
		wp_enqueue_script( 'GA_SCRIPT' );
	}

	/**
	 * Add the script to generate QR codes.
	 */
	function login_script() {
		wp_enqueue_script('jquery');
		wp_register_script('qrcode_script', plugins_url('jquery.qrcode.min.js', __FILE__),array("jquery"));
		wp_enqueue_script('qrcode_script');
		wp_enqueue_style('google_auth', plugins_url('login-style.css', __FILE__));
	}

	function wpse17709_gettext($translation, $text) {
		if ( 'Log In' == $text ) {
			return 'Authorize';
		}

		return $translation;
	}

	/**
	 * Add verification code field to login form.
	 */
	function loginform() {
		$GA_label = 'User';
		$GA_description = get_bloginfo('name');

		// unset($_SESSION["google_authenticator_pre_login_id"]);
		if ( isset($_SESSION["google_authenticator_pre_login_id"]) && FALSE !== get_userdata($_SESSION["google_authenticator_pre_login_id"]) && !empty($_POST['log']) && !empty($_POST['pwd']) ) {
			
			add_filter( 'gettext', array($this, 'wpse17709_gettext'), 10, 2 );

			$user_id = $_SESSION["google_authenticator_pre_login_id"];
			$userdata = get_userdata($user_id);
			$GA_secret = trim( get_user_option( 'googleauthenticator_secret', $user_id ) );
			if ( isset($_SESSION['google_authenticator_create_new_secret']) && $_SESSION['google_authenticator_create_new_secret'] == 1 ) { 
				if ( '' == $GA_secret ) {
					$GA_secret = $this->create_secret();
				} 

				$GA_label = $userdata->user_login;
				$GA_label = ucwords($GA_label);
				$GA_label = str_replace(' ', '', $GA_label);
				$GA_label = rawurlencode($GA_label);

				if ( get_option('google_authenticator_description') ) {
					$GA_description = get_option('google_authenticator_description');
				}

				echo "\t<ol class='auth_message'>\n";
				echo "\t<li>".__('Download authy / other 2-Factor Authentication or 2-Step Verification App on your android or iphone.','google-authenticator')."</li>\n";
				echo "\t<li>";
				echo __('Scan this barcode or Enter the key manually.','google-authenticator') . "\n";
				echo "Your key: <strong>" . $GA_secret . "</strong>";
				echo "</li>\n";
				echo "\t<li>".__('Enter the authorization code.','google-authenticator')."</li>\n";
				echo "\t<li>".__('You are good to go!','google-authenticator')."</li>\n";
				echo "\t</ol>\n";
				echo "\t<div id='GA_QRCODE'></div>\n";
				echo "\t\t<input type=\"hidden\" name=\"ga_secret\" value=\"".$GA_secret."\">";
			}
			echo "\t<p class='auth_code'>\n";
			echo "\t\t<label>".__('Authorization Code','google-authenticator')."<span id=\"google-auth-info\"></span><br />\n";
			echo "\t\t<input type=\"text\" name=\"googleotp\" id=\"user_email\" class=\"input\" value=\"\" size=\"20\" style=\"ime-mode: inactive;\" /></label>\n";
			echo "\t</p>\n";
			
			if ( !isset($_SESSION['invalid_google_authenticator_password']) || $_SESSION['invalid_google_authenticator_password'] != 1 ) { ?>
				<style type="text/css">
					.login #login_error {
						border-left-color: #00a0d2 !important;
					}
				</style>
				<?php 
			} 

			?>
			<style type="text/css">
				label[for="user_login"],label[for="user_pass"] {
					display: none;
				}
				p.forgetmenot {
					display: none;
				}
			</style>
			<script type="text/javascript">
				var qrcode="otpauth://totp/<?php echo $GA_label ?>:<?php echo rawurlencode($GA_description) ?>?secret=<?php echo $GA_secret; ?>&issuer=<?php echo $GA_label ?>";
				jQuery('#GA_QRCODE').qrcode(qrcode);
				jQuery('#user_login').val('<?php echo $_POST['log'] ?>').attr('type', 'hidden');
				jQuery('#user_pass').val('<?php echo $_POST['pwd'] ?>').attr('type', 'hidden');
				if ('<?php echo isset($_POST['rememberme']) ? $_POST['rememberme'] : '' ?>' === 'forever') {
					jQuery('#rememberme').prop('checked', true);
				}
			</script>
			<?php 
		}
	}

	/**
	 * Disable autocomplete on 2-Factor Authentication code input field.
	 */
	function loginfooter() {
		echo "\n<script type=\"text/javascript\">\n";
		echo "\ttry{\n";
		echo "\t\tdocument.getElementById('user_email').setAttribute('autocomplete','off');\n";
		echo "\t} catch(e){}\n";
		echo "</script>\n";
	}

	function is_authenticator_enabled( $user, $username = '', $password = '') {
		if ( !session_id() ) {
			session_start();
		}
		
		$forced_roles = get_option( 'google_authenticator_roles', array() );
		if ( isset( $user->ID ) && !isset($_POST['googleotp'])) {
			if ( 'enabled' == trim( get_user_option( 'googleauthenticator_enabled', $user->ID ) ) || !empty(array_intersect($user->roles, $forced_roles)) ) {
				
				$_SESSION["google_authenticator_pre_login_id"] = $user->ID;
				
				$GA_secret = trim( get_user_option( 'googleauthenticator_secret', $user->ID ) );
				if ( '' == $GA_secret ) {
					$_SESSION['google_authenticator_create_new_secret'] = 1;

					return new WP_Error( 'authenticate_needed', __( 'Enable your 2-FA', 'google-authenticator' ) );
				} else {
					$_SESSION['google_authenticator_create_new_secret'] = 0;
					$_SESSION['invalid_google_authenticator_password'] = 0;

					return new WP_Error( 'authenticate_needed', __( 'Insert your Authorization Code', 'google-authenticator' ) );
				}
			} else {
				return new WP_User( $user->ID );
			}
		}

		return $user;
	}

	/**
	 * Login form handling.
	 * Check 2-Factor Authentication verification code, if user has been setup to do so.
	 * @param wordpressuser
	 * @return user/loginstatus
	 */
	function check_otp( $user, $username = '', $password = '' ) {
		// Store result of loginprocess, so far.
		$userstate = $user;

		// Get information on user, we need this in case an app password has been enabled,
		// since the $user var only contain an error at this point in the login flow.
		if ( get_user_by( 'email', $username ) === false ) {
			$user = get_user_by( 'login', $username );
		} else {
			$user = get_user_by( 'email', $username );
		}

		// Does the user have the 2-Factor Authentication enabled ?
		if ( isset( $user->ID ) && isset($_SESSION["google_authenticator_pre_login_id"]) && $user->ID == $_SESSION["google_authenticator_pre_login_id"] && isset($_POST['googleotp']) ) {

			// Get the users secret
			$GA_secret = trim( get_user_option( 'googleauthenticator_secret', $user->ID ) );

			if ( isset($_POST['ga_secret']) ) {
				update_user_option( $user->ID, 'googleauthenticator_secret', $_POST['ga_secret'], true );
				$GA_secret = $_POST['ga_secret'];
			}
			
			// Figure out if relaxed mode is active ?
			$GA_relaxedmode = trim( get_option( 'google_authenticator_relaxedmode' ) );
			
			// Get the verification code entered by the user trying to login
			if ( !empty( $_POST['googleotp'] )) { // Prevent PHP notices when using app password login
				$otp = trim( $_POST[ 'googleotp' ] );
			} else {
				$otp = '';
			}

			// When was the last successful login performed ?
			$lasttimeslot = trim( get_user_option( 'googleauthenticator_lasttimeslot', $user->ID ) );
			// Valid code ?
			if ( $timeslot = $this->verify( $GA_secret, $otp, $GA_relaxedmode, $lasttimeslot ) ) {
				unset($_SESSION["google_authenticator_pre_login_id"]);
				unset($_SESSION['google_authenticator_create_new_secret']);
				unset($_SESSION["invalid_google_authenticator_password"]);

				// Store the timeslot in which login was successful.
				update_user_option( $user->ID, 'googleauthenticator_lasttimeslot', $timeslot, true );

				return $userstate;
			} else {
				// No, lets see if an app password is enabled, and this is an XMLRPC / APP login ?
				if ( 'enabled' == trim( get_option( 'google_authenticator_pwdenabled' ) ) && trim( get_user_option( 'googleauthenticator_pwdenabled', $user->ID ) ) == 'enabled' ) {
					$GA_passwords 	= json_decode(  get_user_option( 'googleauthenticator_passwords', $user->ID ) );
					$passwordhash	= trim( $GA_passwords->{'password'} );
					$usersha1		= sha1( strtoupper( str_replace( ' ', '', $password ) ) );
					if ( $passwordhash == $usersha1 ) { // ToDo: Remove after some time when users have migrated to new format
						unset($_SESSION["google_authenticator_pre_login_id"]);
						unset($_SESSION["invalid_google_authenticator_password"]);

						return new WP_User( $user->ID );
					} 
					// Try the new version based on thee wp_hash_password function
					elseif ( wp_check_password( strtoupper( str_replace( ' ', '', $otp ) ), $passwordhash ) ) {
						unset($_SESSION["google_authenticator_pre_login_id"]);
						unset($_SESSION["invalid_google_authenticator_password"]);

						return new WP_User( $user->ID );
					} 
					else {
						$_SESSION['invalid_google_authenticator_password'] = 1;

						// Wrong XMLRPC/APP password !
						return new WP_Error( 'invalid_google_authenticator_password', __( '<strong>ERROR</strong>: The App Password is incorrect.', 'google-authenticator' ) );
					} 		 
				} else {
					$_SESSION['invalid_google_authenticator_password'] = 1;

					return new WP_Error( 'invalid_google_authenticator_token', __( '<strong>ERROR</strong>: The Authorization Code is incorrect or has expired.', 'google-authenticator' ) );
				}	
			}
		}

		// 2-Factor Authentication isn't enabled for this account,
		// just resume normal authentication.
		return $userstate;
	}

	/**
	 * Extend personal profile page with 2-Factor Authentication settings.
	 */
	function profile_personal_options($user) {
		global $wpdb, $is_profile_page;

		$user_id = $user->ID;

		if ( isset($_GET['action']) && wp_verify_nonce(@$_GET['action'], 'google_authenticator_remove_secret') ) {
			
			delete_user_option($user_id, 'googleauthenticator_secret'); // blog spesific 
			delete_user_option($user_id, 'googleauthenticator_secret', true); // global (network wide) 
			
			if ( isset($_GET['wp_http_referer']) ) {
				wp_redirect($_GET['wp_http_referer']);
				exit;
			} else {
				$redirect_to = add_query_arg( 
					array( 
						'reset_secret' => 1 
					), 
					admin_url('profile.php') 
				);

				wp_redirect($redirect_to);
				exit;
			}
		}

		// If editing of 2-Factor Authentication settings has been disabled, just return
		$GA_hidefromuser = trim( get_user_option( 'googleauthenticator_hidefromuser', $user_id ) );
		if ( $GA_hidefromuser == 'enabled') return;
		
		$GA_secret			= trim( get_user_option( 'googleauthenticator_secret', $user_id ) );
		$GA_enabled			= trim( get_user_option( 'googleauthenticator_enabled', $user_id ) );
		$GA_description		= trim( get_user_option( 'googleauthenticator_description', $user_id ) );
		$GA_pwdenabled		= trim( get_user_option( 'googleauthenticator_pwdenabled', $user_id ) );
		$GA_password		= trim( get_user_option( 'googleauthenticator_passwords', $user_id ) );
		
		$forced_roles = get_option( 'google_authenticator_roles', array() );

		if ( array_intersect($user->roles, $forced_roles) ) {
			$GA_enabled = 'enabled';
		} 

		if ( 'enabled' == $GA_enabled )	{
			$enable_2FA = 1;
		} else {
			$enable_2FA = 0;
		}

		// We dont store the generated app password in cleartext so there is no point in trying
		// to show the user anything except from the fact that a password exists.
		if ( '' != $GA_password ) {
			$GA_password = "XXXX XXXX XXXX XXXX";
		}

		// In case the user has no secret ready (new install), we create one.
		if ( '' == $GA_secret ) {
			$GA_secret = $this->create_secret();
		}
		
		// Use "WordPress Blog" as default description
		if ( '' == $GA_description ) {
			$GA_description = get_bloginfo('name');
		}

		$GA_description = get_option('google_authenticator_description') ? get_option('google_authenticator_description') : $GA_description;
		$GA_label = $user->user_login;
		$GA_label = ucwords($GA_label);
		$GA_label = str_replace(' ', '', $GA_label);
		$GA_label = rawurlencode($GA_label);

		$GA_relaxedmode = trim( get_option( 'google_authenticator_relaxedmode' ) );
		
		echo "<h3>".__( '2-Factor Authentication Settings', 'google-authenticator' )."</h3>\n";

		echo wp_nonce_field('google-authenticator', 'GA_nonce');

		echo "<input type=\"hidden\" name=\"GA_label\" id=\"GA_label\" value=\"{$GA_label}\">";

		echo "<table class=\"form-table\">\n";
		echo "<tbody>\n";
		
		if ( !array_intersect($user->roles, $forced_roles) ) {
			echo "<tr>\n";
			echo "<th>".__( 'Enable 2-FA', 'google-authenticator' )."</th>\n";
			echo "<td>\n";
			echo "<input name=\"GA_enabled\" id=\"GA_enabled\" class=\"tog\" type=\"checkbox\"" . checked( $GA_enabled, 'enabled', false ) . "/>\n";
			echo "</td>\n";
			echo "</tr>\n";
		} 

		echo "<tr>\n";
		echo "<th>".__( 'Enable 2-FA', 'google-authenticator' )."</th>\n";
		echo "<td>\n";
		if ( $enable_2FA == 1 ) {
			echo "Active" . PHP_EOL;
		} else {
			echo "Not Active" . PHP_EOL;
		}
		echo "<input type=\"hidden\" name=\"enable_2FA\" id=\"enable_2FA\" value=\"".$enable_2FA."\">";
		echo "</td>\n";
		echo "</tr>\n";

		echo "<tr>\n";
		echo "<th>".__( '2-FA Status', 'google-authenticator' )."</th>\n";
		echo "<td id=\"2FA-status\">\n";
		if ( "" != trim( get_user_option( 'googleauthenticator_secret', $user_id ) ) ) {
			echo "Active";

			$url = admin_url('profile.php?action='.wp_create_nonce('google_authenticator_remove_secret'));
			
			echo "<a href=\"".$url."\" class=\"button btn-ga-action inline\">".__('Reset 2-FA Secret','google-authenticator')."</a>";
		} else {
			echo "Not Active";
		}
		echo "</td>\n";
		echo "</tr>\n";

		if ( $is_profile_page || IS_PROFILE_PAGE ) {
			echo "<input type=\"hidden\" name=\"GA_description\" id=\"GA_description\" value=\"{$GA_description}\">";

			if ( "" == trim( get_user_option( 'googleauthenticator_secret', $user_id ) ) ) {
				echo "<tr>";
				echo "<th></th>";
				echo "<td>";
				echo "<div class=\"QR_CODE_BOX\">";
				echo "<div id=\"GA_QR_INFO\" style=\"display: none\" >";
				echo "</div>";

				echo "\t<ol class='auth_message'>\n";
				echo "\t<li>".__('Download authy / other 2-Factor Authentication or 2-Step Verification App on your android or iphone.','google-authenticator')."</li>\n";
				echo "\t<li>";
				echo __('Scan this barcode or Enter the key manually.','google-authenticator') . "\n";
				echo "Your key: <strong>" . $GA_secret . "</strong>";
				echo "</li>\n";
				echo "\t<li>".__('Enter the authorization code.','google-authenticator')."</li>\n";
				echo "\t<li>".__('You are good to go!','google-authenticator')."</li>\n";
				echo "\t</ol>\n";

				echo "<div id=\"GA_QRCODE\"/></div>";
				echo "<input type=\"hidden\" name=\"GA_secret\" id=\"GA_secret\" value=\"{$GA_secret}\" />";
				echo '<span class="description"><br/> ' . __( 'Scan this with the 2-factor authentication or 2-step verification app.', 'google-authenticator' ) . '</span>';
				
				echo "<br><br>";
				echo "<div class=\"input_OTP\">";
				echo "<label for=\"googleotp\">".__('Authentication Code','google-authenticator')."</label>\n";
				echo "<br>";
				echo "<input type=\"text\" name=\"googleotp\" id=\"googleotp\">\n";
				echo "<a href=\"#\" id=\"btn-submit-googleotp\" class=\"button button-primary\">Authorize</a>\n";
				echo "<div id=\"googleotp-status\"><span class=\"description\"></span></div>";
				echo "</div>";
				echo "</div>";
				echo "</td>";
				echo "</tr>";
			} 

			if ( "enabled" == get_option('google_authenticator_pwdenabled') ) {
				echo "<tr>\n";
				echo "<th>".__( 'Enable App password', 'google-authenticator' )."</th>\n";
				echo "<td>\n";
				if ( 'enabled' == $GA_pwdenabled ) {
					echo "<span id=\"GA_APP_PASSWORD_STATUS\">Active</span>" . PHP_EOL;
					echo "<input type=\"hidden\" name=\"GA_pwdenabled\" id=\"GA_pwdenabled\" value=\"1\">";
				} else {
					echo "<span id=\"GA_APP_PASSWORD_STATUS\">Not Active</span>" . PHP_EOL;
					echo "<input type=\"hidden\" name=\"GA_pwdenabled\" id=\"GA_pwdenabled\" value=\"0\">";
				}
				echo "<a href=\"#\" class=\"button btn-ga-action inline\" id=\"GA_APP_PASSWORD\">Create New Password</a>";
				
				echo "</td>\n";
				echo "</tr>\n";
				
				echo "<tr id=\"GA_PASSWORD_BOX\">\n";
				echo "<th></th>\n";
				echo "<td>\n";
				echo "<input name=\"GA_password\" id=\"GA_password\" readonly=\"readonly\" value=\"".$GA_password."\" type=\"text\" size=\"25\" />";
				echo "<br>";
				echo "<span class=\"description\" id=\"GA_passworddesc\"> ".__(' Password is not stored in cleartext, this is your only chance to see it.','google-authenticator')."</span>\n";
				echo "</td>\n";
				echo "</tr>\n";
			}
		}

		echo "</tbody></table>\n";
		echo "<script type=\"text/javascript\">\n";
		echo "var GAnonce = '".wp_create_nonce('GoogleAuthenticatoraction')."';\n";
		echo "var user_id = '".$user_id."';\n";

		echo <<<ENDOFJS
		// Create new secret and display it
		jQuery('#GA_newsecret').bind('click', function() {
			// Remove existing QRCode
			jQuery('#GA_QRCODE').html("");
			var data=new Object();
			data['action']	= 'GoogleAuthenticator_action';
			data['nonce']	= GAnonce;
			jQuery.post(ajaxurl, data, function(response) {
				jQuery('#GA_secret').val(response['new-secret']);
				var qrcode="otpauth://totp/"+jQuery('#GA_label').val()+":"+escape(jQuery('#GA_description').val())+"?secret="+jQuery('#GA_secret').val()+"&issuer="+jQuery('#GA_label').val();
				jQuery('#GA_QRCODE').qrcode(qrcode);
				jQuery('#GA_QR_INFO').show('slow');
			});
		});

		// If the user starts modifying the description, hide the qrcode
		jQuery('#GA_description').bind('focus blur change keyup', function() {
			// Only remove QR Code if it's visible
			if ( jQuery('#GA_QR_INFO').is(':visible') ) {
				jQuery('#GA_QR_INFO').hide('slow');
				jQuery('#GA_QRCODE').html("");
			}
		});

		// Create new app password
		jQuery('#GA_createpassword').bind('click',function() {
			var data = new Object();
			data['action']	= 'GoogleAuthenticator_generate_new_password';
			data['nonce']	= GAnonce;
			data['user_id'] = user_id;
			data['save']	= 1;
			jQuery.post(ajaxurl, data, function(response) {
				console.log(response);

				var json_data = response.data;

				if ( json_data.app_password ) {
					jQuery('#GA_password').val(json_data.app_password);
					jQuery('#GA_passworddesc').show();
				} else {
					alert(json_data.message);
				}
			});
		});
		
		jQuery('#GA_enabled').bind('change',function() {
			GoogleAuthenticator_apppasswordcontrol();
		});

		jQuery('#GA_pwdenabled').bind('change',function() {
			GoogleAuthenticator_apppasswordcontrol();
		});

		jQuery(document).ready(function() {
			if ( jQuery('#GA_QRCODE').length > 0 ) {
				var qrcode="otpauth://totp/"+jQuery('#GA_label').val()+":"+escape(jQuery('#GA_description').val())+"?secret="+jQuery('#GA_secret').val()+"&issuer="+jQuery('#GA_label').val();
				jQuery('#GA_QRCODE').qrcode(qrcode);
			}

			jQuery('#GA_passworddesc').hide();
			GoogleAuthenticator_apppasswordcontrol();
		});
		
		function GoogleAuthenticator_apppasswordcontrol() {
			if ( jQuery('#GA_enabled').length > 0 ) {
				if ( jQuery('#GA_enabled').is(':checked') ) {
					jQuery('#GA_pwdenabled').removeAttr('disabled');
					jQuery('#GA_createpassword').removeAttr('disabled');
				} else {
					jQuery('#GA_pwdenabled').removeAttr('checked')
					jQuery('#GA_pwdenabled').attr('disabled', true);
					jQuery('#GA_createpassword').attr('disabled', true);
				}
			}

			if ( jQuery('#enable_2FA').length > 0 ) {
				if ( 1 == parseInt(jQuery('#enable_2FA').val()) ) {
					jQuery('#GA_pwdenabled').removeAttr('disabled');
					jQuery('#GA_createpassword').removeAttr('disabled');
				} else {
					jQuery('#GA_pwdenabled').removeAttr('checked')
					jQuery('#GA_pwdenabled').attr('disabled', true);
					jQuery('#GA_createpassword').attr('disabled', true);
				}
			} 

			if ( jQuery('#enable_2FA').length > 0 ) {
				if ( jQuery('#GA_pwdenabled').is(':checked') ) {
					jQuery('#GA_PASSWORD_BOX').show('slow');
				} else {
					jQuery('#GA_PASSWORD_BOX').hide('slow');
				}
			}
		}

		function ShowOrHideQRCode() {
			if ( jQuery('#GA_QR_INFO').is(':hidden') ) {
				var qrcode="otpauth://totp/"+jQuery('#GA_label').val()+":"+escape(jQuery('#GA_description').val())+"?secret="+jQuery('#GA_secret').val()+"&issuer="+jQuery('#GA_label').val();
				jQuery('#GA_QRCODE').qrcode(qrcode);
				jQuery('#GA_QR_INFO').show('slow');
			} else {
				jQuery('#GA_QR_INFO').hide('slow');
				jQuery('#GA_QRCODE').html("");
			}
		}
	</script>
ENDOFJS;
	}

	/**
	 * Form handling of 2-Factor Authentication options added to personal profile page (user editing his own profile)
	 */
	function personal_options_update($user_id) {
		$user = get_userdata($user_id);

		if ( !isset($_POST['GA_nonce']) || !wp_verify_nonce( @$_POST['GA_nonce'], 'google-authenticator' ) ) {
			return;
		}
		
		// If editing of 2-Factor Authentication settings has been disabled, just return
		$GA_hidefromuser = trim( get_user_option( 'googleauthenticator_hidefromuser', $user_id ) );
		if ( $GA_hidefromuser == 'enabled') return;

		$GA_enabled		= ( isset($_POST['GA_enabled']) ) ? 'enabled' : 'disabled';
		$GA_description	= trim( sanitize_text_field($_POST['GA_description'] ) );
		$GA_relaxedmode	= isset($_POST['GA_relaxedmode']) ? 'enabled' : 'disabled';
		$GA_secret		= isset($_POST['GA_secret']) ? trim( $_POST['GA_secret'] ) : '';
		$GA_pwdenabled	= isset($_POST['GA_pwdenabled']) ? 'enabled' : 'disabled';
		$GA_password	= isset($_POST['GA_password']) ? str_replace(' ', '', trim($_POST['GA_password'])) : '';
		
		$forced_roles = get_option( 'google_authenticator_roles', array() );

		if ( array_intersect($user->roles, $forced_roles) ) { 
			$GA_enabled = 'enabled';
		}
		
		update_user_option( $user_id, 'googleauthenticator_enabled', $GA_enabled, true );
	}

	/**
	 * Extend profile page with ability to enable/disable 2-Factor Authentication requirement.
	 * Used by an administrator when editing other users.
	 */
	function edit_user_profile($user) {
		global $wpdb;

		$user_id = $user->ID;

		if ( isset($_GET['action']) && wp_verify_nonce(@$_GET['action'], 'google_authenticator_remove_secret') ) {
			
			delete_user_option($user_id, 'googleauthenticator_secret'); // blog spesific 
			delete_user_option($user_id, 'googleauthenticator_secret', true); // global (network wide) 
			
			$redirect_to = add_query_arg( 
				array( 
					'user_id' => $user_id, 
					'reset_secret' => 1 
				), 
				admin_url('user-edit.php') 
			);

			wp_redirect($redirect_to);
			exit;
		}

		$GA_enabled = trim( get_user_option( 'googleauthenticator_enabled', $user_id ) );

		$forced_roles = get_option( 'google_authenticator_roles', array() );

		if ( array_intersect($user->roles, $forced_roles) ) {
			$GA_enabled = 'enabled';

			return false;
		}
		
		$GA_hidefromuser = trim( get_user_option( 'googleauthenticator_hidefromuser', $user_id ) );
		
		echo "<h3>".__('2-Factor Authentication Settings','google-authenticator')."</h3>\n";
		echo wp_nonce_field('google-authenticator', 'GA_nonce');
		echo "<table class=\"form-table\">\n";
		echo "<tbody>\n";

		echo "<tr>\n";
		echo "<th>".__('Hide settings from user','google-authenticator')."</th>\n";
		echo "<td>\n";
		echo "<div><input name=\"GA_hidefromuser\" id=\"GA_hidefromuser\"  class=\"tog\" type=\"checkbox\"" . checked( $GA_hidefromuser, 'enabled', false ) . "/>\n";
		echo "</td>\n";
		echo "</tr>\n";

		echo "<tr>\n";
		echo "<th>".__('Active','google-authenticator')."</th>\n";
		echo "<td>\n";
		echo "<div><input name=\"GA_enabled\" id=\"GA_enabled\"  class=\"tog\" type=\"checkbox\"" . checked( $GA_enabled, 'enabled', false ) . "/>\n";
		echo "</td>\n";
		echo "</tr>\n";

		$GA_secret = trim( get_user_option( 'googleauthenticator_secret', $user_id ) );
		if ( '' != $GA_secret ) {
			echo "<tr>\n";
			echo "<th>".__('Remove Secret','google-authenticator')."</th>\n";
			echo "<td>\n";
			
			$url = admin_url('user-edit.php?user_id='.$user_id.'&action='.wp_create_nonce('google_authenticator_remove_secret'));
			
			echo "<div><a class='button' href='".$url."'>Remove</a>\n";
			echo "</td>\n";
			echo "</tr>\n";
		}

		echo "</tbody>\n";
		echo "</table>\n";
	}

	/**
	 * Form handling of 2-Factor Authentication options on edit profile page (admin user editing other user)
	 */
	function edit_user_profile_update($user_id) {
		$user = get_userdata($user_id);
		
		if ( !isset($_POST['GA_nonce']) || !wp_verify_nonce( @$_POST['GA_nonce'], 'google-authenticator' ) ) {
			return;
		}

		$GA_enabled 		= ! empty( $_POST['GA_enabled'] );
		$GA_hidefromuser 	= ! empty( $_POST['GA_hidefromuser'] );

		if ( ! $GA_enabled ) {
			$GA_enabled = 'disabled';
		} else {
			$GA_enabled = 'enabled';
		}

		if ( ! $GA_hidefromuser ) {
			$GA_hidefromuser = 'disabled';
		} else {
			$GA_hidefromuser = 'enabled';
		}

		$forced_roles = get_option( 'google_authenticator_roles', array() );

		if ( array_intersect($user->roles, $forced_roles) ) {
			$GA_enabled = 'enabled';
			$GA_hidefromuser = 'disabled';
		}
		
		update_user_option( $user_id, 'googleauthenticator_enabled', $GA_enabled, true );
		update_user_option( $user_id, 'googleauthenticator_hidefromuser', $GA_hidefromuser, true );
	}

	/**
	* AJAX callback function used to generate new secret
	*/
	function ajax_callback() {
		global $user_id;

		// Some AJAX security.
		check_ajax_referer( 'GoogleAuthenticatoraction', 'nonce' );
		
		// Create new secret.
		$secret = $this->create_secret();

		$result = array( 'new-secret' => $secret );
		header( 'Content-Type: application/json' );
		echo json_encode( $result );

		// die() is required to return a proper result
		die(); 
	}

	function ajax_personal_options_submit_otp_callback() {
		// get serialize form and parse it to array
		parse_str($_POST['dataForm'], $data);

		$_POST = $data;

		$response = [];

		if ( !isset($_POST['GA_nonce']) || ! wp_verify_nonce($_POST['GA_nonce'], 'google-authenticator') ) {
			$response = [ 
				'status' => 'Not Active', 
				'message' => 'Invalid input!' 
			];
			wp_send_json_success($response);
		}

		$user_id = isset($_POST['user_id']) ? (int) $_POST['user_id'] : 0;

		$user = new WP_User( $user_id );

		if ( !$user->exists() ) {
			$response = [ 
				'status' => 'Not Active', 
				'message' => 'Invalid input!' 
			];
			wp_send_json_success($response);
		}

		if ( isset($_POST['googleotp']) && !empty($_POST['googleotp']) ) {
			// Get the users secret
			$GA_secret = trim( get_user_option( 'googleauthenticator_secret', $user->ID ) );

			if ( isset($_POST['GA_secret']) ) {
				$GA_secret = $_POST['GA_secret'];
			}
			
			// Get the verification code entered by the user trying to login
			$otp = trim( $_POST['googleotp'] );

			// Figure out if relaxed mode is active ?
			$GA_relaxedmode = trim( get_option( 'google_authenticator_relaxedmode' ) );

			// When was the last successful login performed ?
			$lasttimeslot = trim( get_user_option( 'googleauthenticator_lasttimeslot', $user->ID ) );

			// Valid code ?
			if ( $timeslot = $this->verify( $GA_secret, $otp, $GA_relaxedmode, $lasttimeslot ) ) {
				// Update the users secret
				update_user_option( $user->ID, 'googleauthenticator_secret', $GA_secret, true );

				// Store the timeslot in which login was successful.
				update_user_option( $user->ID, 'googleauthenticator_lasttimeslot', $timeslot, true );

				$response = [ 
					'status' => 'Active', 
					'message' => '<strong>Congrats</strong>: Activated 2-FA.' 
				];
			} else {
				$response = [ 
					'status' => 'Not Active', 
					'message' => '<strong>ERROR</strong>: The Authorization Code is incorrect or has expired.' 
				];
			}
		} else {
			$response = [ 
				'status' => 'Not Active', 
				'message' => '<strong>ERROR</strong>: Empty Authorization Code.' 
			];
		}

		wp_send_json_success($response);
	}

	function ajax_GA_app_password_callback() {
		// get serialize form and parse it to array
		parse_str($_POST['dataForm'], $data);

		$_POST = $data;

		$user_id = isset($_POST['user_id']) ? (int) $_POST['user_id'] : 0;

		$user = new WP_User( $user_id );

		if ( !$user->exists() ) {
			$response = [ 
				'status' => 'error', 
				'message' => 'Failed to generate new password!' 
			];
			wp_send_json_success($response);
		}

		$response = [];

		if ( 'enabled' == get_user_option('googleauthenticator_pwdenabled') ) {
			update_user_option( $user_id, 'googleauthenticator_pwdenabled', 'disabled', true );

			$response = [ 
				'status' => 'deactive', 
				'message' => 'Deactivated your app password.' 
			];
		} else {
			// Create new secret.
			$secret = $this->create_secret();

			$GA_password = [ 
				'appname' => 'Default', 
				'password' => wp_hash_password( trim($secret) ) 
			];

			update_user_option( $user_id, 'googleauthenticator_passwords', json_encode( $GA_password ), true );
			update_user_option( $user_id, 'googleauthenticator_pwdenabled', 'enabled', true );

			$response = [ 
				'status' => 'active', 
				'message' => 'Activated your app password.', 
				'plain_text' => $secret, 
				'app_password' => implode(' ', str_split($secret, 4)) 
			];
		}
		
		wp_send_json_success($response);
	}

	function GoogleAuthenticator_generate_new_password_callback() {
		// Some AJAX security.
		check_ajax_referer( 'GoogleAuthenticatoraction', 'nonce' );
		
		// get serialize form and parse it to array
		parse_str($_POST['dataForm'], $data);

		$_POST = $data;

		$user_id = isset($_POST['user_id']) ? (int) $_POST['user_id'] : 0;

		$user = new WP_User( $user_id );

		if ( !$user->exists() ) {
			$response = [ 
				'status' => 'error', 
				'message' => 'Failed to generate new password!' 
			];
			wp_send_json_success($response);
		}
		
		// Create new secret.
		$secret = $this->create_secret();

		$GA_password = [ 
			'appname' => 'Default', 
			'password' => wp_hash_password( trim($secret) ) 
		];

		update_user_option( $user_id, 'googleauthenticator_passwords', json_encode( $GA_password ), true );
		update_user_option( $user_id, 'googleauthenticator_pwdenabled', 'enabled', true );

		$response = [ 
			'plain_text' => $secret, 
			'app_password' => implode(' ', str_split($secret, 4)) 
		];

		header( 'Content-Type: application/json' );
		
		wp_send_json_success($response);
	}

	function ga_embed_footer_scripts() {
		?>
		<script type="text/javascript">
			jQuery('#btn-submit-googleotp').click(function(e){
				e.preventDefault();

				var dataForm = jQuery(this).closest('form').serialize();

				var dataPost = {
					'action': 'personal_options_ajax_submit_otp', 
					'dataForm': dataForm 
				};

				jQuery.ajax({
					url: ajaxurl, 
					type: 'POST', 
					data : dataPost, 
					dataType : "json", 
					success: function(response){
						if ( true === response.success ) {
							var json_data = response.data;
						}
					},
					complete: function(jqXHR, status){
						if ( 'success' == status ) {
							var json_res = jqXHR.responseJSON, 
								json_data = json_res.data;

							console.log(json_data);

							jQuery('#2FA-status').text(json_data.status);
							jQuery('#googleotp-status').find('.description').html(json_data.message);
						}
					}
				});
			});
		</script>
		<?php 
	}

	/**
	 * Admin setting menu for enabling 2-FA per role basis
	 */
	function setting_menu() {
		add_submenu_page( 'options-general.php', __('2-Factor Authentication','google-authenticator'), __('2-Factor Authentication','google-authenticator'), 'manage_options', 'google-authenticator', array( $this, 'setting_menu_callback' )  );
	}

	/**
	 * 2-Factor Authentication Page Handler
	 */
	function setting_menu_callback() {
		if ( isset($_POST['save-settings']) ) {
			$this->update_ga_settings(); 
		}

		$roles = get_editable_roles();
		$enabled_roles = get_option( 'google_authenticator_roles', array() ); 

		$GA_description = get_option('google_authenticator_description');
		$GA_description = $GA_description ? $GA_description : '';

		$GA_relaxedmode = get_option('google_authenticator_relaxedmode');
		$GA_relaxedmode = $GA_relaxedmode ? $GA_relaxedmode : 'disabled';

		$GA_pwdenabled = get_option('google_authenticator_pwdenabled');
		$GA_pwdenabled = $GA_pwdenabled ? $GA_pwdenabled : 'disabled';

		?>
		<div class="wrap">
			<h1><?php _e('2-Factor Authentication Settings'); ?></h1>
			<form action="" method="post">
				<h3><?php _e( 'Force 2-FA on Following Roles', 'google-authenticator' ) ?></h3>
				<table class="form-table">
					<tbody>
						<tr>
							<th><label for=""><?php _e( 'Select Role', 'google-authenticator' ) ?></label></th>
							<td>
								<?php foreach ($roles as $key => $value) : ?>
									<label><input type="checkbox" name="role[]" value="<?php echo $key ?>" <?php echo in_array($key, $enabled_roles) ? 'checked' : '' ?>> <?php echo __($value['name'], 'google-authenticator') ?></label><br>
								<?php endforeach; ?>
							</td>
						</tr>
					</tbody>
				</table>

				<h3><?php _e( 'Extra Options', 'google-authenticator' ) ?></h3>
				<table class="form-table">
					<tbody>
						<tr>
							<th><label for=""><?php _e( 'App Description', 'google-authenticator' ) ?></label></th>
							<td>
								<input type="text" name="GA_description" id="GA_description" value="<?php echo $GA_description; ?>" size="25" />
								<span class="description"><?php _e(' Description that you\'ll see in the 2-factor authentication or 2-step verification app on your phone.', 'google-authenticator'); ?></span>
							</td>
						</tr>
						<tr>
							<th><label for=""><?php _e( ' Relaxed Mode', 'google-authenticator' ) ?></label></th>
							<td>
								<input type="checkbox" name="GA_relaxedmode" id="GA_relaxedmode" class="tog" <?php checked( $GA_relaxedmode, 'enabled', true ); ?> />
								<span class="description"><?php _e('Relaxed mode allows for more time drifting on your phone clock (&#177;2 min)', 'google-authenticator'); ?></span>
							</td>
						</tr>
						<tr>
							<th><label for=""><?php _e( ' Master Password', 'google-authenticator' ) ?></label></th>
							<td>
								<input type="checkbox" name="GA_pwdenabled" id="GA_pwdenabled" class="tog" <?php checked( $GA_pwdenabled, 'enabled', true ); ?> />
								<span class="description"><?php _e('Enabling an App password will decrease your overall login security.', 'google-authenticator'); ?></span>
							</td>
						</tr>
					</tbody>
				</table>

				<?php wp_nonce_field( 'save_roles', 'google_authenticator_action' ); ?>
				<?php submit_button( __( 'Save Changes' ), 'primary left', 'save-settings', false ); ?>
			</form>
		</div>
		<?php 
	}

	/**
	 * Set roles
	 */
	function update_ga_settings() {
		global $pagenow;

		if ( $pagenow != 'options-general.php' ) 
			return;

		if ( !isset($_GET['page']) || $_GET['page'] != 'google-authenticator' )
			return;

		if ( !isset($_POST['google_authenticator_action']) || !wp_verify_nonce( @$_POST['google_authenticator_action'], 'save_roles' ) ) 
			return;

		$GA_roles = isset($_POST['role']) ? $_POST['role'] : array();
		$GA_description = isset($_POST['GA_description']) ? trim( sanitize_text_field($_POST['GA_description']) ) : '';
		$GA_relaxedmode = isset($_POST['GA_relaxedmode']) ? 'enabled' : 'disabled';
		$GA_pwdenabled = isset($_POST['GA_pwdenabled']) ? 'enabled' : 'disabled';
		
		update_option( 'google_authenticator_roles', $GA_roles, 'no' );
		update_option( 'google_authenticator_description', $GA_description, 'no' );
		update_option( 'google_authenticator_relaxedmode', $GA_relaxedmode, 'no' );
		update_option( 'google_authenticator_pwdenabled', $GA_pwdenabled, 'no' );

		echo '<div class="notice notice-success is-dismissible"><p>Perubahan berhasil disimpan.</p></div>';

		// wp_redirect( $_POST['_wp_http_referer'] );
		// exit;
	}

	function hipwee_google_authenticator_sample_admin_notice() {
		global $pagenow;

		if ( !in_array($pagenow, array('profile.php','user-edit.php')) ) 
			return;

		if ( isset($_GET['reset_secret']) && $_GET['reset_secret'] == 1 ) {
			?>
			<div class="notice notice-success is-dismissible">
			<p><?php _e( 'GA secret anda berhasil di hapus.', 'google-authenticator' ); ?></p>
			</div>
			<?php 
		}
	}
} // end class

$google_authenticator = new GoogleAuthenticator;
