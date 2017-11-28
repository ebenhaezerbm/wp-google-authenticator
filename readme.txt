=== Wordpress 2-FA ===
Contributors: Henrik.Schack, Todi.Adiyatmo, Ebenhaezer.BM

Two Factor Authentication for your WordPress blog.

== Description ==

The Wordpress 2-FA plugin for WordPress gives you two-factor authentication using the Google Authenticator app for Android/iPhone/Blackberry.

If you are security aware, you may already have the Google Authenticator app installed on your smartphone, using it for two-factor authentication on Gmail/Dropbox/Lastpass/Amazon etc.

The two-factor authentication requirement can be enabled on a per-user basis. You could enable it for your administrator account, but log in as usual with less privileged accounts.

If You need to maintain your blog using an Android/iPhone app, or any other software using the XMLRPC interface, you can enable the App password feature in this plugin, 
but please note that enabling the App password feature will make your blog less secure.

== Installation ==
1. Make sure your webhost is capable of providing accurate time information for PHP/WordPress, ie. make sure a NTP daemon is running on the server.
2. Install and activate the plugin.
3. Enter a description on the Users -> Profile and Personal options page, in the Google Authenticator section.
4. Scan the generated QR code with your phone, or enter the secret manually, remember to pick the time based one.  
You may also want to write down the secret on a piece of paper and store it in a safe place. 
5. Remember to hit the **Update profile** button at the bottom of the page before leaving the Personal options page.
6. That's it, your WordPress blog is now a little more secure.
