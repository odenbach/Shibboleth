# MediaWiki Shibboleth extension

The **Shibboleth** extension extends the [PluggableAuth](https://www.mediawiki.org/wiki/Extension:PluggableAuth) extension to provide authentication using [Shibboleth Apache module](https://wiki.shibboleth.net/confluence/display/SHIB2/NativeSPApacheConfig).

Recommended MediaWiki version: **1.29+**

## Required packages and settings

In order to use Shibboleth Apache module as an authentication method in your wiki, you need have a functional Shibboleth Service Provider (SP).

Install Shibboleth Apache modul on Debian/Ubuntu linux:

* `sudo apt install libapache2-mod-shib2`
* `sudo a2enmod shib2`
* `sudo systemctl restart apache2`

### Apache vhost config

```apache
<Location /index.php/*:PluggableAuthLogin>
	AuthType shibboleth
	ShibRequestSetting applicationId default
	ShibRequestSetting requireSession true
	Require valid-user
</Location>
```

### Apache vhost config FastCGI (FPM)

You should replace `ShibRequestSetting applicationId default` with `ShibUseHeaders On`.

```apache
<Location /index.php>
  <If "%{QUERY_STRING} =~ /title=(.+):PluggableAuthLogin/">
  AuthType shibboleth
  ShibRequestSetting requireSession true
  Require valid-user
  ShibUseHeaders On
  </If>
</Location>
```

## Installation

> This extension requires the [PluggableAuth](https://www.mediawiki.org/wiki/Extension:PluggableAuth) extension and [Shibboleth](https://wiki.shibboleth.net/confluence/display/SHIB2/NativeSPConfiguration) to be installed first.

* Download and place the file(s) in a directory called Shibboleth in your extensions/ folder.
* Add the following code at the bottom of your LocalSettings.php:

```php
wfLoadExtension( 'Shibboleth' );
```

* Configure as required
* Done! Navigate to Special:Version on your wiki to verify that the extension is successfully installed.

## Configure

Values must be provided for the following mandatory configuration variables:

Flag | Default | Description
---- | ------- | -----------
$wgShibboleth_Username | no default value | The name of the attribute to be used for the user's username.
$wgShibboleth_Email | no default value | The name of the attribute to be used for the user's email address.
$wgShibboleth_DisplayName | no default value | The name of the attribute(s) to be used for the user's real name.
$wgShibboleth_Logout_Base_Url | no default value | Single Logout (SLO) base URL
$wgShibboleth_Logout_Target_Url | no default value | Single Logout (SLO) target URL

In addition, the following optional configuration variable is provided:

Flag | Default | Description
---- | ------- | -----------
$wgShibboleth_GroupMap | null | Mapping from SAML attributes to MediaWiki groups, see example below. No group mapping is performed if $wgShibboleth_GroupMap is null.
$wgShibboleth_GroupMap_attr_may_be_empty | false | Allow empty group mapping attribute. Is you use an entitlement for group mapping this is needed to enable people without any entitlement to login.
$wgShibboleth_DisplayNameFormatString | null | Allows a custom format string which creates the display name (see vsprintf())

### Display name
You can either use a single SAML attribute as display name or multiple attributes:

 $wgShibboleth_DisplayName = 'displayName';
 $wgShibboleth_DisplayName = ['givenName', 'sn'];

If you define multiple attributes their values are concatenated with spaces. If you still want more you can use a user defined format string:

 $wgShibboleth_DisplayName = ["displayName", "mail"];
 $wgShibboleth_DisplayNameFormatString = "%s &lt;%s&gt;";

This results in

 Christopher Odenbach <odenbach@uni-paderborn.de>


### Group mapping

Use case: your SAML IdP reads groups from LDAP or Database and stores this information inside an attribute of the SAML response. You want to use this to map MediaWiki groups to users belonging to some known groups given by your IdP.

Example:

* Your IdP sends an attribute named "groups" with a list of names like "administrator", "student", "teacher", ... in the SAML response after authentication.
* All users that have the value "administrator" in the "groups" attribute shall be mapped to the MediaWiki "sysop" group to give them admin rights within your MediaWiki instance.
* For some reason you may also want to grant sysop rights to someone with a special pairwise-id but who is not in the administrator group.
* Create a group map in your LocalSettings.php as follows:

 $wgShibboleth_GroupMap = [
     'groups' => [
         'administrator' => 'sysop',
     ],
     'pairwise-id' => [
         'OTCROY5S7ZWGWYD6Z7EAXRXMA44YMW5S@uni-paderborn.de' => 'sysop',
     ],
 ];

You can come up with rather complex mappings that fit your needs. If you have more than one attribute from SAML, just add it to the array with the array of values you like to map.

**HINT**: If a user belongs to a MediaWiki group that is no longer mapped to that user (for example, by losing the group membership in the SAML user data source), the user will be removed from that MediaWiki group at next log in. In that way you can mass remove groups from SAML and their memberships, too - just scramble the mapping values so they don't match the SAML response, but don't mess up the MediaWiki group name.

### Single Logout (SLO)

Shibboleth Single Logout (SLO) URL structure

`$wgShibboleth_Logout_Base_Url . Shibboleth.sso/Logout?return= . $wgShibboleth_Logout_Target_Url`

`https://wiki.example.org/Shibboleth.sso/Logout?return=https://wiki.example.org/index.php`

## Known Bugs
(fixed since PluggableAuth >= 5.5)

The very first time when the user authenticates with Shibboleth, **$wgShibboleth_GroupMap** does not take effect due [T184736](https://phabricator.wikimedia.org/T184736) bug. It requires a relogin (logout then login) to be able to map the given configuration.
