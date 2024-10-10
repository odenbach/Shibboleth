<?php

namespace MediaWiki\Extension\Shibboleth;

/**
 * Class ShibbolethHooks
 *
 * This class contains hooks for handling user registration with the Shibboleth plugin.
 */
class ShibbolethHooks {

	/**
	 * Adds the Shibboleth plugin configuration to PluggableAuth's
	 * global $wgPluggableAuth_Config array.
	 *
	 * @param array $info Information about the plugin.
	 *                    - name: The name of the plugin.
	 *
	 * @return void
	 */
	public static function onRegistration( array $info ) {

		if ( !isset( $GLOBALS['wgPluggableAuth_Config'] ) ) {
			$GLOBALS['wgPluggableAuth_Config'] = [];
		}
		$GLOBALS['wgPluggableAuth_Config'][$info['name']] = [
			'plugin' => 'Shibboleth',
			'buttonLabelMessage' => 'shibboleth-login-button-label',
		];
	}
}
