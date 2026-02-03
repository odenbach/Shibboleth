<?php

namespace MediaWiki\Extension\Shibboleth;

use MediaWiki\Auth\AuthManager;
use MediaWiki\Extension\PluggableAuth\PluggableAuth as PA_Base;
use MediaWiki\Logger\LoggerFactory;
use MediaWiki\User\UserFactory;
use MediaWiki\User\UserIdentity;
use MediaWiki\User\UserGroupManager;
use MWException as Exception;
use RequestContext;
use SpecialPage;
use Title;

/**
 * Class PluggableAuth
 *
 * This class provides a pluggable authentication mechanism for MediaWiki, relying on Shibboleth authentication
 *
 * @package MediaWiki\Auth
 */
class PluggableAuth extends PA_Base {

	/**
	* @var AuthManager
	*/
	private AuthManager $authManager;

	/**
	* @var UserFactory
	*/
	private UserFactory $userFactory;

	/**
	* @var UserGroupManager
	*/
	private UserGroupManager $userGroupManager;

	/**
	* @param UserFactory $userFactory
	* @param AuthManager $authManager
	* @param UserGroupManager $userGroupManager
	*/
	public function __construct( UserFactory $userFactory, AuthManager $authManager, UserGroupManager $userGroupManager ) {
		$this->userFactory = $userFactory;
		$this->authManager = $authManager;
		$this->userGroupManager = $userGroupManager;
		$this->setLogger( LoggerFactory::getInstance( 'Shibboleth' ) );
		$this->getLogger()->debug( 'Constructed ' . self::class );
	}

	/**
	* @inheritDoc
	* @throws Exception
	*/
	public function authenticate( ?int &$id, ?string &$username, ?string &$realname, ?string &$email, ?string &$errorMessage ): bool {
		$this->getLogger()->debug( 'Entering authenticate' );

		$currentTitle = RequestContext::getMain()->getTitle();
		$titleOfMySpecialPage = SpecialPage::getTitleFor( SpecialShibboleth::NAME_OF_SPECIAL_PAGE );
		if ( $currentTitle->getPrefixedText() != $titleOfMySpecialPage->getPrefixedText() ) {
			$this->redirectToSpecialPage( $currentTitle, $titleOfMySpecialPage );
		}
		// from this point on assume, that we are on our special page.
		$principal = $_SERVER['REMOTE_USER'] ?? $_SERVER['PHP_AUTH_USER'] ?? $_SERVER['REDIRECT_REMOTE_USER'] ?? null;

		$id = null;
		$username = $this->getUsername();
		$realname = $this->getDisplayName();
		$email = $this->getEmail();
		$userattrs = [];

		if (isset($GLOBALS['wgShibboleth_GroupMap'])) {
			$userattrs = $this->checkGroupMap();
		}

		$user = $this->userFactory->newFromName( $username );
		if ( $user !== false && $user->getId() !== 0 ) {
			$id = $user->getId();
		}
		$user->addToDatabase();
		$this->populateGroups ($user, $userattrs);
	
		return true;
	}

	/**
	* Logout
	*
	* @param User $user
	* @return boolean
	*/
	public function deauthenticate(&$user) : void {

		session_destroy();

		header('Location: ' . $this->getLogoutURL());

	}

	public function saveExtraAttributes($id) : void {

	}

	/**
	* Handle user privilages if it has one
	*
	* @param \User $user
	*/
	public function populateGroups(\User $user, array $userattrs) {

		wfDebugLog( 'Shibboleth', "Doing role mapping");
		$new_roles = array();
		if (!empty($userattrs)) {
			# loop over all user-provided attributes we are interested in
			foreach ($userattrs as $attr => $value) {
				wfDebugLog( 'Shibboleth', "__Checking $attr ($value)");
				# some attributes (e.g. entitlement) may carry multiple values, separated by semicolons
				$groups_array = explode(";", $value);

				# loop over all configured values of this attribute
				foreach ($GLOBALS['wgShibboleth_GroupMap'][$attr] as $group => $role) {
					wfDebugLog( 'Shibboleth', "____Looking for $group");
					$regex = False;
					# check if regex given
					if (preg_match ('/^\/.*\/$/', $group)) {
						$regex = True;
					}

					# loop over all user provided values of this attribute
					foreach ($groups_array as $givenGroup) {
						if ($regex) {
							wfDebugLog( 'Shibboleth', "______RegEx matching $givenGroup");
						} else {
							wfDebugLog( 'Shibboleth', "______Matching $givenGroup");
						}
						if (($regex and preg_match ($group, $givenGroup)) or (!$regex and $givenGroup === $group)) {
							if (!in_array ($role, $new_roles)) {
								wfDebugLog( 'Shibboleth', "________Match! Results in role $role");
								array_push ($new_roles, $role);
							}
						}
					}
				}
			}
		}

		# get old user groups
		$old_roles = array();
		$old_roles = $this->userGroupManager->getUserGroups($user);

		# compare current and new roles
		foreach ($old_roles as $role) {
			if (!in_array ($role, $new_roles)) {
				wfDebugLog( 'Shibboleth', "__Removing role $role");
				$this->userGroupManager->removeUserFromGroup($user, $role);
			}
		}

		foreach ($new_roles as $role) {
			if (!in_array($role, $old_roles)) {
				wfDebugLog( 'Shibboleth', "__Adding role $role");
				$this->userGroupManager->addUserToGroup($user, $role);
			}
		}
	}

	/**
	* Display name from Shibboleth
	*
	* @return string
	* @throws Exception
	*/
	private function getDisplayName() {

		// wgShibboleth_DisplayName check in LocalSettings.php
		if (empty($GLOBALS['wgShibboleth_DisplayName'])) {
			throw new Exception(wfMessage('shibboleth-wg-empty-displayname')->plain());
		} else {
			$displayName = $GLOBALS['wgShibboleth_DisplayName'];
			# force into an array
			if (!is_array ($displayName)) {
				$displayName = [$displayName];
			}
		}

		foreach ($displayName as $attr) {
			$varlist[$attr] = FILTER_DEFAULT;
		}

		$userattrs = filter_input_array (INPUT_SERVER, $varlist, False);

		if (empty($GLOBALS['wgShibboleth_DisplayNameFormatString'])) {
			$list = array();
			foreach ($userattrs as $attr) {
				array_push ($list, '%s');
			}
			$format = implode (' ', $list);
		} else {
			$format = $GLOBALS['wgShibboleth_DisplayNameFormatString'];
		}

		return vsprintf ($format, $userattrs);

	}

	/**
	* Email address from Shibboleth
	*
	* @return string
	* @throws Exception
	*/
	private function getEmail() {

		// wgShibboleth_Email check in LocalSettings.php
		if (empty($GLOBALS['wgShibboleth_Email'])) {
			throw new Exception(wfMessage('shibboleth-wg-empty-email')->plain());
		} else {
			$mail = $GLOBALS['wgShibboleth_Email'];
		}

		// E-mail shibboleth attribute check
		if (empty(filter_input(INPUT_SERVER, $mail))) {
			return '';
		} else {
			return filter_input(INPUT_SERVER, $mail);
		}
	}

	/**
	* Username from Shibboleth
	*
	* @return string
	* @throws Exception
	*/
	private function getUsername() {

		// wgShibboleth_Username check in LocalSettings.php
		if (empty($GLOBALS['wgShibboleth_Username'])) {
			throw new Exception(wfMessage('shibboleth-wg-empty-username')->plain());
		} else {
			$user = $GLOBALS['wgShibboleth_Username'];
		}

		// Username shibboleth attribute check
		if (empty(filter_input(INPUT_SERVER, $user))) {
			throw new Exception(wfMessage('shibboleth-attr-empty-username')->plain());
		} else {

			$username = filter_input(INPUT_SERVER, $user);

			// If $username contains '@' replace it with '(AT)'
			if (strpos($username, '@') !== false) {
				$username = str_replace('@', '(AT)', $username);
			}

			// Uppercase the first letter of $username
			return ucfirst($username);
		}
	}

	/**
	* This redirects to Shibboleth authentication special page
	*
	* @param Title $currentTitle
	* @param Title $destinationTitle
	*
	* @throws Exception
	* @return void
	*/
	protected function redirectToSpecialPage( Title $currentTitle, Title $destinationTitle ): void {
		$url = $destinationTitle->getFullURL( [
			'returnto' => $currentTitle,
			'returntoquery' => $this->authManager->getRequest()->getRawPostString(),
		] );
		if ( $url ) {
			$this->getLogger()->debug( 'Redirecting to ' . $url );
			header( 'Location: ' . $url );
		} else {
			throw new Exception( "Could not determine URL for " . $destinationTitle->getPrefixedText() );
		}
		exit;
	}


	private function checkGroupMap() {

		foreach ($GLOBALS['wgShibboleth_GroupMap'] as $attr => $line) {
			$varlist[$attr] = FILTER_DEFAULT;
		}

		$userattrs = filter_input_array (INPUT_SERVER, $varlist, False);

		if (!$GLOBALS['wgShibboleth_GroupMap_attr_may_be_empty'] and empty($userattrs)) {
			throw new Exception(wfMessage('shibboleth-attr-empty-groupmap-attr')->plain());
		}

		return $userattrs;
	}

	private function getLogoutURL() {

		$base_url = $GLOBALS['wgShibboleth_Logout_Base_Url'];

		if (empty($base_url)) {
			throw new Exception(wfMessage('shibboleth-wg-empty-logout-base-url')->plain());
		}

		$target_url = $GLOBALS['wgShibboleth_Logout_Target_Url'];

		if (empty($target_url)) {
			throw new Exception(wfMessage('shibboleth-wg-empty-logout-target-url')->plain());
		}

		$logout_url = $base_url . '/Shibboleth.sso/Logout?return=' . $target_url;

		return $logout_url;
	}

}
