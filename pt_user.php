<?php
/**
 *    This file is part of OXID eShop Community Edition.
 *
 *    OXID eShop Community Edition is free software: you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License as published by
 *    the Free Software Foundation, either version 3 of the License, or
 *    (at your option) any later version.
 *
 *    OXID eShop Community Edition is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License for more details.
 *
 *    You should have received a copy of the GNU General Public License
 *    along with OXID eShop Community Edition.  If not, see <http://www.gnu.org/licenses/>.
 *
 * @link http://www.oxid-esales.com
 * @package core
 * @copyright (C) OXID eSales AG 2003-2009
 * @version OXID eShop CE
 * $Id: oxuser.php 23173 2009-10-12 13:29:45Z sarunas $
 * 
 * @copyright Avenger 2010, entwicklungs@powertemplate.de
 * 
 * Allow login to user account also with user email and admin password.
 * 
 * Include with: oxuser=>powertemplate/pt_user/pt_user
 */

/**
 * User manager.
 * Performs user managing function, as assigning to groups, updating
 * information, deletion and other.
 * @package core
 */
class pt_user extends pt_user_parent
{
    /**
     * Performs user login by username and password. Fetches user data from DB.
     * Registers in session. Returns true on success, FALSE otherwise.
     *
     * @param string $sUser     User username
     * @param string $sPassword User password
     * @param bool   $blCookie  (default false)
     *
     * @throws oxConnectionException, oxCookieException, oxUserException
     *
     * @return bool
     */
    public function login( $sUser, $sPassword, $blCookie = false)
    {
        if ( $this->isAdmin() && !count( oxUtilsServer::getInstance()->getOxCookie() ) ) {
            $oEx = oxNew( 'oxCookieException' );
            $oEx->setMessage( 'EXCEPTION_COOKIE_NOCOOKIE' );
            throw $oEx;
        }

        $myConfig = $this->getConfig();
        if ( $sPassword ) {

            $sShopID = $myConfig->getShopId();
            $oDb = oxDb::getDb();

            $sUserSelect = is_numeric( $sUser ) ? "oxuser.oxcustnr = {$sUser} " : "oxuser.oxusername = " . $oDb->quote( $sUser );
            $sPassSelect = " oxuser.oxpassword = MD5( CONCAT( ".$oDb->quote( $sPassword ).", UNHEX( oxuser.oxpasssalt ) ) ) ";
            $sShopSelect = "";

            // admin view: can only login with higher than 'user' rights
            if ( $this->isAdmin() ) {
                $sShopSelect = " and ( oxrights != 'user' ) ";
            }

            $sWhat = "oxid";
            $sSelect0 =  "select $sWhat from oxuser where oxuser.oxactive = 1 and ";              
            $sSelect =  $sSelect0."{$sPassSelect} and {$sUserSelect} {$sShopSelect} ";
            if ( $myConfig->isDemoShop() && $this->isAdmin() ) {
                if ( $sPassword == "admin" && $sUser == "admin" ) {
                    $sSelect = "select $sWhat from oxuser where oxrights = 'malladmin' {$sShopSelect} ";
                } else {
                    $oEx = oxNew( 'oxUserException' );
                    $oEx->setMessage( 'EXCEPTION_USER_NOVALIDLOGIN' );
                    throw $oEx;
                }
            }
            // load from DB
            $aData = $oDb->getAll( $sSelect );
            $sOXID = @$aData[0][0];
            //Avenger -- Try to login with master admins password start.
            $blIsInvalidValigLogin=!$sOXID; 
            for ($iLoginStep=1;$iLoginStep<=2;$iLoginStep++)
            {
              if ($blIsInvalidValigLogin) 
              {
                if ($iLoginStep==2)
                {
                  $oEx = oxNew( 'oxUserException' );
                  $oEx->setMessage( 'EXCEPTION_USER_NOVALIDLOGIN' );
                  throw $oEx;
                }
                else
                {
                  //Reduce login requirements as 1st step (only check for eMail-address)
                  $sSelect =  $sSelect0."{$sUserSelect} {$sShopSelect} ";
                  // load from DB
                  $aData = $oDb->getAll( $sSelect );
                  $sOXID = @$aData[0][0];
                  if ( $sOXID ) 
                  {
                    //User found by eMail-address, now check password against master admins' password....

                    //Get  master admins' password and password 'salt'
                    $sWhat .= ",oxpassword,oxpasssalt";
                    $sSelect =  "select $sWhat from oxuser where oxid='oxdefaultadmin'";
                    $aData = $oDb->getAll( $sSelect );
                    $sAdminOXID = @$aData[0][0];
                    $sAdminPassword = @$aData[0][1];
                    $sAdminPasswordSalt = @$aData[0][2];
                    //Check password entered against master admins' password
                    $blIsInvalidValigLogin=$sAdminPassword<>md5($sPassword.$this->unhex($sAdminPasswordSalt));
                  }
                  else
                  {
                    $blIsInvalidValigLogin=true;
                  }
                }
              }
              else
              {
                 $this->load( $sOXID );
                 break;
              }
            }
            //Avenger -- Try to login with master admins password end.
        }
        //login successfull?
        if ($this->oxuser__oxid->value ) {   // yes, successful login
            if ( $this->isAdmin() ) {
                oxSession::setVar( 'auth', $this->oxuser__oxid->value );
            } else {
                oxSession::setVar( 'usr', $this->oxuser__oxid->value );
            }

            // cookie must be set ?
            if ( $blCookie ) {
                oxUtilsServer::getInstance()->setUserCookie( $this->oxuser__oxusername->value, $this->oxuser__oxpassword->value, $myConfig->getShopId() );
            }
            return true;
        } else {
            $oEx = oxNew( 'oxUserException' );
            $oEx->setMessage( 'EXCEPTION_USER_NOVALIDLOGIN' );
            throw $oEx;
        }
    }

   function unhex($sHex)
  {
    $sStr='';
    for ($i=0,$iHexLen=strlen($sHex);$i<$iHexLen;$i+=2)
    {
      $sStr.=chr(hexdec(substr($sHex,$i,2)));
    }
    return $sStr;
  }
}