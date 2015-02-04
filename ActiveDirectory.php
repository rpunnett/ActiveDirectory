<?php

  /**
 * @class name: ActiveDirectory
 *
 * @Version: 3.0.2
 * 
 * @description: Access the Active Directory Servers
 * 
 *  Offers two static functions:
 *      * getDetails: Queries a person or pc
 *      * verify: checks a users credentials
 *
 *  Example: ActiveDirectory::verify('<USERNAME>','<PASSWORD>');
 *      Returns: True or False
 * 
 *  Example: ActiveDirectory::getDetails('<USERNAME>','user');
 *      Returns: A user object of LDAP info or False
 * 
 * @author Robert Punnett
 * @date 02-03-2015
 */
 
class ActiveDirectory {
    
    private $_bind = false;//Stores LDAP bind
    private $_cnx = false; //Stores LDAP Connection object
    
    private $_userSearchField = "SamAccountName";   //In what Active Directory field do you want to search for the string
    private $_cnSearchField = "Name";   //In what Active Directory field do you want to search for the string
	private $_LDAPHost = 'example.ad.example.com';       //Your LDAP server DNS Name or IP Address
	private $_dn = 'DC=example,DC=AD,DC=example,DC=COM'; //Put your Base DN here
	private $_LDAPUserDomain = "@example";  //Needs the @, but not always the same as the LDAP server domain
    private $_adminUser = 'theUser'; //Base account RACF to do LDAP queries
    private $_adminPassword = 'thePassword'; //Base account password to do LDAP queries
    
    private $_userFields = array( //Array of fields to retrieve from user
        "SamAccountName",
        "UserPrincipalName",
        "thumbnailphoto",
        "givenname",
        "surname",
        "memberof",
        "sn",
        "title",
        "StreetAddress",
        "st",
        "l",
        "physicaldeliveryofficename",
        "Department",
        "telephoneNumber",
        "mobile",
        "postalcode",
        "CanonicalName",
        "mail",
        "useraccountcontrol",
        "badpwdcount",
        "badpasswordtime",
        "accountexpires",
        "lockouttime"
    );
    
    private $_cnFields = array(  //Array of fields to retrieve from a pc
        "CN",
    	"createtimestamp",
    	"DistinguishedName",
    	"lastlogontimestamp",
    	"modifytimestamp",
    	"OperatingSystem",
    	"whenChanged",
    	"CanonicalName",
    );
    
    private $_forests = array(  //List of LDAP forests
    	"example.ad.example.com" => "DC=example,DC=AD,DC=example,DC=COM",
    );

        
    public function __construct() {
    
     
    }   

    /**
	 * Setup the connection and bind
	 *
     *  @param string $host  The ldap hostname
     *  @param string $user  A user's username
     *  @param string $password  A user's password
     * 
	 * @return bool
	 */    
    private function connect ($host = 'example.ad.example.com' , $user = 'theUser', $password = 'thePassword') {
        
        $this->_cnx = ldap_connect($host) 
            or die("Could not connect to {$host}");
        
        
        if (!ldap_set_option($this->_cnx, LDAP_OPT_PROTOCOL_VERSION, 3)) { //Version 3! Defaults to UTF-8
            throw new Exception('Could not set LDAP to Protocol Version 3');
        }

         if (!ldap_set_option($this->_cnx, LDAP_OPT_REFERRALS, 0)) { //Set to 0 LDAP referrals
            throw new Exception('Could not set LDAP to Opt Referrals: 0');
        }
        
        // The @ sign suppresses the exception
        if(!($this->_bind=@ldap_bind($this->_cnx,$user.$this->_LDAPUserDomain,$password)))
        {
            return false;
            //Exception works but breaks other code......false allows to check login info//Depreciate? 
            //throw new Exception('Could not connect to LDAP through connect function. Please check settings.');
        }
        
         return true;
        
    
    }
    
    
   /**
     * Checks if a passed U/P binds against AD
	 *
     *  @param string $user  A user's username
     *  @param string $password  A user's password
     * 
	 * @return bool
	 */ 
    static function verify($user, $password) {
    
        $AD = new ActiveDirectory();
        
        if( $AD->connect($AD->_LDAPHost,$user,$password) )
        {
            return true;
        }
        else
        {
            return false;
        }
        
        //If all else fails...
        throw new Exception('Could not verify user\'s credentials. Unknown exception.');
    }
        
     
    /**
    * Gets the details of a pc or user
    *
    *  @param string $value  What is being search for (Person or PC)
    *  @param string $type  Determines what is being searched -> Options are 'user' or 'cn'
    * 
    * @return object, or false
    */ 
    public static function getDetails($value,$type = 'user'){
    
        //Create new object instance
        $AD = new ActiveDirectory();     
        
        //get the return object
        $return = $AD->search($value,$type);
        
        //If there is a result...
        if($return)
        {
            //Clean up the results and return it
            return  $AD->ldapArraytoObject($return);
        }
        
        //else if no results found, do something elese..
        return false;
    
    }//end of search function
    
    
     /**
     * Searches LDAP, if found, returns an object of the search fields
     * if not found, returns false
	 *
     *  @param string $value  What is being search for (Person or PC)
     *  @param string $type  Determines what is being searched -> Options are 'user' or 'cn'
     *  @param array $searchField  The fields to search for IE -> mail, photo, samaccountname...
     * 
	 * @return object
	 */   
    private function search($value,$type = 'user', $searchField = null) {
        
        $count = count($this->_forests);
        $loops = 0;
        
        foreach($this->_forests as $LDAPHost => $dn)
        {
            //Log::info($LDAPHost);
            $this->connect($LDAPHost);

  
            if($type == 'user')
            {   
                //Set type specific info
                //The field to search in
                $field = $this->_userSearchField;
                //The fields to search for
                $searchField = $searchField?: $this->_userFields;
                 
                $filter="($field=$value*)"; 
                $sr=ldap_search($this->_cnx, $dn, $filter,  $searchField); 
            }
            else if($type == 'cn')
            {
                //Set type specific info
                //The field to search in
                $field = $this->_cnSearchField ;
                //The fields to search for
                $searchField = $searchField?: $this->_cnFields;
                
                $filter="($field=$value*)"; 
                $sr=ldap_search($this->_cnx, $this->_dn, $filter, $searchField ); 
            }
            
                //Perform the search
                $info = ldap_get_entries($this->_cnx, $sr);
                
                if($info['count'] === 0)
                {
                    //If no results -> keep going
                    $loops++;
                }
                else if($info['count'] === 1)
                {
                    //Else stop searching and get a real job
                    break;
                }

        }
 
            //If all DN's have been checked, just give up
            if($loops === $count)
            {   
                return false;
            }
    
        //If a result was found, go ahead and return it, you earned it
        return $info;
        
    }
    
    /**
    * Modifies the LDAP Array
    * Changes the array into an object
    * Cleans any fields that don't show human readable data
    *   IE -> Timestamps, account statuses.....
    *
    *  @param array $array  The input array to turn into an object and 'clean'
    *  
    * @return object or false
    */ 
    private function ldapArraytoObject($array){
        
        $results = new StdClass;
        $newArrary = array();
        
        foreach($array as $item) 
        {
            if (is_array($item)) 
            {
                foreach ($item as $key => $value) 
                {
                    if ((count($item[$key]) - 1) === 1)  //If the item is NOT an array
                    {
                        
                        if (is_array($value)) 
                        {
                            //Remove count
                            unset($item[$key]["count"]);
                        }
                        
                        //If item is a time stamp, convert to human readable
                        if(preg_match("/(createtimestamp)|(modifytimestamp)|(whenchanged)|(badpasswordtime)|(accountexpires)|(lastlogontimestamp)/", $key, $matches))
                        {
                            $item[$key][0] = $this->convertTimestamp($item[$key][0]);
                        }
                        
                        //If item is a photo, convert to base64
                        if(preg_match("/(photo)/", $key, $matches))
                        {
            			    $item[$key][0] = base64_encode($item[$key][0]);
                        }
                        
                        //Makes the account status human readble
                        if(preg_match("/(useraccountcontrol)/", $key, $matches))
                        {     
                		    $item[$key][0] =   $this->getAccountStatus($item[$key][0]);
                        }
                        
                        //Cleans email by removing exchange
                        if(preg_match("/(mail)/", $key, $matches))
                        {
                            $item[$key][0] = (explode("@", $item[$key][0])[0]). '@nscorp.com';
                        }               
                        
                        //Send it to the new object
                        $results->$key = $item[$key][0];
                    }
                    elseif((count($item[$key]) - 1) > 1)  //If the item IS an array
                    {
                        
                        if(isset($item[$key]['count']))
                        {
                            //Remove the count array position
                            unset($item[$key]['count']);
                        }
                        
                        foreach($item[$key] as $arrayPosition)
                        {
                            //Build the new array
                           array_push($newArrary, $arrayPosition);
                        }
                        
                        //Send it to the new object
                        $results->$key = $newArrary;
                        
                    }
                }
            }
        }
   
        return $results;
    }

    /**
    * Coverts an LDAP timestamp to human readable
    *
    *  @param string $ts  The timestamp to be made readable
    * 
    * @return string
    */ 
    private function convertTimestamp($ts){

        $regex = "/z$/i"; 
        
        if (preg_match($regex, $ts, $matches)) {
            //Converts ZULU time to standard
            $year = substr($ts,0,4);
            $month = substr($ts,4,2);
            $day = substr($ts,6,2);
            $hour = substr($ts,8,2);
            $minute = substr($ts,10,2);
            $second = substr($ts,12,2);
            // Output the finished timestamp
            $normalDate = $month."/".$day."/".$year." ".$hour.":".$minute.":".$second;
        }
        else
        {
            //CONVERTS WIN32FILETIME/LDAP TIME to Standard
            $seconds_ad = $ts / (10000000);
            //86400 -- seconds in 1 day
            $unix = ((1970-1601) * 365 - 3 + round((1970-1601)/4) ) * 86400;
            $timestamp = $seconds_ad - $unix; 
            //$today = date("m.d.y");    
            $normalDate = date('m\/d\/Y h:i:s', $timestamp);
            
            
        }
        //Returns a nice human readable date
        return $normalDate;
    }  



    /**
    * Converts LDAP account status to human readable
    *
    *  @param string $value  The account status (IE -> 512) to convert
    * 
    * @return string
    */  
    private function getAccountStatus($value){
        switch($value)
        {
            case 512: return "Enabled";
            case 514: return "Disabled";
            case 544: return "Account Enabled - Require user to change password at first logon";
            case 4096: return "Workstation/server";
            case 66048: return "Enabled, password never expires";
            case 66050: return "Disabled, password never expires";
            case 262656: return "Smart Card Logon Required";
            case 532480: return "Domain controller" ;
            case 1: return "script";
            case 2: return "accountdisable";
            case 8: return "homedir_required";
            case 16: return "lockout";
            case 32: return "passwd_notreqd";
            case 64: return "passwd_cant_change";
            case 128: return "encrypted_text_pwd_allowed";
            case 256: return "temp_duplicate_account";
            case 512: return "normal_account";
            case 2048: return "interdomain_trust_account";
            case 4096: return "workstation_trust_account";
            case 8192: return "server_trust_account";
            case 65536: return "dont_expire_password";
            case 131072: return "mns_logon_account";
            case 262144: return "smartcard_required";
            case 524288: return "trusted_for_delegation";
            case 1048576: return "not_delegated";
            case 2097152: return "use_des_key_only";
            case 4194304: return "dont_req_preauth";
            case 8388608: return "password_expired";
            case 16777216: return "trusted_to_auth_for_delegation";
        }  
    } 

}//end of ActiveDirectory Class
