# JaasBonitaLogin
Jaas module to query the Bonita User Database, and return true if the login / password exist. This JAAS module is perfect if you want to use multiple JAAS module, and say "in Bonita OR in my LDAP"

## installation
Copy the jar file in <tomcat>/webapps/bonita/WEB_INF/lib (or for another web server, where the bonita jar file are)

## JAAS file

Add this module in the JAAS.cfg file:

BonitaAuthentication-1 {
    com.bonitasoft.jaaslogin.JaasBonitaLogin SUFFICIENT
    tenantid="<tenantId>"
    [debug=true|false]
    [customuserattribut="<name>:<value>";
    ;
};


## Example:


BonitaAuthentication-1 {

 com.sun.security.auth.module.LdapLoginModule sufficient
	userProvider="ldap://ldap.forumsys.com:389/cn=read-only-admin,dc=example,dc=com"
	authIdentity="cn=read-only-admin,dc=example,dc=com"
	debug=true
	useSSL=false;
	
		 
	// if the user does not exist in the LDAP, use the BonitaJaas
	com.bonitasoft.jaaslogin.JaasBonitaLogin sufficient
		tenantid="1"
		debug=false
		customuserattribut="jaasbonitalogin:accepted";

 

};



# Security and Custom Attribute Verification
## ATTENTION:
The LDAP-Synchronizer tool creates users in Bonita when it detect a user exist in the LDAP, and not in Bonita. Doing that, it creates a very easy password.
So, using this Authentication implie that you change this password in the Bonita Database, else, if the password failed in the LDAP, this JAAS source will check
the user with this easy-password.
To
Use the Java API to check if the user/password exists and is correct. Stable across different Bonita version

## custom attribute
Add a "customuserattribut" option. If set, then the verification control that this custom attribute exist for the user, with the expected value.
So, let's imagine you create a custom attribute "jaasbonitalogin". When the user is created from LDAP, the value of the attribute is null. THe BonitaJaasLogin wioll reject this login everytime.
When you add manually a user, set the custom attribute to "accepted".


com.bonitasoft.jaaslogin.JaasBonitaLogin sufficient
		tenantid="1"
		debug=true
		customuserattribut="jaasbonitalogin:accepted";

