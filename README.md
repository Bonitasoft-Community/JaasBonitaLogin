# JaasBonitaLogin
Jaas module to query the Bonita User Database, and return true if the login / password exist. This JAAS module is perfect if you want to use multiple JAAS module, and say "in Bonita OR in my LDAP"

1/ installation
Copy the jar file in <tomcat>/webapps/bonita/WEB_INF/lib (or for another web server, where the bonita jar file are)

2/ JAAS file

Add this module in the JAAS.cfg file:

BonitaAuthentication-1 {
    com.bonitasoft.jaaslogin.JaasBonitaLogin SUFFICIENT
    tenantid="1";
};


Example:


BonitaAuthentication-1 {

 com.sun.security.auth.module.LdapLoginModule sufficient
	userProvider="ldap://ldap.forumsys.com:389/cn=read-only-admin,dc=example,dc=com"
	authIdentity="cn=read-only-admin,dc=example,dc=com"
	debug=true
	useSSL=false;
	
		 
	// if the user does not exist in the LDAP, use the BonitaJaas
	com.bonitasoft.jaaslogin.JaasBonitaLogin sufficient
		tenantid="1"
		debug=false;

 

};

ATTENTION:
The LDAP-Synchronizer tool creates users in Bonita when it detect a user exist in the LDAP, and not in Bonita. Doing that, it creates a very easy password.
So, using this Authentication implie that you change this password in the Bonita Database, else, if the password failed in the LDAP, this JAAS source will check
the user with this easy-password.

