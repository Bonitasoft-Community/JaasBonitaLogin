package com.bonitasoft.jaaslogin;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.FailedLoginException;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;

import org.bonitasoft.engine.api.IdentityAPI;
import org.bonitasoft.engine.connector.ConnectorAPIAccessorImpl;
import org.bonitasoft.engine.identity.IdentityService;
import org.bonitasoft.engine.identity.SUserNotFoundException;
import org.bonitasoft.engine.identity.User;
import org.bonitasoft.engine.identity.UserNotFoundException;
import org.bonitasoft.engine.identity.model.SUser;
import org.bonitasoft.engine.service.TenantServiceSingleton;

public class JaasBonitaLogin implements LoginModule {

    private Subject subject;
    private CallbackHandler callbackHandler;
    private Map sharedState;
    private Map options;
    private boolean isdebug = false;
    private boolean isDiscoverUser = false;
    private boolean succeeded = false;
    private Long optTenantId = null;

    public JaasBonitaLogin() {
        log("Login Module - constructor called", true);
    }

    public boolean abort() throws LoginException {
        log("Login Module - abort called", true);
        return true;
    }

    public boolean commit() throws LoginException {
        log("Login Module - commit called", true);
        return true;
    }

    /**
     *
     */
    public void initialize(final Subject subject, final CallbackHandler callbackHandler, final Map<String, ?> sharedState,
            final Map<String, ?> options) {

        log("Login Module - initialize called", true);
        this.subject = subject;
        this.callbackHandler = callbackHandler;
        this.sharedState = sharedState;
        this.options = options;

        if (options != null)
        {
            try
            {
                isdebug = "true".equalsIgnoreCase(options.get("debug").toString());
                optTenantId = Long.valueOf(options.get("tenantid").toString());
                isDiscoverUser = "true".equalsIgnoreCase(options.get("discoveruser").toString());
            } catch (final Exception e)
            {
            };
            log("initialize, Options: " + options.toString() + " isDebug[" + isdebug + "] isDiscoverUser[" + isDiscoverUser + "]", false);
        }
        succeeded = false;
    }

    /**
     *
     */
    public boolean login() throws LoginException {
        log("Login Module - login called", true);
        if (callbackHandler == null) {
            throw new LoginException("Oops, callbackHandler is null");
        }

        final Callback[] callbacks = new Callback[2];
        callbacks[0] = new NameCallback("name:");
        callbacks[1] = new PasswordCallback("password:", false);

        try {
            callbackHandler.handle(callbacks);
        } catch (final IOException e) {
            throw new LoginException("Oops, IOException calling handle on callbackHandler");
        } catch (final UnsupportedCallbackException e) {
            throw new LoginException("Oops, UnsupportedCallbackException calling handle on callbackHandler");
        }

        final NameCallback nameCallback = (NameCallback) callbacks[0];
        final PasswordCallback passwordCallback = (PasswordCallback) callbacks[1];

        final String username = nameCallback.getName();
        final String password = new String(passwordCallback.getPassword());

        log("Check User[" + username + "] v4", true);

        // -------------------------------------------- get the tenant
        final long tenantId = optTenantId == null ? 1 : optTenantId;

        if (isDiscoverUser) {
            discoverUsers(1);
        }

        succeeded = checkUserByServiceAPI(tenantId, username, password);

        if (!succeeded)
        {
            succeeded = checkUserByApi(tenantId, username, password);
        }

        if (!succeeded) {
            throw new FailedLoginException("NoLogin for [" + username + "]");
        }
        log("Check User[" + username + "] Result[" + succeeded + "]", false);

        return succeeded;
    }

    public boolean logout() throws LoginException {
        log("Login Module - logout called", true);
        return false;
    }

    /**
     * @param tenantId
     * @param username
     * @param password
     * @return
     */
    private boolean checkUserByServiceAPI(final long tenantId, final String username, final String password)
    {
        boolean succeeded = false;
        try
        {
            log("checkUserByServiceAPI[" + username + "] tenantId[" + tenantId + "]", true);

            SUser suser;

            /*
             * User user;
             * final ConnectorAPIAccessorImpl connectorAccessorAPI = new ConnectorAPIAccessorImpl(tenantId);
             * final IdentityAPI identityAPI = connectorAccessorAPI.getIdentityAPI();
             * user = identityAPI.getUserByUserName(username);
             * suser = TenantServiceSingleton.getInstance(1).getIdentityService().getUser(user.getId());
             */
            // check the password

            suser = TenantServiceSingleton.getInstance(1).getIdentityService().getUserByUserName(username);
            log(" User found[" + suser.getUserName() + "] id[" + suser.getId() + "]", true);

            succeeded = TenantServiceSingleton.getInstance(1).getIdentityService().checkCredentials(suser, password);
            log(" RESULT SUser[" + username + "] succeed " + succeeded, false);

        } catch (final SUserNotFoundException e) {
            log("User[" + username + "] not found via SUser: " + e.toString(), false);
            succeeded = false;

        } catch (final Exception e) {
            final StringWriter sw = new StringWriter();
            e.printStackTrace(new PrintWriter(sw));
            final String exceptionDetails = sw.toString();

            log("General exception for User[" + username + "] " + e.toString() + " at " + exceptionDetails, false);
            succeeded = false;

        }

        return succeeded;

    }

    /**
     * @param tenantId
     * @param username
     * @param password
     * @return
     */
    private boolean checkUserByApi(final long tenantId, final String username, final String password)
    {
        boolean succeeded = false;
        try {
            log("checkUserByApi[" + username + "] tenantId[" + tenantId + "]", true);

            User user;
            final ConnectorAPIAccessorImpl connectorAccessorAPI = new ConnectorAPIAccessorImpl(tenantId);

            final IdentityAPI identityAPI = connectorAccessorAPI.getIdentityAPI();
            user = identityAPI.getUserByUserName(username);
            succeeded = user.getPassword() == password;
            log(" RESULT User[" + username + "] succeed " + succeeded + "]", false);
            // getPassword()=[" + user.getPassword() + "] password=[" + password + "]", false);
            // for the moment, if the user exist, consider it at true
            succeeded = true;

        } catch (final UserNotFoundException e)
        {
            log("User[" + username + "] not found via getUserByUserName: " + e.toString(), false);
            succeeded = false;
        } catch (final Exception e) {
            final StringWriter sw = new StringWriter();
            e.printStackTrace(new PrintWriter(sw));
            final String exceptionDetails = sw.toString();

            log("General exception for User[" + username + "] " + e.toString() + " at " + exceptionDetails, false);
            succeeded = false;
        }
        return succeeded;
    }

    /**
     * @param tenantId
     */
    private void discoverUsers(final long tenantId) {

        String trace = "";
        try
        {
            final IdentityService identityService = TenantServiceSingleton.getInstance(tenantId).getIdentityService();

            trace += "IdentidyService: [" + identityService.toString() + "]";

            final long nbUsers = identityService.getNumberOfUsers();
            trace += "NbUsers = " + nbUsers + ";";
            final List<SUser> listUsers = identityService.getUsers(0, 1000);
            for (final SUser suser : listUsers)
            {
                trace += "user[" + suser.getUserName() + "] id[" + suser.getId() + "] getPassword[" + suser.getPassword() + "]"
                        + identityService.checkCredentials(suser, "bpm");

            }
            log("Discover User [" + trace + "]", true);
        } catch (final Exception e)
        {
            log("ERROR at Discover User TenantId[" + tenantId + "] Error [" + e.toString() + "] trace[" + trace + "]", true);

        }

    }

    /**
     * log
     */
    Logger logger = Logger.getLogger("com.bonitasoft.jaaslogin.JaasBonitaLogin");

    private void log(final String message, final boolean logAsDebug)
    {
        if (logAsDebug)
        {
            if (isdebug) {
                // to go to the System.out like do a real LDAP module... go to Catalina.out in fact
                System.out.println("  JaasBonitaLogin(debug):" + message);
                logger.info("  JaasBonitaLogin(debug):" + message);
            }
        } else {
            System.out.println("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ JaasBonitaLogin: " + message);

            logger.info("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ JaasBonitaLogin: " + message);
        }
    }

}
