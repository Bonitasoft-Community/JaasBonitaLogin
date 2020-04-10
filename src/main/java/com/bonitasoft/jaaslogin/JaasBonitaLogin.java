package com.bonitasoft.jaaslogin;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.FutureTask;
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

import org.bonitasoft.engine.identity.IdentityService;
import org.bonitasoft.engine.identity.model.SUser;
import org.bonitasoft.engine.service.TenantServiceSingleton;

public class JaasBonitaLogin implements LoginModule {

    private CallbackHandler callbackHandler;
    // private Map<String, ?> sharedState;
    // private Map<String, ?> options;
    private boolean isdebug = false;
    private boolean isDiscoverUser = false;
    boolean succeeded = false;
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

        log("initialize called", true);        
        this.callbackHandler = callbackHandler;
        
        if (options != null)
        {
            try
            {
                isdebug = "true".equalsIgnoreCase(getOptionString(options, "debug", "false"));
                optTenantId = Long.valueOf(getOptionString(options, "tenantid", "1"));
                isDiscoverUser = "true".equalsIgnoreCase(getOptionString(options, "discoveruser", "false"));
            } catch (final Exception e)
            {
                StringWriter sw = new StringWriter();
                e.printStackTrace(new PrintWriter(sw));
                String exceptionDetails = sw.toString();
                
                log("initialize, Options: " + options.toString() + " Error "+e.getMessage()+" at "+exceptionDetails, true);
            };
            log("initialize, Options: " + options.toString() + " isDebug[" + isdebug + "] isDiscoverUser[" + isDiscoverUser + "]", false);
        }
        succeeded = false;
    }
    
    private String getOptionString(Map<String, ?> options, String attribut, String defaultValue ) {
        if (options.get(attribut)==null)
            return defaultValue;
        return options.get(attribut).toString();
    }

    /**
     *
     */
    public boolean login() throws LoginException {
        log("login called", true);
        if (callbackHandler == null) {
            throw new LoginException("Oops, callbackHandler is null");
        }

        final Callback[] callbacks = new Callback[2];
        callbacks[0] = new NameCallback("name:");
        callbacks[1] = new PasswordCallback("password:", false);

        try {
            callbackHandler.handle(callbacks);
        } catch (final IOException e) {
            StringWriter sw = new StringWriter();
             e.printStackTrace(new PrintWriter(sw));
             String exceptionDetails = sw.toString();
             
            throw new LoginException("Oops, IOException calling handle on callbackHandler at "+exceptionDetails);
        } catch (final UnsupportedCallbackException e) {
            StringWriter sw = new StringWriter();
             e.printStackTrace(new PrintWriter(sw));
             String exceptionDetails = sw.toString();
             
            throw new LoginException("Oops, UnsupportedCallbackException calling handle on callbackHandler at "+exceptionDetails);
        }

        final NameCallback nameCallback = (NameCallback) callbacks[0];
        final PasswordCallback passwordCallback = (PasswordCallback) callbacks[1];

        final String username = nameCallback.getName();
        final String password = new String(passwordCallback.getPassword());

        log("Check User[" + username + "] v2.0 - API", true);

        // -------------------------------------------- get the tenant
        final long tenantId = optTenantId == null ? 1 : optTenantId;

        if (isDiscoverUser) {
            discoverUsers(1);
        }

        // We must start a new Thread to check by the API, because a transaction is open here
        JaasBonitaLoginThread runJaasLoginThread = new JaasBonitaLoginThread(this, tenantId, username, password);
        
        try {
        
            FutureTask<String> futureTask = new FutureTask<>(runJaasLoginThread, "Check Login");
            // create thread pool of 1 size for ExecutorService 
            ExecutorService executor = Executors.newFixedThreadPool(1);
            executor.execute(futureTask);
        
            // wait end of execution
            futureTask.get();
            succeeded= runJaasLoginThread.succedded;
        } catch (InterruptedException e) {
            StringWriter sw = new StringWriter();
            e.printStackTrace(new PrintWriter(sw));
            String exceptionDetails = sw.toString();

            logger.severe("JaasBonitaLogin. error " + e.toString()+" at "+exceptionDetails);
            Thread.currentThread().interrupt();
        } catch (ExecutionException e) {
            StringWriter sw = new StringWriter();
            e.printStackTrace(new PrintWriter(sw));
            String exceptionDetails = sw.toString();
            logger.severe("JaasBonitaLogin. error " + e.toString()+" at "+exceptionDetails);
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
     */
    private void discoverUsers(final long tenantId) {

        StringBuilder trace = new StringBuilder();
        try
        {
            final IdentityService identityService = TenantServiceSingleton.getInstance(tenantId).getIdentityService();

            trace.append( "IdentidyService: [" + identityService.toString() + "]");

            final long nbUsers = identityService.getNumberOfUsers();
            trace.append( "NbUsers = " + nbUsers + ";" );
            final List<SUser> listUsers = identityService.getUsers(0, 1000);
            for (final SUser suser : listUsers)
            {
                trace.append( "user[" + suser.getUserName() + "] id[" + suser.getId() + "] getPassword[" + suser.getPassword() + "]"
                        + identityService.checkCredentials(suser, "bpm"));

            }
            log("Discover User [" + trace.toString() + "]", true);
        } catch (final Exception e)
        {
            StringWriter sw = new StringWriter();
            e.printStackTrace(new PrintWriter(sw));
            String exceptionDetails = sw.toString();

            log("ERROR at Discover User TenantId[" + tenantId + "] Error [" + e.toString() + "] trace[" + trace.toString() + "] at "+exceptionDetails, true);
        }

    }

    /**
     * log
     */
    Logger logger = Logger.getLogger("com.bonitasoft.jaaslogin.JaasBonitaLogin");

    void log(final String message, final boolean logAsDebug)
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
