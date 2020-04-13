package com.bonitasoft.jaaslogin;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.List;

import org.bonitasoft.engine.api.IdentityAPI;
import org.bonitasoft.engine.connector.ConnectorAPIAccessorImpl;
import org.bonitasoft.engine.identity.IdentityService;
import org.bonitasoft.engine.identity.SUserNotFoundException;
import org.bonitasoft.engine.identity.User;
import org.bonitasoft.engine.identity.UserNotFoundException;
import org.bonitasoft.engine.identity.model.SUser;
import org.bonitasoft.engine.service.TenantServiceSingleton;

class JaasBonitaLoginThread implements Runnable {

    /**
     * 
     */
    private final JaasBonitaLogin jaasBonitaLogin;

    public Long lock = Long.valueOf(0);
    
    private long tenantId;
    private String userName;
    private String passWord;
    boolean succedded;
    
    JaasBonitaLoginThread(JaasBonitaLogin jaasBonitaLogin, long tenantId, String userName, String passWord) {
        this.jaasBonitaLogin = jaasBonitaLogin;
        this.tenantId = tenantId;        
        this.userName = userName;
        this.passWord = passWord;
    }

    
    public long getTenantID() {
        return tenantId;
    }
    public boolean isSucceed() {
        return succedded;
    }
    public void run() {
        // succedded = checkUserByApi(tenantId, userName, passWord);
        succedded = checkUserByServiceAPI(tenantId, userName, passWord);
    }
    
   
    
    /**
     * @param tenantId
     * @param username
     * @param password
     * @return
     */
    public boolean checkUserByServiceAPI(final long tenantId, final String username, final String password)
    {
        boolean succeeded = false;
        try
        {
            jaasBonitaLogin.log("checkUserByServiceAPI[" + username + "] tenantId[" + tenantId + "]", true);

            SUser suser;

            /*
             * User user;
             * final ConnectorAPIAccessorImpl connectorAccessorAPI = new ConnectorAPIAccessorImpl(tenantId);
             * final IdentityAPI identityAPI = connectorAccessorAPI.getIdentityAPI();
             * user = identityAPI.getUserByUserName(username);
             * suser = TenantServiceSingleton.getInstance(1).getIdentityService().getUser(user.getId());
             */
            
            // check the password
            IdentityService identityService = TenantServiceSingleton.getInstance(tenantId).getIdentityService();
            suser = identityService.getUserByUserName(username);
            // jaasBonitaLogin.log(" User found[" + suser.getUserName() + "] id[" + suser.getId() + "]", true);

            succeeded = identityService.checkCredentials(suser, password);            
            jaasBonitaLogin.log("Authentication User[" + username + "] succeed [" + succeeded + "]", false);

        } catch (final SUserNotFoundException e) {
            jaasBonitaLogin.log("User[" + username + "] not found via SUser: " + e.toString(), false);
            succeeded = false;

        } catch (final Exception e) {
            final StringWriter sw = new StringWriter();
            e.printStackTrace(new PrintWriter(sw));
            final String exceptionDetails = sw.toString();

            jaasBonitaLogin.log("General exception for User[" + username + "] " + e.toString() + " at " + exceptionDetails, false);
            succeeded = false;
        } catch (final Error e) {
            final StringWriter sw = new StringWriter();
            e.printStackTrace(new PrintWriter(sw));
            final String exceptionDetails = sw.toString();
    
            jaasBonitaLogin.log("General Error for User[" + username + "] " + e.toString() + " at " + exceptionDetails, false);
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
            jaasBonitaLogin.log("checkUserByApi[" + username + "] tenantId[" + tenantId + "]", true);

            User user;
            final ConnectorAPIAccessorImpl connectorAccessorAPI = new ConnectorAPIAccessorImpl(tenantId);

            final IdentityAPI identityAPI = connectorAccessorAPI.getIdentityAPI();
            user = identityAPI.getUserByUserName(username);
            succeeded = password.equals( user.getPassword());
            jaasBonitaLogin.log("Authentication User[" + username + "] succeed [" + succeeded + "] password["+password+"] UserReference["+user.getPassword()+"]", false);
            // getPassword()=[" + user.getPassword() + "] password=[" + password + "]", false);
            // for the moment, if the user exist, consider it at true
        } catch (final UserNotFoundException e)
        {
            jaasBonitaLogin.log("User[" + username + "] not found via getUserByUserName: " + e.toString(), false);
            succeeded = false;
        } catch (final Exception e) {
            final StringWriter sw = new StringWriter();
            e.printStackTrace(new PrintWriter(sw));
            final String exceptionDetails = sw.toString();

            jaasBonitaLogin.log("General exception for User[" + username + "] " + e.toString() + " at " + exceptionDetails, false);
            succeeded = false;
        }
        return succeeded;
    }
    


}