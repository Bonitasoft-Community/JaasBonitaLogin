package com.bonitasoft.jaaslogin;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.Method;
import java.util.List;

import org.bonitasoft.engine.api.IdentityAPI;
import org.bonitasoft.engine.api.LoginAPI;
import org.bonitasoft.engine.api.TenantAPIAccessor;
import org.bonitasoft.engine.connector.ConnectorAPIAccessorImpl;
import org.bonitasoft.engine.identity.CustomUserInfo;
import org.bonitasoft.engine.identity.IdentityService;
import org.bonitasoft.engine.identity.SUserNotFoundException;
import org.bonitasoft.engine.identity.User;
import org.bonitasoft.engine.identity.UserNotFoundException;
import org.bonitasoft.engine.identity.model.SUser;
import org.bonitasoft.engine.platform.LoginException;
import org.bonitasoft.engine.service.TenantServiceSingleton;
import org.bonitasoft.engine.session.APISession;

import com.bonitasoft.jaaslogin.JaasBonitaLogin.TYPECHECK;


class JaasBonitaLoginThread implements Runnable {

    /**
     * 
     */
    private final JaasBonitaLogin jaasBonitaLogin;

    public Long lock = Long.valueOf(0);
    
    private long tenantId;
    private String userName;
    private String passWord;
    private boolean succedded;
    private TYPECHECK typeCheck;
    private String customuserattribut;
    private long userId;
    
    JaasBonitaLoginThread(JaasBonitaLogin jaasBonitaLogin, TYPECHECK typeCheck, String customuserattribut, long tenantId, String userName, String passWord) {
        this.jaasBonitaLogin = jaasBonitaLogin;
        this.typeCheck = typeCheck;
        this.customuserattribut = customuserattribut;
        this.tenantId = tenantId;        
        this.userName = userName;
        this.passWord = passWord;
    }

    public void setTypeCheck( TYPECHECK typeCheck ) {
        this.typeCheck = typeCheck;
    }
    public void setUserId(long userId) {
        this.userId = userId;
    }
    
    public long getTenantID() {
        return tenantId;
    }
    public boolean isSucceed() {
        return succedded;
    }
    public void run() {
        if (this.typeCheck == TYPECHECK.CHECKPASSWORD)
            succedded = checkUserByServiceAPI(tenantId, userName, passWord);
        else if (this.typeCheck == TYPECHECK.LOGINAPI)
            succedded = checkUserByLoginAPI(tenantId, userName, passWord);
        else if (this.typeCheck == TYPECHECK.SERVICE)
            succedded = checkUserByApi(tenantId, userName, passWord);
        else if (this.typeCheck == TYPECHECK.JUSTVERIFYCUSTOMATTRIBUT)
            succedded = verifyCustomAttribut(tenantId, userId);
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
            this.userId = suser.getId();
            
            succeeded = identityService.checkCredentials(suser, password);        
            final ConnectorAPIAccessorImpl connectorAccessorAPI = new ConnectorAPIAccessorImpl(tenantId);
            final IdentityAPI identityAPI = connectorAccessorAPI.getIdentityAPI();
           

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
    public boolean checkUserByLoginAPI(final long tenantId, final String username, final String password)
    {
        boolean succeeded = false;
        try {
            
            jaasBonitaLogin.log("checkUserByLogin[" + username + "] tenantId[" + tenantId + "]", true);


            final LoginAPI loginAPI = TenantAPIAccessor.getLoginAPI();
            final APISession apiSession;
            if (loginAPI.getClass().getName().equals("com.bonitasoft.engine.api")) {
                // login(long tenantId, String userName, String password)
                Method mLoginWithTenant = loginAPI.getClass().getDeclaredMethod("login", long.class, String.class, String.class);  
                apiSession = (APISession) mLoginWithTenant.invoke(loginAPI, tenantId, username, password);  
            }
            else {
                apiSession = loginAPI.login(username, password);
            }
            
            IdentityAPI identityAPI = TenantAPIAccessor.getIdentityAPI(apiSession);
            if (succeeded)
                succeeded= verifyCustomAttribut( tenantId, apiSession.getUserId() );
            loginAPI.logout(apiSession);
            
            
        } catch ( NullPointerException | LoginException e)
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
            if (succeeded)
                succeeded= verifyCustomAttribut(tenantId, user.getId());
            
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
    
    
    private boolean verifyCustomAttribut(final long tenantId, long userId) {
        if (customuserattribut == null)
            return true;

        ConnectorAPIAccessorImpl connectorAccessorAPI = new ConnectorAPIAccessorImpl(tenantId);
        IdentityAPI identityAPI = connectorAccessorAPI.getIdentityAPI();
       
        String customName = customuserattribut;
        String customValue="true";
            
        int pos=customuserattribut.indexOf(":");
        if (pos!=-1) {
            customName = customuserattribut.substring(0,pos);
            customValue = customuserattribut.substring(pos+1);
        }
        jaasBonitaLogin.log("verifyCustomAttribut[" + customName + "] value[" + customValue + "]", true);
            
        List<CustomUserInfo> listCustomInfo = identityAPI.getCustomUserInfo( userId,0,10000);
        for (CustomUserInfo customInfo : listCustomInfo)
        {
            if (customName.equals( customInfo.getDefinition().getName())) {
                if (customValue.equals(customInfo.getValue()))
                {
                    return true;
                } else {
                    jaasBonitaLogin.log("verifyCustomAttribut[" + customName + "] value[" + customInfo.getValue() +"] (expected ["+customValue + "])", true);
                    return false;
                }
            }
        }
        jaasBonitaLogin.log("verifyCustomAttribut[" + customName + "] does not exist", true);
        return false;
    }


}