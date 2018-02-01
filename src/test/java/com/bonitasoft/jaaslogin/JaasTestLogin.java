package com.bonitasoft.jaaslogin;
import static org.junit.Assert.fail;

import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import org.junit.Test;


public class JaasTestLogin {

    @Test
    public void test() {

        System.setProperty("java.security.auth.login.config", "C:/dev/workspace/JaasBonitaLogin/src/main/java/BonitaLoginJaas.cfg");

        final String name = "myName";
        final String password = "myPassword";

        try {
            final LoginContext lc = new LoginContext("BonitaAuthentication-1", new JaasCallback(name, password));
            lc.login();
        } catch (final LoginException e) {
            e.printStackTrace();
            fail(e.toString());
        }
    }
}
