package com.bonitasoft.jaaslogin;

import java.io.IOException;
import java.util.logging.Logger;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

public class JaasCallback implements CallbackHandler {

    String name;
    String password;

    public JaasCallback(final String name, final String password) {
        log("constructor called");
        this.name = name;
        this.password = password;
    }

    public void handle(final Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        log("handle called");
        for (int i = 0; i < callbacks.length; i++) {
            if (callbacks[i] instanceof NameCallback) {
                final NameCallback nameCallback = (NameCallback) callbacks[i];
                nameCallback.setName(name);
            } else if (callbacks[i] instanceof PasswordCallback) {
                final PasswordCallback passwordCallback = (PasswordCallback) callbacks[i];
                passwordCallback.setPassword(password.toCharArray());
            } else {
                throw new UnsupportedCallbackException(callbacks[i], "The submitted Callback is unsupported");
            }
        }
    }

    /**
     * log
     */
    Logger logger = Logger.getLogger("com.bonitasoft.jaaslogin.JaasCallback");

    private void log(final String message)
    {
        logger.info("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ JaasCallback:" + message);
    }
}
