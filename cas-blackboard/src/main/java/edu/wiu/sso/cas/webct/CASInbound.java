/**
 *
 *   WIU's Blackboard 8 CAS SSO Custom Authentication Module
 *   Copyright (C) 2011  Western Illinois University
 * 
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 * 
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 * 
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *   Written by Russell E Glaue, rglaue@cait.org, re-glaue@wiu.edu
 *   Center for the Application of Information Technologies
 *   Western Illinois University
 *   http://www.cait.org
 *   http://www.wiu.edu
 *
 *
 * Referenced Material:
 * 1. Blackboard Learning System(tm)
 *    PowerLinks Kit Programmer's Guide
 *    Blackboard Learning System — CE Enterprise License (Release 8)
 *    Blackboard Learning System — Vista Enterprise License (Release 8)
 *    SDK version 8.0.0
 *    Document version 8.0.0.0
 */

package edu.wiu.sso.cas.webct;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.lang.Boolean;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.util.Hashtable;
import java.util.Map;
import java.util.Date;
import java.util.regex.*;

import java.text.ParseException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.security.GeneralSecurityException;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.login.LoginException;
import javax.servlet.http.HttpServletRequest;

import org.apache.log4j.Logger;

import com.webct.platform.sdk.security.authentication.module.AuthenticationModule;
import com.webct.platform.sdk.security.authentication.module.WebCTSSOContext;
import edu.wiu.sso.cas.AuthService;
import edu.wiu.sso.cas.ServiceTicket;
import edu.wiu.sso.weblogicHttpsUrlRequest;

/**
 * <p>
 * This is an inbound SSO module for Blackboard WebCT Vista. It extends the class
 * {@link com.webct.platform.sdk.security.authentication.module.AuthenticationModule}
 * from the Blackboard/WebCT PowerLinks SDK (v 4.2.1).
 * </p>
 *
 * @version 1.3.1
 * @author Copyright (c) 2010-2011 by Western Illinois University, CAIT. All Rights Reserved.
 * @see com.webct.platform.sdk.security.authentication.module.AuthenticationModule
 * @see <br><a href="http://www.edugarage.com/display/BBDN/Documentation">Blackboard Developer Network Documentation</a>
 * @see <br><a href="http://library.blackboard.com/ref/54086399-82d8-4827-a8a2-5fc39b51a294/">PowerLinks SDK APIs v4.2.1</a>
 * @see <br><a href="http://www.edugarage.com/display/BBDN/Integration+Scenarios">Blackboard/WebCT Authentication Integration Scenarios</a>
 */
public class CASInbound extends com.webct.platform.sdk.security.authentication.module.AuthenticationModule {
    private static final Logger logger = Logger.getLogger(CASInbound.class);
    private static final String classname = CASInbound.class.getName();
    private static final Logger auditlog = Logger.getLogger( (classname + ".audit") );
    private static final String VERSION = "1.3.1";
    private String casUserId = null;

    /**
     * Constructor
     */
    public CASInbound() {
        super();
        logger.debug("[" + classname + "] in CASInboundModule() Constructor "+VERSION);
    }

    /**
     * Constructor
     * @param arg0
     */
    public CASInbound(Hashtable arg0) {
        super(arg0);
        logger.debug("[" + classname + "] in CASInboundModule(Hashtable) Constructor "+VERSION);
    }

    /**
     * getCasUserId
     * @return casUserId the userid retrieved from the CAS ticket
     */
    private String getCasUserId() {
        return casUserId;
    }

    /**
     * setCasUserId
     * @param setCasUserId the userid retrieved from the CAS ticket
     */
    private void setCasUserId(String value) {
        casUserId = value;
    }

    /**
     * abort
     * The WebCT Vista SDK SSO abort method
     * The abort method can be used to perform cleanup in the event that
     * authentication fails. This method must return true.
     * @see javax.security.auth.spi.LoginModule#abort()
     */
    public boolean abort() throws LoginException {
        logger.debug("[" + classname + ".abort] in cas abort method");
        return super.abort();
    }

    /**
     * initialize
     * The WebCT Vista SDK SSO initialize method
     * The initialize method is called when the AuthenticationModule is instantiated.
     * It can be implemented to provide custom initialization logic specific to this
     * AuthenticationModule, but it is not required.
     * @see javax.security.auth.spi.LoginModule#initialize(javax.security.auth.Subject, javax.security.auth.callback.CallbackHandler, java.util.Map, java.util.Map)
     */
    public void initialize(
        javax.security.auth.Subject subject,
        javax.security.auth.callback.CallbackHandler callbackHandler,
        Map sharedState,
        Map options) {
            // NOTE:
            // (1) you must call super.initialize() before your implementation code.
            //     This ensures that the module is initialized with the Subject and
            //     the module's settings.;
            // (2) No other methods of AuthenticationModule should be called in this initialize method.
        super.initialize(subject, callbackHandler, sharedState, options);
            // custom implementation below
        logger.debug("[" + classname + ".initialize] in cas initialize method");
    }

    /**
     * login
     * The WebCT Vista SDK SSO login method
     * @return boolean
     * @throws LoginException
     */
    public boolean login() throws LoginException {

        logger.debug("[" + classname + ".login] in cas login method");

        WebCTSSOContext ssoContext = this.getWebCTSSOContext();
        Map settings = ssoContext.getSettings();
        HttpServletRequest request = ssoContext.getRequest();

        StringBuffer auditmessage = new StringBuffer();
        auditmessage.append(request.getRemoteAddr());
        auditmessage.append(" [" + new Date().toString() + "]");

        String queryString = request.getQueryString();
        logger.debug("[login] querystring is "+queryString);

        String errorURL         = (String) settings.get("errorurl");
        String casValURL        = (String) settings.get("casvalidationurl");
        String casSslTrustAll   = (String) settings.get("casssltrustall");
        String casValVer        = (String) settings.get("casvalidationversion");
        String service          = (String) settings.get("serviceurl");
        String lcid             = request.getParameter("lcid");
        String ticket           = request.getParameter("ticket");

        logger.debug("[login] errorurl is "+errorURL);
        logger.debug("[login] casvalidationurl is "+casValURL);
        logger.debug("[login] casssltrustall is "+casSslTrustAll);
        logger.debug("[login] casvalidationversion is "+casValVer);
        logger.debug("[login] service is "+service);
        logger.debug("[login] lcid is "+lcid);
        logger.debug("[login] ticket is "+ticket);

        boolean casSslTrustAllBoolean = false;
        if (casSslTrustAll.equals("true")) {
            casSslTrustAllBoolean = true;
        }
        this.setRedirectUrlOnError(errorURL);

        if (ticket == null) {
            auditmessage.append(" ticket=\"null\"");
            auditmessage.append(" auth=\"failure\"");
            auditmessage.append(" userid=\"null\"");
            logger.debug("[login] The user-provided CAS ticket is null. The authentication process failed.");
            throw new LoginException("The user's CAS validation ticket is null. The authentication process failed.");
        } else {
            auditmessage.append(" ticket=\"" + ticket + "\"");
        }

        boolean authenticated = false;

        try {

            // CAS 1.0 or 2.0 verification. Defaults to 2.0
            int casVer = 2;
            if (casValVer.equals("cas1")) {
                casVer = 1;
            }

            Date casauthDate1 = new Date();
            if (casauth(casValURL,casSslTrustAllBoolean,casVer,service,lcid,ticket)) {
                Date casauthDate2 = new Date();
                auditmessage.append(" auth=\"success\"");
                auditmessage.append(" userid=\"" + getCasUserId() + "\"");
                auditmessage.append(" timems=\"" + (casauthDate2.getTime() - casauthDate1.getTime()) + "\"");
                logger.debug("[login] found user is "+getCasUserId());
                authenticated = true;
            } else {
                Date casauthDate2 = new Date();
                auditmessage.append(" auth=\"failure\"");
                auditmessage.append(" userid=\"null\"");
                auditmessage.append(" timems=\"" + (casauthDate2.getTime() - casauthDate1.getTime()) + "\"");
                // LoginException should have been thrown already
                logger.debug("[login] authentication failed");
                throw new LoginException("Authentication Failed");
            }
            
        } catch (MalformedURLException e) {
            auditmessage.append(" error=\"bad URL with validation\"");
            logger.error("bad URL with validation ",e);
        } catch (IOException e) {
            auditmessage.append(" error=\"error talking to validation server\"");
            logger.error("error talking to validation server",e);
        } catch (LoginException e) {
            auditmessage.append(" error=\"" + e.toString() + "\"");
            logger.error("error validating CAS ticket",e);
        }
        // Login failures should have already been returned with thrown LoginException
        // Using the 'authenticated' flag a failsafe measure to ensure against errors
        //   that cause either MalformedURLException or IOException to be thrown.
        // Vista SDK API says returning "false" is reserved for special meaning
        auditlog.info( auditmessage.toString() );
        if (!authenticated) {
            logger.debug("[login] The authentication process failed.");
            throw new LoginException("The authentication process failed.");
        }

        // go to commit()
        return true;
    }

    /**
     * commit
     * The WebCT Vista SDK SSO commit method
     * @return boolean
     * @throws LoginException
     */
    public boolean commit() throws LoginException {

        logger.debug("[" + classname + ".commit] in cas commit method");

        String userid = getCasUserId();
        logger.debug("[commit] userid is " + userid );

        if (userid != null){
            this.setUserId(userid);

            WebCTSSOContext ssoContext = this.getWebCTSSOContext();
            HttpServletRequest request = ssoContext.getRequest();
            String redirectURL = ssoContext.getRedirectUrl(MYWEBCT_TOKEN, 0);
            String lcid = request.getParameter("lcid");

            logger.debug("[commit] lcid is "+lcid);
            if (lcid != null) {
                redirectURL = ssoContext.getRedirectUrl(COURSE_HOMEPAGE_TOKEN, Long.parseLong(lcid));
            }

            logger.debug("[commit] Redirect URL is "+redirectURL);
            setRedirectUrl(redirectURL);
        }
        else {
            logger.debug("[commit] Authentication failed, WebCT userid is not available.");
            throw new LoginException("Authentication failed, WebCT userid is not available.");
        }

        // allow user to login
        return true;
    }

    /**
     * logout
     * The WebCT Vista SDK SSO logout method
     * The logout method is called when the Subject logs out of the application.
     * It can be implemented to perform any necessary cleanup operations.
     * This method must return true.
     * @see javax.security.auth.spi.LoginModule#logout()
     */
    public boolean logout() throws LoginException {
        logger.debug("[" + classname + ".logout] in cas logout method");
        return super.logout();
    }

    /**
     * casauth
     * Validate a CAS ticket against a CAS 2.0 Server
     * @param casValUrl The URL to the CAS Server to validate Tickets 
     * @param vasValVer The CAS Version to validate by, e.g. 1 = 1.0, 2 = 2.0
     * @param service The WebCT Service URL to return the ticket to
     * @param lcid (optional) The WebCT section 
     * @param ticket The CAS Server Authentication Ticket to validate
     * @return boolean true if valid, false otherwise
     * @throws MalformedURLException
     * @throws IOException
     * @throws LoginException
     */
    private boolean casauth (String casValUrl, int casValVer, String service, String ticket)
        throws MalformedURLException, IOException, LoginException
    {
        return casauth(casValUrl,false,casValVer,service,null,ticket);
    }

    private boolean casauth (String casValUrl, boolean casSslTrustAll, int casValVer, String service, String lcid, String ticket)
        throws MalformedURLException, IOException, LoginException
    {
        logger.debug("[" + classname + ".casauth] in cas casauth method");

        // Create the Service URL
        // The Service URL needs to be URL Encoded, which the AuthService module take care of for us
        // The base Service URL is user-provided through this module's configuration
        // The Lcid is provided via the httpRequest object
        String serviceUrl = service;
        if (lcid != null) {
            String[] uf = { service, ("lcid="+lcid) };
            serviceUrl = this.urlConstructor(uf);
        }

        weblogicHttpsUrlRequest whuc = new weblogicHttpsUrlRequest();
        whuc.setTrustAllCerts( casSslTrustAll );
        AuthService   casauth   = new AuthService(new URL(casValUrl), casValVer, whuc);
        ServiceTicket casticket = new ServiceTicket(ticket, new URL(serviceUrl), casValVer);

        logger.debug("[casauth] CAS Server Validate url is: "      + casauth.getValidationUrl() );
        logger.debug("[casauth] CAS Server Service parameter is: " + casticket.getServiceUrl() );
        logger.debug("[casauth] CAS Server Ticket parameter is: "  + casticket.getId() );

        try {
            casauth.validateTicket(casticket);
        } catch (GeneralSecurityException e) {
            logger.debug("[casauth] CAS Auth server SSL error, throwing LoginException",e);
            logger.error("Received SSL error from CAS Auth server.");
            throw new LoginException("CAS Auth server SSL error");
        } catch (IOException e) {
            logger.debug("[casauth] Error connecting to CAS Auth server, throwing LoginException",e);
            logger.error("Error connecting to CAS Auth server");
            throw new LoginException("Error connecting to CAS Auth server");
        } catch (ParseException e) {
            logger.debug("[casauth] CAS Auth Unknown Response, throwing LoginException",e);
            logger.error("Unknown response from CAS server: "+casticket.getValidationResponse() );
            throw new LoginException("Unknown CAS server response.");
        }

        logger.debug("[casauth] CAS Server Validate results:\n" + casticket.getValidationResponse() );

        if ( casticket.isAuthSuccess() ) {
            logger.debug( "[casauth] CAS user ticket=" + casticket.getId() );
            logger.debug( "[casauth] Parsed CAS UserId/WebctID is: " + casticket.getAuthUser() );
            setCasUserId( casticket.getAuthUser() );
            return true;
        } else {
            logger.debug("[casauth] CAS error code: " + casticket.getAuthCode() );
            logger.debug("[casauth] CAS error message: " + casticket.getAuthMessage() );
            logger.debug("[casauth] CAS user ticket: " + casticket.getId() );
            logger.debug("[casauth] CAS Auth Failed, throwing LoginException.");
            logger.error("User's CAS session is not valid. CAS code="+ casticket.getAuthCode() +", CAS message="+ casticket.getAuthMessage() +", CAS ticket="+ casticket.getId());
            throw new LoginException("User's CAS session is not valid.");
        }
    }

    /**
     * urlConstructor
     *
     * <p>
     * Use this function to assemble a URL with a set of elements that are the
     * base url, and various query paramaters and values. This method takes
     * care of putting them all together into one URL, make sure that there is
     * only 1 ?, and a & exists between each paramater set.
     * </p>
     * <p>
     * Note: This method does not encode URL query paramaters. All characters
     * being passed in as query paramaters should be propery encoded first.
     * </p>
     * Examples:
     * <code><pre>
     *   String raw_url = "http://www.domain.com/query.cgi?abc=1"
     *   String[] urlfragments = { raw_url, "t1=v1", "t2=v2" };
     *   String url = urlConstructor( urlfragments );
     *   // url == "http://www.domain.com/query.cgi?abc=1&t1=v1&t2=v2"
     *
     *   String raw_url = "http://www.domain.com/query.cgi"
     *   String[] urlfragments = { raw_url, "t1=v1", "t2=v2" };
     *   String url = urlConstructor( urlfragments );
     *   // url == "http://www.domain.com/query.cgi?t1=v1&t2=v2"
     * </pre></code>
     * @return String of the assembled URL
     */
    private static String urlConstructor(String[] fragments) {
        StringBuffer url = new StringBuffer(fragments[0]);
        String p_onend = ".*\\?$"; 
        String p_inside = ".*\\?.+$";
        boolean f_onend = false;
        boolean f_inside = false;
        
        for (int i = 1; i < fragments.length; i++) {
            if ((! f_inside) && (! f_onend)) {
                if (Pattern.matches(p_inside, url)) {
                    f_inside = true;
                } else if (Pattern.matches(p_onend, url)) {
                    f_onend = true;
                } else {
                    url.append("?");
                    f_onend = true;
                }
            }
            if (! f_onend) {
                url.append("&");
            }
            url.append(fragments[i]);
            f_onend = false;
            f_inside = true;
        }
        return url.toString();
    }
}

