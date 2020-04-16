/**
 *
 *   WIU's CAS Simple Client Library
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
 */

package edu.wiu.sso.cas;

import java.io.*;
import java.lang.*;
import java.net.URL;
import java.util.Date;
import java.net.URLEncoder;
import java.util.regex.*;
import edu.wiu.sso.httpsUrlRequest;
import edu.wiu.sso.cas.ServiceTicket;

import java.net.MalformedURLException;
import java.security.GeneralSecurityException;
import java.text.ParseException;

/**
 * <p>A module to handle CAS (Central Authentication Service)
 * (http://www.jasig.org/cas) ticket validation. Within a few lines of code,
 * an application can easily validate a user's CAS ticket, retrieve the
 * validation results and any error codes and error messages.</p>
 *
 * <p>
 * Example code to illustrate use:
 * <code><pre>
 *  try {
 *      // CAS 1.0 or 2.0 verification. Defaults to 2.0
 *      int casAuthVersion = 2;
 *      URL casAuthValidation = "https://auth.yourdomain.com/cas-webapp/serviceValidate";
 *      URL myAppServiceUrl = "http://yourdomain.com/yourwebapp/casBridgeAndStartPage";
 *      String casTicketId = "ST-26-3khTvbVucs3FDdC34Krc-auth";
 *  } catch (MalformedURLException e) {
 *      System.err.println("[ERROR] Bad URL with validation ",e);
 *  }
 *  // The HTTPS URL Request object does the work to talk to the CAS Server
 *  weblogicHttpsUrlRequest whuc = new weblogicHttpsUrlRequest();
 *  AuthService   casauth   = new AuthService(  casAuthValidation,
 *                                              casAuthVersion,
 *                                              whuc);
 *  ServiceTicket casticket = new ServiceTicket(casTicketId,
 *                                              myAppServiceUrl,
 *                                              casAuthVersion);
 *  try {
 *      casauth.validateTicket(casticket);
 *  } catch (GeneralSecurityException e) {
 *      System.err.println("Received SSL error from CAS auth validation server.");
 *  } catch (IOException e) {
 *      System.err.println("Error talking to CAS auth validation server ");
 *  } catch (ParseException e) {
 *      System.err.println("Unknown response from CAS server: "+casticket.getValidationResponse() );
 *  }
 *  if ( casticket.isAuthSuccess() ) {
 *      System.out.println( "CAS ticket validation success!"
 *                          + " The user's NetId is:" + casticket.getAuthUser() );
 *  } else {
 *      System.err.println( "The user's CAS ticket is not valid."
 *                          + " ticket=" + casticket.getId()
 *                          + ", CAS code=" + casticket.getAuthCode()
 *                          + ", CAS message=" + casticket.getAuthMessage()  );
 *  }
 * </pre></code>
 * Alternate code example:
 * <code><pre>
 *  AuthService casauth;
 *  ServiceTicket casticket;
 *  try {
 *      // Setup validation information
 *      int    casAuthVersion    = 2;
 *      URL    casAuthValidation = "https://auth.yourdomain.com/cas-webapp/serviceValidate";
 *      URL    myAppServiceUrl   = "http://yourdomain.com/yourwebapp/casBridgeAndStartPage";
 *      String casTicketId       = "ST-26-3khTvbVucs3FDdC34Krc-auth";
 *      // Initialize the CAS Auth objects
 *      casauth     = new AuthService(  casAuthValidation,
 *                                      casAuthVersion,
 *                                      new weblogicHttpsUrlRequest() );
 *      casticket   = new ServiceTicket(casTicketId,
 *                                      myAppServiceUrl,
 *                                      casAuthVersion);
 *      // Validate the user's CAS ticket
 *      casauth.validateTicket(
 *          new ServiceTicket(  casTicketId,
 *                              myAppServiceUrl,
 *                              casAuthVersion)
 *      );
 *      // Determine is the ticket was validated successfully
 *      if ( casticket.isAuthSuccess() ) {
 *          System.out.println( "CAS ticket validation success!"
 *                              + " The user's NetId is:" + casticket.getAuthUser() );
 *      } else {
 *          System.err.println( "The user's CAS ticket is not valid."
 *                              + " ticket=" + casticket.getId()
 *                              + ", CAS code=" + casticket.getAuthCode()
 *                              + ", CAS message=" + casticket.getAuthMessage()  );
 *      }
 *  } catch (Exception e) {
 *      System.err.println("[ERROR] Error validating the user's CAS ticket.");
 *      System.err.println("[ERROR] " + e.getMessage() );
 *      e.printStackTrace(System.err);
 *  } 
 * </pre></code>
 * </p>
 *
 * @author Copyright (c) 2010-2011 by Western Illinois University, CAIT. All Rights Reserved.
 * @see edu.wiu.sso.cas.ServiceTicket
 */
public class AuthService {

    private URL validationUrl = null;   // URL for CAS Auth Validation Service
    private int validationVersion = 2;  // CAS 2.0
    private httpsUrlRequest hur = null;

    /**
     * @param validationUrl The CAS server validation service URL
     * @param validationVersion The version of the CAS server validation method
     */
     public AuthService(URL validationUrl,
                        int validationVersion) {
        new AuthService( validationUrl,
                         validationVersion,
                         false
                         );
     }

    /**
     * @param validationUrl The CAS server validation service URL
     * @param validationVersion The version of the CAS server validation method
     * @param ssltrust Set to true to not require Trusted SSL Certs, AuthService defaults to requiring trusted SSL Certs
     */
     public AuthService(URL validationUrl,
                        int validationVersion,
                        boolean ssltrust) {
        httpsUrlRequest hur_t = new httpsUrlRequest();
        hur_t.setTrustAllCerts(ssltrust);
        new AuthService( validationUrl,
                         validationVersion,
                         hur_t
                         );
     }

    /**
     * @param validationUrl The CAS server validation service URL
     * @param validationVersion The version of the CAS server validation method
     * @param hur Set the httpsUrlRequest object to be used
     */
     public AuthService(URL validationUrl,
                        int validationVersion,
                        httpsUrlRequest hur) {
        this.setValidationUrl(validationUrl);
        this.setValidationVersion(validationVersion);
        this.setHttpsUrlRequest(hur);
     }

    /**
     * Set the CAS Server Validation URL. This is the URL that will be used to
     * validate the Service Ticket.
     * The validation url is set by the constructor.
     *
     * @param url java.net.URL object of the URL to request from
     */
    private void setValidationUrl(URL validationUrl) {
        this.validationUrl = validationUrl;
    }

    /**
     * Get the CAS Server Validation URL. This is the URL that will be used to
     * validate the Service Ticket.
     * The validation url is set by the constructor.
     *
     * @return java.net.URL object of the URL to request from
     */
    public URL getValidationUrl() {
        return this.validationUrl;
    }

    /**
     * <p>
     * Set the CAS Server protocol version. This is the protocol version that
     * will be used to validate the Service Ticket.
     * The validation version is set by the constructor.
     * </p>
     * There are only two possible values:
     * <ul>
     *  <li> <code>1</code> - CAS protocol version 1.0
     *  <li> <code>2</code> - CAS protocol version 2.0
     * </ul>
     *
     * @param validationVersion The CAS Server protocol version for validation
     */
    private void setValidationVersion(int validationVersion) {
        this.validationVersion = validationVersion;
    }

    /**
     * <p>
     * Get the CAS Server protocol version. This is the protocol version that
     * will be used to validate the Service Ticket.
     * The validation version is set by the constructor.
     * </p>
     * There are only two possible values:
     * <ul>
     *  <li> <code>1</code> - CAS protocol version 1.0
     *  <li> <code>2</code> - CAS protocol version 2.0
     * </ul>
     *
     * @return validationVersion The CAS Server protocol version for validation
     */
    public int getValidationVersion() {
        return this.validationVersion;
    }

    /**
     * Set the HttpsUrlRequest object to be used for connecting to the CAS
     * Server in the {@link #validateTicket validateTicket} method.
     *
     * @param hur The httpsUrlRequest object to be used
     */
    public void setHttpsUrlRequest(httpsUrlRequest hur) {
        this.hur = hur;
    }

    /**
     * Get the HttpsUrlRequest object set to be used for connecting to the CAS
     * Server in the {@link #validateTicket validateTicket} method.
     *
     * @return The httpsUrlRequest object to be used
     */
    public httpsUrlRequest getHttpsUrlRequest() {
        return this.hur;
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

    /**
     * Validate a Service Ticket with the CAS Server
     *
     * @param st The ticket to validate
     */
    public void validateTicket(ServiceTicket st)
        throws MalformedURLException, IOException, GeneralSecurityException, ParseException
    {
        httpsUrlRequest huc = this.getHttpsUrlRequest();
        String[] uf = { this.getValidationUrl().toString(),
                        ("ticket=" + st.getId()),
                        ("service=" + URLEncoder.encode(st.getServiceUrl().toString()))
        };
        java.net.URL authUrl = new URL( this.urlConstructor(uf) );
        st.setRequestTime( new Date() );
        String rmsg = huc.urlRequest(authUrl);
        st.setResponseTime( new Date() );
        st.setValidationResponse(rmsg); // gets parsed when set
    }

}

