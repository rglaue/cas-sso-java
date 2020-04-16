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

package edu.wiu.sso;

import java.io.*;
import java.lang.*;
import java.net.URL;
import weblogic.net.http.HttpsURLConnection;
import weblogic.security.SSL.TrustManager;
import edu.wiu.sso.ssl.WeblogicNulledHostnameVerifier;
import edu.wiu.sso.ssl.WeblogicNulledTrustManager;
//import javax.net.ssl.TrustManager;

import java.io.IOException;
import java.net.MalformedURLException;
import java.security.GeneralSecurityException;

/**
 * <p>
 * Retrieve remote content via HTTP or HTTPS, using WebLogic libraries.
 * Specifically, this class implements the WebLogic Null Trust Manager.
 * </p>
 *
 * @author Copyright (c) 2010-2011 by Western Illinois University, CAIT. All Rights Reserved.
 * @see edu.wiu.sso.httpsUrlRequest
 */
public class weblogicHttpsUrlRequest extends httpsUrlRequest {

    // The weblogic.security.SSL.TrustManager
    private TrustManager trustManager = null;

    /**
     * Set the TrustManager
     *
     * @param tm weblogic.security.SSL.TrustManager object of the URL to request from
     */
    public void setTrustManager(weblogic.security.SSL.TrustManager tm) {
        this.trustManager = tm;
    }

    /**
     * Get the TrustManager
     *
     * @return weblogic.security.SSL.TrustManager object of the URL to request from
     */
    public javax.net.ssl.TrustManager getTrustManager() {
        return (javax.net.ssl.TrustManager) this.trustManager;
    }

    /**
     * Perform an HTTPS request and return the results.
     *
     * If running inside BEA WebLogic, BEA's libraries intrude
     * on the Connection Context Process, thus we
     * must adhear to its practices.
     *
     * @param url a URL to retrieve HTTPS results from
     * @param trustallcerts set to true to not verify the trust of SSL Certificates
     * @return String The results of the HTTPS request
     * @throws GeneralSecurityException if an error occurs configuring the Null Trust Manager in the SSL context
     * @throws MalformedURLException
     * @throws IOException if connecting to the URL fails
     */
    public String urlRequest (URL url, boolean trustallcerts)
        throws GeneralSecurityException, MalformedURLException, IOException
    {
        URL SSL_URL = url;
        String trustall_init = "false";

        if (((trustallcerts) || (this.trustManager != null)) && (SSL_URL.getProtocol().equals("https"))) {
            trustall_init = "true";
            /*
             *  Create a Null Trust Manager within WebLogic's realm of operation
             */
            try {
                final java.util.Properties p = System.getProperties();
                String s = p.getProperty("java.protocol.handler.pkgs");
    
                if (s == null) { 
                    s = "weblogic.net";
                }
                else if (s.indexOf("weblogic.net") == -1) {
                    s = "|weblogic.net";
                }
    
                p.put("java.protocol.handler.pkgs", s);
                System.setProperties(p);

                HttpsURLConnection huc = new weblogic.net.http.HttpsURLConnection(SSL_URL);
                if (this.trustManager != null) {
                    huc.setTrustManager(this.trustManager);
                } else {
                    WeblogicNulledHostnameVerifier hVerifier = new WeblogicNulledHostnameVerifier();
                    huc.setHostnameVerifier(hVerifier);
                    WeblogicNulledTrustManager trustAllCerts = new WeblogicNulledTrustManager();
                    huc.setTrustManager(trustAllCerts);
                }
                huc.connect();
            } catch (Exception e) {
                throw new GeneralSecurityException("weblogicHttpsUrlRequest: Error in configuring the Weblogic Null Trust Manager in the SSL Context", e);
            }
        }
        trustall_init = (trustall_init + ":" + SSL_URL.getProtocol());
        /*
         *  Get the content from the URL
         */
        BufferedReader r = null;
        StringBuffer buf = new StringBuffer();

        try {
            r = new BufferedReader(new InputStreamReader(SSL_URL.openStream()));

            // Read from the BufferedReader into the StringBuffer
            String line;
            while ((line = r.readLine()) != null) {
                buf.append(line).append("\n");
            }
        } catch (IOException ex) {
            String trustall = "false";
            if (trustallcerts) { trustall = "true"; }
            throw new IOException (("weblogicHttpsUrlRequest: Error connecting to URL (trustallcerts="+trustall+";init="+trustall_init+") "+SSL_URL.toString() +": " + ex.toString()));
        } finally {
            try {
                if (r != null) r.close();
            } catch (IOException ex) {
                // this should not cause the request to fail, so ignore it
            }
        }
        return buf.toString();
    }

}

