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
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import edu.wiu.sso.ssl.NulledHostnameVerifier;
import edu.wiu.sso.ssl.NulledTrustManager;

import java.io.IOException;
import java.net.MalformedURLException;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.KeyManagementException;

/**
 * <p>Retrieve remote content via HTTP or HTTPS</p>
 *
 * @author Copyright (c) 2010-2011 by Western Illinois University, CAIT. All Rights Reserved.
 */
public class httpsUrlRequest {

    // The java.net.URL
    private java.net.URL url = null;
    // The javax.net.ssl.TrustManager
    private TrustManager trustManager = null;
    // Do we trust all SSL certificates?
    private boolean TrustAllCerts = false;

    /**
     *
     */
    public httpsUrlRequest() {
    }
    /**
     * @param url    The URL to which a request will be made of
     * @throws MalformedURLException
     */
    public httpsUrlRequest(String url) throws MalformedURLException {
        this.setURL( new URL(url) );
    }
    /**
     * @param url    The URL to which a request will be made of
     */
    public httpsUrlRequest(URL url) {
        this.setURL( url );
    }

    /**
     * Set the URL to be used in other methods of this object.
     *
     * @param url     java.net.URL object of the URL to request from
     */
    public void setURL(URL url) {
        this.url = url;
    }

    /**
     * Set the URL that is set to be used in other methods of this object.
     *
     * @return    java.net.URL object of the URL to request from
     */
    public URL getURL() {
        return this.url;
    }

    /**
     * Set this object to trust all Certificate Authorties when connecting via
     * the https protocol. Setting to true causes this object to use a Nulled
     * Trust Manager. Default is false, and uses a normal Trust Manager.
     *
     * @param trust    set to true to trust all ssl certs, default is false
     */
    public void setTrustAllCerts(boolean trust) {
        this.TrustAllCerts = trust;
    }

    /**
     * Get the setting of this object using a Nulled Trust Manager. Will be
     * true if the object is set to use a Nulled Trust Manager.
     *
     * @return     true if object is set to trust all ssl certs, default is false
     */
    public boolean getTrustAllCerts() {
        return this.TrustAllCerts;
    }

    /**
     * If the URL is set, and the protocol is https, this method returns true.
     * Otherwise this method returns false. If the URL has not been set yet,
     * via setURL, then this method returns false.
     * Simply, this method returns true only if getURL().getProtocol.equals("https")
     *
     * @return true if the HTTP connection will use SSL
     */
    public boolean isSSL() {
        if (this.url != null) {
            if (this.url.getProtocol().equals("https")) {
                return true;
            }
        }
        return false;
    }

    /**
     * Set the TrustManager. Setting the Trust Manager will override the object
     * creating its own Trust Manager. If the object has been set true for
     * {@link #setTrustAllCerts}, and the Trust Manager has been set with this
     * method. This object will use this Trust Manager, and not create its own
     * Nulled Trust Manager.
     *
     * @param tm javax.net.ssl.TrustManager object of the URL to request from
     */
    public void setTrustManager(javax.net.ssl.TrustManager tm) {
        this.trustManager = tm;
    }

    /**
     * Get the TrustManager
     *
     * @return javax.net.ssl.TrustManager object of the URL to request from
     */
    public javax.net.ssl.TrustManager getTrustManager() {
        return this.trustManager;
    }

    /**
     * Perform an HTTP request and return the results
     *
     * @param httpUrl a String representing a URL to retrieve HTTP results from
     * @return String The results of the HTTPS request
     * @throws GeneralSecurityException if an error occurs configuring the Null Trust Manager in the SSL context
     * @throws MalformedURLException
     * @throws IOException if connecting to the URL fails
     */
    public String urlRequest (String httpUrl)
        throws GeneralSecurityException, MalformedURLException, IOException
    {
        URL url = new URL(httpUrl);
        return urlRequest(url, this.getTrustAllCerts());
    }
    /**
     * Perform an HTTP request and return the results
     *
     * @param httpUrl a String representing a URL to retrieve HTTP results from
     * @param trustallcerts set to true to not verify the trust of SSL Certificates
     * @return String The results of the HTTPS request
     * @throws GeneralSecurityException if an error occurs configuring the Null Trust Manager in the SSL context
     * @throws MalformedURLException
     * @throws IOException if connecting to the URL fails
     */
    public String urlRequest (String httpUrl, boolean trustallcerts)
        throws GeneralSecurityException, MalformedURLException, IOException
    {
        URL url = new URL(httpUrl);
        return urlRequest(url, trustallcerts);
    }
    /**
     * Perform an HTTP request and return the results
     *
     * @param url a URL to retrieve HTTPS results from
     * @return String The results of the HTTPS request
     * @throws GeneralSecurityException if an error occurs configuring the Null Trust Manager in the SSL context
     * @throws MalformedURLException
     * @throws IOException if connecting to the URL fails
     */
    public String urlRequest(URL url)
        throws GeneralSecurityException, IOException
    {
        return urlRequest(url, this.getTrustAllCerts());
    }
    /**
     * Perform an HTTP request and return the results
     *
     * @param url a URL to retrieve HTTPS results from
     * @param trustallcerts set to true to not verify the trust of SSL Certificates
     * @return String The results of the HTTPS request
     * @throws GeneralSecurityException if an error occurs configuring the Null Trust Manager in the SSL context
     * @throws MalformedURLException
     * @throws IOException if connecting to the URL fails
     */
    public String urlRequest(URL url, boolean trustallcerts)
        throws GeneralSecurityException, IOException
    {
        URL SSL_URL = url;
        String trustall_init = "false";

        if (((trustallcerts) || (this.trustManager != null)) && (SSL_URL.getProtocol().equals("https"))) {
            trustall_init = "true";
            /*
             *  Create and initialize the default SSLContext
             */
            try {
                SSLContext sc = SSLContext.getInstance("SSL");
                if (this.trustManager != null) {
                    TrustManager[] tm =  new javax.net.ssl.TrustManager[] { this.trustManager };
                    sc.init(null, tm, new java.security.SecureRandom());
                } else {
                    TrustManager[] trustAllCerts = new javax.net.ssl.TrustManager[] { new NulledTrustManager() };
                    sc.init(null, trustAllCerts, new java.security.SecureRandom());
                    NulledHostnameVerifier hVerifier = new NulledHostnameVerifier();
                    HttpsURLConnection.setDefaultHostnameVerifier(hVerifier);
                }
                // SSLContext.setDefault(sc); // setDefault() is only in Java 1.6
                HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
            } catch (NoSuchAlgorithmException e) {
                throw new GeneralSecurityException("httpsUrlRequest: NoSuchAlgorithmException Error in configuring the Null Trust Manager in the SSL Context", e);
            } catch (KeyManagementException e) {
                throw new GeneralSecurityException("httpsUrlRequest: KeyManagementException Error in configuring the Null Trust Manager in the SSL Context", e);
            }
        }
        trustall_init = (trustall_init + ":" + SSL_URL.getProtocol());
        /*
         *  Get the content from the URL via java.net.URL
         */
        BufferedReader r = null;
        StringBuffer buf = new StringBuffer();

        try {
            /** Another Way to get the InputStreamReader
             * URLConnection uc = SSL_URL.openConnection();
             * uc.setRequestProperty("Connection", "close");
             * r = new BufferedReader(new InputStreamReader(uc.getInputStream()));
             */
            r = new BufferedReader(new InputStreamReader(SSL_URL.openStream()));

            // Read from the BufferedReader into the StringBuffer
            String line;
            while ((line = r.readLine()) != null) {
                buf.append(line).append("\n");
            }
        } catch (IOException ex) {
            String trustall = "false";
            if (trustallcerts) { trustall = "true"; }
            throw new IOException (("httpsUrlRequest: Error connecting to URL (trustallcerts="+trustall+";init="+trustall_init+") "+SSL_URL.toString() + ": " + ex.toString()));
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

