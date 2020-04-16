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

package edu.wiu.sso.ssl;

import javax.net.ssl.X509TrustManager;
import javax.net.ssl.TrustManager;
import java.security.cert.X509Certificate;

/**
 * <p>
 *  Null Trust Manager class
 * </p>
 * <p>
 *  Create a trust manager that does not validate certificate chains like the
 *  default TrustManager. This routine is what Netscape and IE do when they
 *  receive a certificate that is not in their KeyStore. The only difference is
 *  that this code does not ask you to accept it.
 * </p>
 * <p>
 *  There are two ways to implement a trustless or null TrustManager
 * </p>
 * <p>
 * <ol>
 *  <li> The Classless implementation - does not require this additional class:
 *  
 *  <code><pre>TrustManager[] trustAllCerts = new TrustManager[]
 *  {
 *      new X509TrustManager()
 *      {
 *          public java.security.cert.X509Certificate[] getAcceptedIssuers()
 *          {
 *              return null;
 *          }
 *  
 *          public void checkClientTrusted(java.security.cert.X509Certificate[] certs, String authType) { }
 *  
 *          public void checkServerTrusted(java.security.cert.X509Certificate[] certs, String authType) { }
 *      }
 *  };</pre></code>
 *  
 *  <li> The Classed implementation - requires this (NulledTrustManager) class:
 *  
 *  <code><pre>TrustManager[] trustAllCerts = new javax.net.ssl.TrustManager[] { new NulledTrustManager() };</pre></code>
 * </ol>
 * </p>
 *
 * This class implement the javax.net.ssl.X509TrustManager class which also
 * implements javax.net.ssl.TrustManager
 *
 * @author Copyright (c) 2010-2011 by Western Illinois University, CAIT. All Rights Reserved.
 * @see javax.net.ssl.X509TrustManager
 * @see javax.net.ssl.TrustManager
 */

public final class NulledTrustManager implements javax.net.ssl.X509TrustManager, javax.net.ssl.TrustManager
{
    public NulledTrustManager () { }

    /**
     * This is a nulled method (does not do anything) that just returns null, regardless.
     * @return  null
     */
    public java.security.cert.X509Certificate[] getAcceptedIssuers()
    {
        return null;
    }

    public void checkClientTrusted(java.security.cert.X509Certificate[] certs, String authType) { }

    public void checkServerTrusted(java.security.cert.X509Certificate[] certs, String authType) { }
}

