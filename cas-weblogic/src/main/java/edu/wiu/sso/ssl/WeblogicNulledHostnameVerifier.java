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

/**
 * <p>
 * HostnameVerifier provides a callback mechanism so that implementers
 * of this interface can supply a policy for handling the case where
 * the host that's being connected to and the server name from the
 * certificate SubjectDN must match.
 * </p>
 * <p>
 * For Example. If the client code connects to a server at 'localhost' but the
 * certificate's SubjectDN CommonName is 'bea.com', the default
 * weblogic.security.SSL.HostnameVerifier does a String.equals() on those two
 * hostnames and returns false because they do not match.
 * </p>
 * <p>
 * This is a null version of that class in that it always returns true, never
 * attempting to compare the server hostname and certificate SubjectDN..
 * </p>
 *
 * @author Copyright (c) 2010-2011 by Western Illinois University, CAIT. All Rights Reserved.
 * @see weblogic.security.SSL.HostnameVerifier
 * @see javax.net.ssl.HostnameVerifier
 * @see <br><span>Refer to: <a href="http://download-llnw.oracle.com/docs/cd/E11035_01/wls100/pdf/security.pdf">http://download-llnw.oracle.com/docs/cd/E11035_01/wls100/pdf/security.pdf</a></span>
 */

public class WeblogicNulledHostnameVerifier implements weblogic.security.SSL.HostnameVerifier
{
    /**
     * This is a nulled method (does not do anything) that just returns true, regardless.
     * @see                 weblogic.security.SSL.HostnameVerifier#verify
     * @param urlHostname   The server hostname
     * @param session       The SSL session used for the connection to urlHostname
     * @return              Always returns true
     */
    public boolean verify(final String urlHostname, final javax.net.ssl.SSLSession session)
    {
        return true;
    }
}

