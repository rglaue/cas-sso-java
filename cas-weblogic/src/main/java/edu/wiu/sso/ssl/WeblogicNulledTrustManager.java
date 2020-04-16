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

import weblogic.security.SSL.TrustManager;
import java.security.cert.X509Certificate;

/**
 * Null Trust Manager class, implemented the Weblogic way
 *
 * @author Copyright (c) 2010-2011 by Western Illinois University, CAIT. All Rights Reserved.
 * @see weblogic.security.SSL.TrustManager
 */

public class WeblogicNulledTrustManager implements weblogic.security.SSL.TrustManager
{
    /**
     * This is a nulled method (does not do anything) that just returns true, regardless.
     * @return  Always returns true
     * @see weblogic.security.SSL.TrustManager#certificateCallback
     */
    public boolean certificateCallback(final java.security.cert.X509Certificate[] o, final int validateErr)
    {
        /* Uncomment this to print the certificate to Standard Out
        for (int i = 0; i < o.length; i++)
            { System.out.println(" certificate " + i + " -- " + o[i].toString()); }
        */
        return true;
    }
}

