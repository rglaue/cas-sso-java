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
import edu.wiu.sso.*;

import java.net.MalformedURLException;
import java.text.ParseException;

/**
 * <p>This object represents a CAS Ticket. And at this time it only supports
 * CAS Authentication messages in 1.0 and 2.0 formats.</p>
 *
 * <p>At this time, this module can only parse CAS ticket validation responses
 * to obtain the following informations:
 * <ol>
 * <li> The successfulness or unsuccessfulness of validating the CAS ticket.
 * <li> If successful, the NetId (a.k.a the username) authenticated to the CAS
 *      Server, which is associated with the CAS ticket.
 * <li> If unsuccessful, the error code associated with the reason why the CAS
 *      ticket was not successfully validated
 * <li> If unsuccessful, the error message associated with the reason why the
 *      CAS ticket was not successfully validated
 * </ol>
 * </p>
 *
 * @author Copyright (c) 2010-2011 by Western Illinois University, CAIT. All Rights Reserved.
 * @see edu.wiu.sso.cas.AuthService
 */
public class ServiceTicket {

    private String id = null;
    private URL serviceUrl = null;
    private int validationVersion = 2;  // 2 = 2.0, 1 = 1.0, 3 = 3.0, etc..
    private String validationResponse = null;
    private String authCode = null;
    private String authMessage = null;
    private String authUser = null;
    private boolean isAuthSuccess = false;
    private Date requestTime = null;
    private Date responseTime = null;

    /**
     * 
     * @param ticketId The Id string of this service ticket
     * @param serviceUrl The Application Service URL
     * @param valVer The CAS server protocol version used for validation
     */
    public ServiceTicket(String ticketId, URL serviceUrl, int valVer) {
        this.setId(ticketId);
        this.setServiceUrl(serviceUrl);
        this.setValidationVersion(valVer);
    }

    /**
     * Set the Id of the CAS Service Ticket
     * @param ticketId The Id string of this service ticket
     */
    private void setId(String ticketId) {
        this.id = ticketId;
    }

    /**
     * Get the Id of the CAS Service Ticket
     * @return The Id string of this service ticket
     */
    public String getId() {
        return this.id;
    }

    /**
     * Set the Application Service URL
     * @param servUrl The service URL of this service ticket
     */
    private void setServiceUrl(URL servUrl) {
        this.serviceUrl = servUrl;
    }

    /**
     * Get the Application Service URL
     * @return The service URL of this service ticket
     */
    public URL getServiceUrl() {
        return this.serviceUrl;
    }

    /**
     * <p>
     * Set the CAS Validation Response to be parsed as version 1 = 1.0, or
     * 2 = 2.0. Currently, this module only supports versions 1.0 or 2.0
     * formats, and not the 3.0 format. See also parseValidationResponse().
     * </p>
     * <p>
     * This method only allows two possible values:
     * <ul>
     *  <li> <code>1</code> - CAS protocol version 1.0
     *  <li> <code>2</code> - CAS protocol version 2.0
     * </ul>
     * </p>
     *
     * @param valVersion The CAS validation version of this service ticket
     */
    private void setValidationVersion(int valVersion) {
        if (valVersion == 1) {
            this.validationVersion = 1;
        } else {
            this.validationVersion = 2;
        }
    }

    /**
     * Get the CAS server protocol version for validating this ticket.
     * There are only two possible values:
     * <ul>
     *  <li> <code>1</code> - CAS protocol version 1.0
     *  <li> <code>2</code> - CAS protocol version 2.0
     * </ul>
     * @return The CAS validation version of this service ticket
     */
    public int getValidationVersion() {
        return this.validationVersion;
    }

    /**
     * <p>
     * The validation response is parsed according to the value of
     * validationVersion set in setValidationVersion(). This method currently
     * parses CAS 1.0 and 2.0 formatted responses, defaulting to 2.0.
     * See also setValidationVersion().
     * </p>
     * <p>
     * The parsing of CAS Version 2.0 validation response messages is not
     * complete. This parsing only extracts the netid, validation response code
     * and validation response message. Nothing else, like proxy, is extracted.
     * </p>
     *
     * @throws IOException if the CAS server validation response is not in a recognized format
     */
    private void parseValidationResponse() throws java.io.IOException, java.text.ParseException {
        if (this.validationResponse == null) {
            return;
        }
        String response = this.validationResponse;
        if (this.validationVersion == 1) {
            String [] results = response.split("\n");
            String casSuccess = results[0].trim();
            String casUser    = results[1].trim();
    
            if (casSuccess.equalsIgnoreCase("no")) {
                this.isAuthSuccess = false;
            } else if (casSuccess.equalsIgnoreCase("yes")) {
                this.isAuthSuccess = true;
                this.setAuthUser(casUser);
            }
            else{
                throw new IOException("Unknown CAS server validation response");
            }

        // By default, we validate the response as CAS 2.0
        } else {
            String casSuccess = "unknown";
            String casUser    = null;
            String casCode    = "unknown";
            String casMessage = "unknown";
            if (response.contains("<cas:authenticationSuccess>")) {
                casSuccess = "yes";
                // obtain the CDATA value inside the first <cas:user> tag
                int startIdx = response.indexOf("<cas:user>");
                startIdx += 10;  // i.e. length("<cas:user>")
                int endIdx   = response.indexOf("</cas:user>",startIdx);
                // apply .trim() to CDATA inside openning and closing tags
                casUser  = response.substring(startIdx,endIdx).trim();
            }
            else if (response.contains("<cas:authenticationFailure")) {
                casSuccess = "no";
                int startIdx  = response.indexOf("<cas:authenticationFailure ");
                int endIdx    = response.indexOf(">",startIdx);
                String failureTag = response.substring(startIdx,endIdx);
                // obtain the value of the code attribute of the <cas:authenticationFailure> tag
                if (failureTag.contains("code=")) {
                    failureTag   = failureTag.replaceAll("\"","'");  // should never have ("), but make sure
                    int attrIdx1 = response.indexOf("code='");
                        attrIdx1 = response.indexOf("'",attrIdx1) + 1; // get position of first (')
                    int attrIdx2 = response.indexOf("'",attrIdx1);     // get position of second (')
                    if (attrIdx1 < attrIdx2) {
                        // Do not apply .trim(), XML attribute value inside quotes is asis
                        casCode  = response.substring(attrIdx1,attrIdx2);
                    }
                }
                // obtain the CDATA value inside the <cas:authenticationFailure> tag
                startIdx     = endIdx + 1;  // Start at the position immediately after (>)
                endIdx       = response.indexOf("</cas:authenticationFailure>",startIdx);  // position left of closing tag
                if (startIdx < endIdx) {
                    // Chars like ' and & can only exist in XML as an ASCII escaped code.
                    // "&#039;" == "'"
                    // "&#038;" == "&"
                    // apply .trim() to CDATA inside openning and closing tags
                    casMessage   = response.substring(startIdx,endIdx).trim().replaceAll("&#039;","'");
                }
            }

            if (casSuccess.equalsIgnoreCase("no")) {
                this.isAuthSuccess = false;
                this.setAuthCode(casCode);
                this.setAuthMessage(casMessage);
            }
            else if (casSuccess.equalsIgnoreCase("yes")) {
                this.isAuthSuccess = true;
                this.setAuthUser(casUser);
            }
            else{
                throw new ParseException("Could not parse CAS validation message. Unknown message format.",0);
            }

        }
    }

    /**
     * Set the validation response received from the CAS server after attempting
     * to validate this Service Ticket. Once the validation response is set with
     * this method, it is immediately parsed. The results from parsing the
     * message are set into this object.
     * <p>The validation response is set by {@link AuthService#validateTicket AuthService.validateTicket}.</p>
     *
     * @param valResponse The response from the CAS Server after the validation attempt
     * @throws IOException If the CAS server validation response is not in a recognized format
     */
    public void setValidationResponse(String valResponse) throws java.io.IOException, java.text.ParseException {
        this.validationResponse = valResponse;
        this.parseValidationResponse();
    }

    /**
     * Get the validation response received from the CAS server after attempting
     * to validate this Service Ticket.
     * <p>The validation response is set by {@link AuthService#validateTicket AuthService.validateTicket}.</p>
     *
     * @return The response from the CAS Server after the validation attempt
     */
    public String getValidationResponse() {
        return this.validationResponse;
    }

    /**
     * After the validation response is set by {@link AuthService#validateTicket AuthService.validateTicket},
     * call this method to test is authentication is successful.
     *
     * @return true if the validation response indicates successful authentication
     */
    public boolean isAuthSuccess() {
        return this.isAuthSuccess;
    }

    /**
     * <p>Only for CAS Server protocol 2.0</p>
     * The {@link #setValidationResponse setValidationResponse} will set the Auth Code if validation
     * was unsuccessful.
     *
     * @param aCode The code from the validation response, only available if validation was unsuccesful
     */
    private void setAuthCode(String aCode) {
        this.authCode = aCode;
    }

    /**
     * <p>Only for CAS Server protocol 2.0</p>
     * After validation of this service ticket via {@link AuthService#validateTicket AuthService.validateTicket},
     * the Auth Code will be set if validation
     * was unsuccessful. Use this method to retrieve the Auth Code.
     *
     * @return The code from the validation response, only available if validation was unsuccesful
     */
    public String getAuthCode() {
        return this.authCode;
    }

    /**
     * <p>Only for CAS Server protocol 2.0</p>
     * The {@link #setValidationResponse setValidationResponse} will set the Auth Message if validation
     * was unsuccessful.
     *
     * @param aMessage The message from the validation response, only available if validation was unsuccesful
     */
    private void setAuthMessage(String aMessage) {
        this.authMessage = aMessage;
    }

    /**
     * <p>Only for CAS Server protocol 2.0</p>
     * After validation of this service ticket via {@link AuthService#validateTicket AuthService.validateTicket},
     * the Auth Message will be set if validation
     * was unsuccessful. Use this method to retrieve the Auth Message.
     *
     * @return The message from the validation response, only available if validation was unsuccesful
     */
    public String getAuthMessage() {
        return this.authMessage;
    }

    /**
     * The {@link #setValidationResponse setValidationResponse} will set the Auth User if validation
     * was successful.
     *
     * @param aUser The user (or netid) from the validation response, only available if validation was successful
     */
    private void setAuthUser(String aUser) {
        this.authUser = aUser;
    }

    /**
     * After validation of this service ticket via {@link AuthService#validateTicket AuthService.validateTicket},
     * the Auth User will be set if validation
     * was successful. Use this method to retrieve the Auth User.
     *
     * @return The user (or netid) from the validation response, only available if validation was successful
     */
    public String getAuthUser() {
        return this.authUser;
    }

    /**
     * Set the time the validation was requested.
     * This is set by {@link AuthService#validateTicket AuthService.validateTicket}
     *
     * @param reqTime The time at which the validation request was made
     */
    public void setRequestTime(Date reqTime) {
        this.requestTime = reqTime;
    }

    /**
     * Before validation of this service ticket via {@link AuthService#validateTicket AuthService.validateTicket},
     * the request time is set.
     * Use this method to get the time the validation was requested.
     *
     * @return The time at which the validation request was made
     */
    public Date getRequestTime() {
        return this.requestTime;
    }

    /**
     * Set the time the validation response was received.
     * This is set by {@link AuthService#validateTicket AuthService.validateTicket}
     *
     * @param resTime The time at which the validation response was received
     */
    public void setResponseTime(Date resTime) {
        this.responseTime = resTime;
    }

    /**
     * After validation of this service ticket via {@link AuthService#validateTicket AuthService.validateTicket},
     * the response time is set.
     * Use this method to get the time the validation response was received.
     *
     * @return The time at which the validation response was received
     */
    public Date getResponseTime() {
        return this.responseTime;
    }

}

