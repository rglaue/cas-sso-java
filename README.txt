README for WIU's Blackboard 8.0+ CAS SSO Custom Authentication Module
------------------------------------------------------------------------

  [SUBPROJECTS]

  The CASSSO project is comprised of three subproject libraries

  1. cas-client

    The minimal 3rd-party-library-independent CAS SSO Client Library.

    This subproject is independent of the other two (cas-weblogic and
    cas-blackboard). It is a minimal-3rd-party-independent CAS client
    library, and can be used by itself for handling the validation of
    CAS Service Tickets with a CAS Server Validation Service.

  2. cas-weblogic

    The Weblogic specific classes for a Null Trust Manager.

    The classes in this subproject extend classes from the cas-client
    subproject to implement WebLogic specific methods, and to extended
    classes from the WebLogic library necessary for implementing a
    Nulled Trust Manager.

  3. cas-blackboard

    The Blackboard 8 CAS SSO Custom Authentication Module.

    This CAS SSO authentication module is a Blackboard 8 Custom
    Authentication Module. The module is utilized for authenticating a
    user to Blackboard against a CAS server.


  [LICENSE]

  The CASSSO project is released under the terms of the GNU General
  Public License, version 3.


  [WEB SITE]

  Please refer to the CAS SSO project web site for further details.
  http://www.codepin.org/project/cassso


  [CONTRIBUTORS]

  This project is made possible by the contributions of Western
  Illinois University, and Center for the Application of Information
  Technologies, a Center at the University.

  Western Illinois University
  http://www.wiu.edu

  Center for the Application of Information Technologies
  http://www.cait.org
