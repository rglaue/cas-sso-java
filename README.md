# cas-sso-java project

This repository is an archive of the CASSSO project, developed in 2010-2011,
as the Blackboard WebCT learning mnagement system cas-sso plugin. The last
update to this project was February 22, 2011.

The cas-client subproject is fully independent of Blackboard WebCT. This
library can be used alone by itself as a CAS client, and has no other
java library dependencies.

Historical documentation, including the Java API for these libraries, is
available in the `docs/` directory. Historical releases is available in the
`releases/` directory.


See Also: [Central Authentication Service](https://en.wikipedia.org/wiki/Central_Authentication_Service)


## ABOUT CASSSO

### The minimal 3rd-party-library-independent CAS SSO Client Library

This project entails two agendas. The first is to create an updated CAS SSO Authentication Module for Blackboard 8\. The second is to create a minimal and 3rd-party-library-independent CAS client library.

The objective is to provide a useful CAS client library that does not require any 3rd party libraries, including XML parsers. This CAS client library is then implemented in the Blackboard 8 CAS SSO Custom Authentication Module. The WebLogic Server library dependencies are seperated out into an additional library so that it can be excluded if desired.

### Blackboard CAS SSO Custom Authentication Module

This CAS SSO authentication module is a Blackboard 8 Custom Authentication Module. The module is utilized for authenticating a user to Blackboard against a CAS server.

This CAS SSO Module for Blackboard 8+ is intended to replace the previous CAS SSO authentication module for WebCT Vista 4+ once made available at http://devnet.webct.com, and later moved in 2007 to OSCELOT FORGE at [http://projects.oscelot.org/gf/project/wct-cas](http://projects.oscelot.org/gf/project/wct-cas), navigatable to `[ Home > Projects > WebCT CE/Vista CAS SSO Module ]`.

This module is a complete rewrite of its predecessor. It is a complete Maven 2 project with the following features:

1.  Supports CAS 2.0 and CAS 1.0 protocols. This is configurable via the module's configuration page in Blackboard.
2.  Supports a Null Trust Manager configuration. This is, SSL Cert CA Trust can be turned off or on via the module's configuration page in Blackboard.
3.  The module libraries can be compiled without WebLogic library dependencies, and used in Blackboard (without the Null Trust Manager though). The predecessor requires the WebLogic Server library for compilation.
4.  Has more debugging output
5.  Provides for audit logging via Blackboard's Log4j configuration.

The creation of this Blackboard 8.0 CAS SSO Custom Authentication Module was undertaken by [Western Illinois University](http://www.wiu.edu). It was written by [Russell E Glaue](http://russ.glaue.org), an employee of [Western Illinois University](http://www.wiu.edu) [Center for the Application of Information Technologies](http://www.cait.org), a Center at the University within the University's [uTech](http://www.wiu.edu/utech) division. This module is distributed and supported by [Western Illinois University](http://www.wiu.edu), [uTech](http://www.wiu.edu/utech) division.

### Subproject division

This project is divided into three subprojects:

1.  cas-client - The minimal 3rd-party-library-independent CAS SSO Client Library
2.  cas-weblogic - The Weblogic specific classes for a Null Trust Manager
3.  cas-blackboard - The Blackboard 8 CAS SSO Custom Authentication Module

## REQUIREMENTS

### The requirements for compiling the CASSO subprojects

<div class="subHeading-1-Body-1">

*   **CASSSO version 1.3.X**
    *   Maven 3.0+ (Maven is used to compile and package the libraries)
        *   _Required for the sub projects: cas-client, cas-weblogic, cas-bloackboard_
    *   Java 1.5.0 (1.5.0_22 tested)
        *   _Required for the sub projects: cas-client, cas-weblogic, cas-bloackboard_
    *   WebLogic Server Library 9.2 (9.2.3 tested)
        *   _Required for the sub projects: cas-weblogic_
    *   Blackboard 8 PowerLinks 4.2.1 SDK
        *   _Required for the sub projects: cas-blackboard_

### The requirements for implementing the CASSSO project libraries

*   **CASSSO version 1.3.X**
    *   cas-client (CAS Client Library)
        *   _Java 1.5.0 (1.5.0_22 tested)_
    *   cas-blackboard (Blackboard 8 CAS SSO Custom Authentication Module)
        *   _Java 1.5.0 (1.5.0_22 tested)_
        *   cas-client (CAS Client Library)
        *   cas-weblogic (WebLogic-specific Null Trust Manager)
            *   _WebLogic Server 9.2+ (Which contains the server library in runtime)_
        *   _Blackboard 8.0+ (Which contains the PowerLink SDK 4.2.1+ in runtime)_
    *   cas-weblogic
        *   _Java 1.5.0 (1.5.0_22 tested)_
        *   _WebLogic Server 9.2+ (Which contains the server library in runtime)_
        *   _Note: If you want to use a Nulled Trust Manager, the cas-client library comes with a native Java implementation. This library is only necessary to implement a Nulled Trust Manager within the WebLogic runtime which overloads the native Java equivelances._

## Three Subprojects

### cas-client - (The minimal-3rd-party-independent CAS client library)

This subproject is independent of the other two (cas-weblogic and cas-blackboard). It is a minimal-3rd-party-independent CAS client library, and can be used by itself for handling the validation of CAS Service Tickets with a CAS Server Validation Service.


### cas-weblogic - (For implementing a Nulled Trust Manager in the Oracle/Bea WebLogic Server)

The classes in this subproject extend classes from the cas-client subproject to implement WebLogic specific methods, and to extended classes from the WebLogic library necessary for implementing a Nulled Trust Manager.

The Oracle/Bea WebLogic Server implements its own version of certain SSL libraries, overriding the associated classes in the Oracle/Sun JDK. In order to implement a Nulled Trust Manager within the Java runtime environment of a Oracle/Bea WebLogic server, the WebLogic specific SSL classes must be extended and implemented.

Since Blackboard 8 runs on Oracle/Bea WebLogic Server 9.2, the cas-weblogic subproject becomes a necessary library in order for the Blackboard CAS SSO Custom Authentication Module to utilize a Nulled Trust Manager.

The cas-client subproject has native JDK implementations for a Nulled Trust Manager. The cas-weblogic library is only necessary to be used within a Oracle/Bea WebLogic Server for utilizing a Nulled Trust Manager.

#### Why use a Nulled Trust Manager?

If a CAS Server utilizes a self-signed SSL Certificate, or a certificate signed by a non-trusted CA (an organization might have its own internal CA), the CA (Certificate Authority) certificate chain must be added to the database of Known Root Certificate Authorities within the Oracle/Bea WebLogic server.

Adding a CA Certificate Chain to this Known Root CA database is not a simple process. Blackboard does not provide any Graphical User Interface to help the administrator do this. It must be completed through command line tools distributed with the JDK, and also requires you to export and import the CA Chain in specific formats.

Since the Blackboard CAS SSO Custom Authentication module is configured to connect to one SSL server, that is the CAS Server, it is likely that the SSL Certificate of the server is already trusted by the administrator. So instead of going through the process of importing the CA Chain, the administrator can just configure the module to use a Trust Manager that does not require the CA Chain to be known.

This routine of using a Nulled Trust Manager is what Mozilla Firefox, Google Chrome, and Internet Explorer do when they receive a certificate that is not in their KeyStore, and you click the button to make the browser to accept the untrusted SSL Certificate and proceed to the web site any way. The only difference is that this code does not ask you to accept it, you configure ahead of time with this library to just have this turned off.

The SSL connection is securely encrypted with a Nulled Trust Manager just as much as with a typical Trust Manager.


### cas-blackboard - (WIU's Blackboard 8+ CAS SSO Custom Authentication Module)

[Blackboard](http://blackboard.com) produces a Learning Management Platform. During the first decade of the 21st century, Blackboard bought out a rival company WebCT. The WebCT Learning Management Platform retained its name through version 4, and another version named Campus Edition version 6, or CE6. These were the predominate versions through 2007.

During this era, [CAS (Central Authentication Service)](http://www.jasig.org/cas) was widely used for Single Sign On (SSO) within educational institutions. A WebCT employee had produced a Custom Authentication Module for WebCT which authenticated WebCT users with a CAS Server.

After Blackboard bought out WebCT in the later part of that decade, no new releases to the WebCT CAS Authentication Module were produced. The WebCT web site which the module resided on disapeared, and the module was moved to another community site by community members.

Though new releases of the module were no longer forth coming, the CAS project was very active. It produced newer versions of the software, and the protocol. The WebCT 4 CAS SSO Custom Authentication Module only supported CAS protocol version 1.0, where as the CAS project was nearing version 3.0 in 2010.

With the jump from WebCT 4 and WebCT CE6 to Blackboard 8, the documentation for the WebCT 4 CAS SSO Custom Authentication Module was no longer fully accurate. Additionally, the WebCT 4 CAS SSO Custom Authentication Module was coded in a way that provided for minimal satisfactory operation.

#### Western Illinois University's role

WIU ([Western Illinois University](http://www.wiu.edu)) had CAS Single Sign On services implemented in its enterprise, but was utilizing CAS protocol version 2.0\. Additionally, the documentation of the WebCT 4 CAS SSO Custom Authentication Module did not account for the Institutional Administrative level introduced in Blackboard 8.0\. The module had to be configured on the that level, and would not work if only configured on the Domain Administration level as the documentation said. The tech administrators also found it difficult to debug the module's activity. And finally, there was nothing in place to audit the authorization activity of the module. The audit measures were necessary to monitor activity, and to assist users having trouble gaining access to Blackboard via the module.

CAIT ([Center for the Application of Information Technologies](http://www.cait.org)) is a special organization on WIU's campus, under the uTech ([University Technology](http://www.wiu.edu/utech)) division. Specifically, CAIT actively participates in the online and distance learning development initiatives of the University. When the challenges were presented in an update meeting, employees from CAIT and uTech worked together to produce a solution. The result of that solution is this project, WIU's Blackboard 8+ CAS SSO Custom Authentication Module. The fruit of the solution produced three specific projects: cas-client, cas-weblogic, and cas-blackboard. The later is this subproject which encompases the specific authentication module.

#### Features and Benefits

These are the specific features and benefits of WIU's Blackboard 8+ CAS SSO Custom Authentication Module that make it advantageous.

These features are configurable on the module's configuration page within the Blackboard 8 Institutional Administration settings.

*   Supports both version 2.0 and 1.0 CAS protocols.  
    _By looking at the specifications, the CAS protocol version 3.0 should be compatible with the module's parser for the 2.0 protocol version, without the support for proxy authentication. However, this is untested._
*   Supports both a normal SSL Trust Manager and a Nulled SSL Trust Manager.  
    _Using a Nulled Trust Manager saves the administrator from importing a CA chain in to the WebLogic JDK keystore for self-signed certificates._

These features are configurable in Blackboard's Log4j configuration.

*   Has more debugging output, and throws a lot more (and more informing) errors when something does not go right.
*   Supports audit logging. The module can output to an audit log information about a user's attempted authorization. Whether the attempt was successful or not.  
    _The audit output looks like this:_  
    `10.0.0.57 [Tue Feb 15 15:50:50 CST 2011] ticket="ST-723-qPQ1tsbg79x0HazgeINi-cas" auth="success" userid="jsmith" timems="834"`

*   Audit logging to a database or remote logging server. Log4j can be configured to log the audit log data to a remote database or logging server. This is ideal in a multi-node Blackboard installation.

Here are some additional benefits.

*   The source code is freely available under the [GPL license](license.html)
*   The cas-blackboard libraries can be compiled without WebLogic library dependencies, and used in Blackboard (without the Null Trust Manager though).  
    _The installation documentation describes how to obtain a WebLogic Server library for compiling the cas-weblogic subproject. If you have a Oracle/Bea WebLogic server, then you have the library. However, with changes to a few lines of code, you can compile the cas-blackboard library without the cas-weblogic dependency._
*   The cas-client subproject is a minimal CAS client library that can be used in any Java application to help with managing validation with a CAS server.


## DEPENDENCIES

Refer to the installation documentation for the dependencies.

All subproject libraries were tested with Java 1.5 (specifically release 22).

### cas-client dependencies

No 3rd party library dependencies.

Can run in any JVM environment.

### cas-weblogic dependencies

Appendix A in the installation documentation describes how to obtain the WebLogic Server library needed for compilation. If you have an Oracle/Bea WebLogic Server, then you already have the library.

Can only run in the WebLogic Server JVM environment.

### cas-blackboard dependencies

The Blackboard PowerLinks 4.2.1 or greater is needed for compiling the CAS SSO Custom Authentication Module. To download it, you will need access to Blackboard's support site, Behind the Blackboard.

However, the documentation is available on EDU Garage, Blackboard's Community Site.
See Blackboard Developer Network Documentation, and PowerLinks SDK APIs v4.2.1

Can only run in the WebLogic Server JVM environment, within Blackboard.
Compatible with Blackboard version 8.0+, and probably also compatible with WebCT version 4.2.1+ as it should run in any Blackboard or WebCT deployment that has the (Blackboard/WebCT) PowerLinks SDK 4.2.1 and higher.


## AVAILABILITY

CASSSO Version 1.3.1, 2011-02-22, is available in the `releases` directory
