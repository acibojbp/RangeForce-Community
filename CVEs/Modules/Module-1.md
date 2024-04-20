# CVE Overview

CVE stands for Common Vulnerabilities and Exposures. It is a list of publicly known computer security flaws. The system is operated by the MITRE Corporation, and receives funding from the National Cyber Security Division of the United States Department of Homeland Security. This system has been available for the public since September 1999.

In this module, you will learn precisely how CVEs and CVSS works and how to find out when a CVE related to your project is published.

## Contents
- [What are CVEs](#what-are-cves)
- [CVE Severity Score](#cve-severity-score)
- [CVE Reporting and Response](#cve-reporting-and-response)

## What are CVEs

**Common Vulnerabilities and Exposures** is a list of publicly known computer security flaws. Each security flaw receives a unique **CVE ID**. When security professionals talk about a specific CVE, they mention the CVE ID. For example, the infamous **Dirty Cow** security vulnerability is **CVE-2016-5195**.

Unlike Dirty Cow or Heartbleed, most vulnerabilities are not infamous enough to have their own well-recognized name. CVE IDs are extremely useful because they avoid naming confusions when having a discussion about security flaws.

CVEs are assigned by **CVE Numbering Authorities (CNAs)**. There are three main types of CNAs:

- MITRE functions both as an editor and the primary CVE Numbering Authority, assigning CVE numbers for any vulnerability not covered by another CNA.
- Many CNAs exist to assign CVE numbers for their own products, for example, Adobe, Apple, Atlassian, etc.
- A third-party coordinator, such as a CERT organization, may assign CVE numbers for products not covered by other CNAs. For example, JPCERT/CC is a root CNA for Japanese organizations.

[Click here to see the list of CNAs](https://www.cve.org/PartnerInformation/ListofPartners).

Along with the identifier, a CVE entry also has a brief **description**, ideally about what the vulnerability is and which products it affects. In addition to the short description, the CVE will include **references** to additional information about the vulnerability, such as the vendor's security advisory.

- Answer the question.

**Which of the following are part of a CVE entry?**  

**References — a list of URLs to sites with useful details about the vulnerability.**  
Analysis — a lengthy and detailed description of how the vulnerability functions.  
**ID — a unique identifier assigned to each vulnerability**  
**Description — a brief description of the vulnerability and the product(s) it affects**  

## CVE Severity Score

CVEs don't just allow security professionals to **distinguish** vulnerabilities, they also make it easy to know at a glance how **impactful** any given vulnerability is. If a new CVE comes out about a product your company is using, then it's important to know if your systems can be completely compromised at any moment (critical severity), or if the vulnerability is most likely not exploitable or does not lead to any significant compromise in security (low severity).

To that effect, each CVE is assigned a **severity score** according to the **Common Vulnerability Scoring System (CVSS)**. CVSS scores range from 0 to 10, and the final score includes different factors, such as the vulnerability's impact, ease of exploitability, and vulnerable target distribution. A CVSS score is also represented as a string, which contains the values used to derive the score.

For example, examine a CVSS 9.0 (critical severity) vulnerability, wherein a buffer overflow can be exploited in a web application to cause a crash. The CVSS string corresponding to the vulnerability, **AV:N/AC:L/Au:N/C:P/I:P/A:C**, means the following:

- Access Vector (**AV**) — Network (**N**): The vulnerability may be exploited from any network that can access the target system.
- Access Complexity (**AC**) — Low (**L**): Accessing the vulnerability is not complex.
- Authentication (**Au**) — None (**N**): The attacker is not required to authenticate to exploit the vulnerability.
- Confidentiality (**C**) — Partial (**P**): The attacker can access some additional files and data on the system as a result of exploiting the vulnerability.
- Integrity (**I**) — Partial (**P**): The attacker is able to alter some files or data on the system.
- Availability (**A**) — Complete (**C**): The attacker is able to cause the system to become completely unavailable as a result of exploiting the vulnerability.

There are multiple versions of CVSS. At the time of writing this module, the latest version is CVSS 3.1. CVSS 3 scores are assigned thusly:

|Severity|Base Score Range|
|---|:-:|
|None|0.0|
|Low|0.1-3.9|
|Medium|4.0-6.9|
|High|7.0-8.9|
|Critical|9.0-10.0|
- Answer the questions.

**In the CVSS vector string AV:N/AC:L/Au:N/C:P/I:C/A:C, what is the level of compromise for Integrity?**  
`Complete`

**What is the severity of a vulnerability with CVSS score 10.0?**  
`Critical`

## CVE Reporting and Response

Now that you know about CVEs and the CVSS, how do you apply that knowledge to your own projects? If there is an unpatched CVE in your project, you obviously want to fix the issue. But how to find out when a CVE is published about your product, or a product you use in your project? The general answer is that you have to be easy to find and you have to be good at information retrieval.

First of all, it's important to know that anyone can apply for a CVE. [Responsible disclosure](https://en.wikipedia.org/wiki/Responsible_disclosure) dictates that the owner of the product should be notified and allowed to patch the product before publishing the details of the vulnerability. Responsible disclosure guidelines are not always followed, but you can improve your chances by making it easy to find vulnerability disclosure information for your organization. Organizations should publish a **disclosure policy**, or a **[security.txt](https://securitytxt.org/) page**.

You should keep in mind that not all vulnerabilities are found by the good guys. As your product grows, you are going to want to introduce some form of **security verification**, for example:

- Manual and automatic code security analysis
- Penetration testing
- Independent code review

In case the CVE is in a dependency of some other product your organization uses, it's important that you keep a close eye on CVEs about that product. To retrieve information about CVEs, you can:

- Subscribe to a security feed or mailing list, such as [Full Disclosure](https://seclists.org/fulldisclosure/).
- Set up a [Google Alerts](https://www.google.com/alerts) search about a specific product's vulnerabilities.

- Answer the question.

**What is the expected relative URL of a [security.txt](https://securitytxt.org/) page on a website?**  
`/.well-known/security.txt`
