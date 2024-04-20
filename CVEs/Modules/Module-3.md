# CVE-2023-36884 Windows Search - Remote Code Execution

On July 11, 2023, Microsoft released a blog post and a security guideline about a phishing campaign by a threat actor called Storm-0978 (also known as RomCom) that involved the abuse of previously undisclosed CVE-2023-36884. The exploitation takes place when the end users open specifically crafted Microsoft Office documents, which leads to the loading of a series of files and scripts via iframe injections. This results in the download and execution of the final payload. CVE-2023-36884 was exploited in one of the steps of the attack chain and involves misusing the Windows Search functionality to avoid the stamping of the Mark of the Web (MotW) tag on the malicious files.

In this module, you will analyze the initial malicious document and examine the attack chain to understand CVE-2023-36884.

CVSS Base Score: 8.8 (HIGH)
CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H

Learning outcomes

Upon completion of this module, learners will be able to:

- Analyze malicious Office documents.
- Understand how the vulnerability is exploited.
- Know how to mitigate the vulnerability.

## Contents
- [Campaign and Threat Actor Overview](#campaign-and-threat-actor-overview)
- [Maldoc Analysis](#maldoc-analysis)
- [Attack Chain Overview](#attack-chain-overview)
- [Vulnerability Overview](#vulnerability-overview)
- [Mitigation & Security Updates](#mitigation--security-updates)

## Campaign and Threat Actor Overview

On July 11, 2023, **Microsoft** released a [blog post](https://www.microsoft.com/en-us/security/blog/2023/07/11/storm-0978-attacks-reveal-financial-and-espionage-motives/) and a [security guideline](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36884) about a phishing campaign that involved the abuse of previously undisclosed **CVE-2023-36884**. Microsoft attributed the attack to a threat actor called **Storm-0978** (also known as RomCom) and urged customers to apply the provided interim remediation actions.

Prior to Microsoft's report, the **BlackBerry Threat Research and Intelligence Team** discovered two malicious documents used in this campaign. These documents imitated legitimate documents related to the **Ukrainian World Congress** and **NATO Summit** in Vilnius, Lithuania. They reported their findings to relevant governmental organizations and [published their](https://blogs.blackberry.com/en/2023/07/romcom-targets-ukraine-nato-membership-talks-at-nato-summit) analysis on their blog on July 7. The BlackBerry team also attributed the attack to **RomCom** based on the tactics, techniques, and procedures (TTPs), and the usage of some of the infrastructure previously observed with RomCom.

**Storm-0978** is a threat actor operating out of Russia. In the past, they have conducted opportunistic **ransomware** and **extortion** operations against financial and telecom industries around the world as well as **credential-gathering** campaigns against the Ukrainian military and government. Usually, they targeted organizations with trojanized versions of popular legitimate software that led to the installation of the RomCom backdoor. In their latest campaign, they were observed exploiting the **CVE-2023-36884** vulnerability to deliver a backdoor similar to RomCom.

![Screenshot 2024-04-20 042003](https://github.com/acibojbp/RangeForce-Community/assets/164168280/11f12f06-4f0d-4813-aa48-14f2d6c2e378)

Malicious documents were specifically crafted to imitate documents related to the **Ukrainian World Conference** and **NATO Summit** and targeted organisations and officials in **Europe and North America** sympathetic to Ukraine. When opened, an attack chain consisting of tens of steps would execute and finish with the installation of the final payload. This is considered to be a targeted campaign with the goal of **spyware** installation later on. However, unrelated organizations who also fell victim to the attack were not spared and reportedly were infected with **ransomware**.

- Answer the questions.

**Which threat actor was this attack attributed to?**  
`RomCom`

**Who were the main targets of this campaign?**

Small and medium-sized enterprises in Russia  
**Officials and organisations in Europe and North America sympathetic to Ukraine**  
Organisations in financial and telecom industries around the world  
Supply chain targets and manufacturers in Europe and North America  

## Maldoc Analysis

The attack chain starts with a maldoc. Microsoft Office documents, starting with Office 2007 and later versions, use a file format known as **Office Open XML** (OOXML). OOXML files use a structured format based on XML (Extensible Markup Language) to store different elements of an Office document. This format consists of a collection of XML files, the document's content, formatting, metadata, and relationships to other parts of the document within a **ZIP archive**. You can open office documents with a zip utility and examine their contents.

Relationships are defined using XML and stored in special `.rels` files. In this attack chain, the adversary has embedded and linked an `.rtf` file into the maldoc with **AltChunks** (aFChunk) relationship type. AltChunks are used to embed content from external files (in this case, an `.rtf` file) into the Word document. The **Target** field specifies the relative path to the target file within the word document's ZIP archive. You can examine the relationship from `word/_rels/document.xml.rels` within the archive.

![Screenshot 2024-04-20 042508](https://github.com/acibojbp/RangeForce-Community/assets/164168280/bae6a7ef-a445-4229-935a-fe1f6ca5e800)

Identify and extract the malicious `.rtf` document for further analysis. The malicious `.rtf` file contains two **OLE objects**. OLE (Object Linking and Embedding) objects in Office documents can be abused by adversaries to deliver malicious content or execute commands. In this case, OLE objects are used to communicate with the hosts controlled by the adversary to start the next stages of the attack chain. OLE objects embedded in the `.rtf` documents can be listed with **rtfobj** ( `rtfobj.exe <mal_document.rtf>` ) from oletools suite.

![Screenshot 2024-04-20 042649](https://github.com/acibojbp/RangeForce-Community/assets/164168280/c0d086f2-dac2-4fff-bbb5-42b1ce80fc80)

You can extract these OLE objects for further analysis with `rtfobj.exe -s all -d . <mal_document.rtf>` :

- `-s all` selects and saves all OLE objects;
- `-d .` saves them in the current directory.
Now that the OLE objects are extracted, you can use the **strings** command line tool or **PEStudio**, to examine strings in these objects.

![Screenshot 2024-04-20 052608](https://github.com/acibojbp/RangeForce-Community/assets/164168280/767386bd-8336-4ca6-a714-6aa6199d03d2)

When the end user opens the malicious Word document, the embedded `.rtf` document loads up, and OLE objects execute and load the `file001.url` and `start.xml` files from the adversary-controlled SMB and web servers.

- Extract the Word document (maldoc) from the zip archive:
	- File: `maldoc.zip`
	- Password: infected
- Identify and extract the malicious `.rtf` file from the maldoc.
- Extract and analyze the OLE objects embedded in the `.rtf` file.
- Extract URLs from the OLE objects.
- Answer the questions.

![Screenshot 2024-04-20 042959](https://github.com/acibojbp/RangeForce-Community/assets/164168280/056b27ff-63bc-4cdb-9824-f5c399046dd9)

![Screenshot 2024-04-20 044112](https://github.com/acibojbp/RangeForce-Community/assets/164168280/f8e96724-8926-4b80-adc7-b075c0eeb955)

![Screenshot 2024-04-20 044136](https://github.com/acibojbp/RangeForce-Community/assets/164168280/e2adf381-7018-4a45-93af-7f9aa4d5e8a1)

**What is the name of the `.rtf` file embedded in the maldoc?**  
`afchunk.rtf`

---

![Screenshot 2024-04-20 044306](https://github.com/acibojbp/RangeForce-Community/assets/164168280/48cdf872-01d7-4248-add4-87f845975475)

![Screenshot 2024-04-20 044429](https://github.com/acibojbp/RangeForce-Community/assets/164168280/0748cac4-20f8-4f67-b2fc-40ff0b3c9359)

![Screenshot 2024-04-20 044459](https://github.com/acibojbp/RangeForce-Community/assets/164168280/7069140e-c218-45e9-8d06-89add1015acb)

![Screenshot 2024-04-20 052039](https://github.com/acibojbp/RangeForce-Community/assets/164168280/6fb550dd-7c82-41bd-b508-3220f7a9087c)

**What is the URL of the file loaded via SMB?**  
`\\104.234.239.26\share1\MSHTML_C7\file001.url`

---

![Screenshot 2024-04-20 044633](https://github.com/acibojbp/RangeForce-Community/assets/164168280/8608d536-3c19-4361-ac58-cf98f6febfd5)

**What is the URL of the file loaded via HTTP?**  
`http://74.50.94.156/MSHTML_C7/start.xml`

---

## Attack Chain Overview

The vulnerability was originally named **Office and Windows HTML Remote Code Execution**. Initially, the precise nature of CVE-2023-36884 was not clear. Consequently, if you search for CVE-2023-36884, you will discover numerous technical articles where the whole attack chain was analyzed and portrayed as CVE-2023-36884. Microsoft later renamed the vulnerability to **Windows Search Remote Code Execution Vulnerability** and specified that the adversary was able to exploit a previously undisclosed vulnerability in **Windows Search** to evade the stamping of the **Mark of the Web (MotW)** tag.

Researchers still look at the whole attack chain when talking about CVE-2023-36884, as the chain itself is elaborate and the preceding steps need to succeed for the vulnerability to be exploited. Furthermore, the chain can be broken into pieces and re-used by other adversaries in other attacks. For example, the method of OLE object-embedded `.rtf` file inclusion in the main maldoc (first stage of the attack chain) has already been used by other adversaries in their attacks.

Below is a simplified chain (less details, misses some steps) derived from the attack chain created by [research team at Volexity](https://twitter.com/r00tbsd/status/1679042071477338114) and a spreadsheet created by a vulnerability analyst [Will Dormann](https://twitter.com/wdormann/status/1684682954063114240).

![Screenshot 2024-04-20 045021](https://github.com/acibojbp/RangeForce-Community/assets/164168280/bc5a0d75-042c-49b6-b367-db04edd0f520)

**A simplified attack chain description:**

- Initial maldoc includes an `-rtf` document embedded with the **AltChunks** (aFChunk) method.
- The `.rtf` file contains **OLE objects** that connect to remote URLs.
- **OLE object 1** loads share1\MSHTML_C7\file001.url from the adversary's **SMB server**. The file identifies and passes the victim's **IP address**. Simultaneously, **multiple files are generated automatically** (with the victim's IP address in their name) in the adversary SMB server for later use.
- **OLE object 2** connects to `http://[adv_http_server_ip]/MSHTML_C7/start.xml`  via **HTTP**. The script then loads `RFile.asp*` with an HTML **iframe** tag from the adversary's HTTP server. This attack chain uses iframes quite extensively to load the following steps.
- `RFile.asp` loads one of the previously generated files, `[victim_ip]_[hex]_file001.htm` , via iframe from the adversary's SMB server.
- `file001.htm` loads the `[victim_ip]_[hex]_file001.search-ms` **Windows search file** from the adversary's SMB server and creates variables representing the victim's **computer name** and **username**. The discovered computer name and the username are used in the following steps.
- `file001.search-ms` loads `[victim_ip]_[hex]_file001.zip` with the contents **1111.htm** and **2222.chm**. This step exploits the **CVE-2023-36884** vulnerability to evade the **Mark of the Web (MotW) defenses** and allow code execution.
- `1111.htm` and `2222.chm` go through a set of steps of calling additional files (omitted for simplicity) via iframes and end up loading `ex001.zip/file001.vbs` from the adversary's SMB server.
- `file001.vbs` is loaded from the IE cache. It loads and executes the **final payload** (backdoor similar to RomCom).


- Answer the questions.

In which Windows service is the CVE-2023-36884 vulnerability exploited?  
`Windows Search`

What HTML element does the threat actor predominantly use to load scripts and files in this attack chain?  
`iframe`

Connection to which file triggers the automated generation of tailored files in the adversary's SMB server? (file name)  
`file001.url`

Which security measure is evaded by the threat actor with the exploitation of CVE-2023-36884?  
`Mark of the Web `

## Vulnerability Overview

The **Mark of the Web (MOTW)** is a concept used in Windows operating systems to indicate that a file downloaded from the internet might be potentially unsafe. It is a security feature implemented by Microsoft to help protect users from potentially malicious files or scripts that could harm their computers. When a file is downloaded from the internet, a **special comment** is automatically added to its **NTFS file metadata** to alert the system that the file came from the web. When you attempt to open or run a file with the MOTW tag, Windows may apply additional security measures, such as running it in a restricted mode, prompting you for permission to execute it, or warning you about potential risks.

Microsoft disclosed that the exploitation of the CVE-2023-36884 vulnerability allows the adversary to **evade the Mark of the Web (MotW)** defenses which can result in **code execution** on the victims' systems. Unfortunately, Microsoft does not go into detail about the root cause of the vulnerability or how it was exploited by the adversary. However, researchers were able to deduce the issue by analyzing the attack chain and the changes provided by Microsoft in the related patches.

Per [Will Dorman's analysis](https://twitter.com/wdormann/status/1691202940361465860) of the attack chain:

- Adversary loads `[victim_ip]_[hex]_file001.zip` from their SMB server with `[victim_ip]_[hex]_file001.search-ms` but stops the execution of `search-ms` before the MotW comment is added. Contents of the ZIP archive on initial download are some dummy `1111.txt` and `2222.txt` files.
- The archive is replaced in the SMB server and `search-ms` is executed the second time. The files (inside the archive) loaded in the second try are `1111.htm` and `2222.chm`.
- `1111.htm` is loaded from the ZIP archive before the MotW comment is added to the file.

It is worth noting that this method of running the file before the MotW stamping is unreliable. The race is not won every time and fails quite often. However, it is doable as **before the patch**, approximately a **20-second delay was observed between the file extraction and the MotW stamping** for files loaded with search-ms . Furthermore, the files would be **extracted in a predictable temporary location** of `C:\Users\<username>\AppData\Local\Temp\Temp_1_[victim_ip]_[hex]_file001.zip\` . The adversary then could easily access the files with `\\<computer_name>\c$\Users\<username>\AppData\Local\Temp\Temp1_[victim_ip]_[hex]_file001.zip\1111.htm` . Note that the victim's computer name, username, and IP address were already known to the adversary from the earlier stages of the attack chain.

- Answer the question below.

**What are the two main issues that allow the exploitation of the vulnerability?**

Executables embedded into Office documents via the AltChunks method do not trigger security measures.  
**There is a long delay between file extraction and MotW application for files loaded with search-ms files.**  
The MotW tag is never stamped on files loaded from remote SMB servers.  
**Archives are extracted in a predictable temporary location.**  
Files loaded with search-ms do not get the MotW tag stamped on them by default.  


## Mitigation & Security Updates

The vulnerability affected nearly all Windows operating systems and Office versions except for the customers who use **Microsoft Defender for Office 365** or **Microsoft 365 Apps with versions 2302 or higher**. As the interim solution, Microsoft advised customers of the vulnerable Office versions to set the **FEATURE_BLOCK_CROSS_PROTOCOL_FILE_NAVIGATION** registry key to avoid exploitation. This entails editing or creating the `Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_BLOCK_CROSS_PROTOCOL_FILE_NAVIGATION\` registry key and adding **Office application names** as values of **type REG_DWORD** with **data 1**.

![Screenshot 2024-04-20 050350](https://github.com/acibojbp/RangeForce-Community/assets/164168280/49eec2d2-707d-46e9-8c63-b346207ad006)

The provided interim solution stops the execution of the attack chain at `[victim_ip]_[hex]_file001.htm` during the **transitioning from HTTP to SMB/WebDav**. While it does break the attack chain and mitigates the exploitation of the vulnerability, it does not address the underlying issues that make the Windows Search service vulnerable.

![Screenshot 2024-04-20 050521](https://github.com/acibojbp/RangeForce-Community/assets/164168280/77e25e96-a9af-4462-bfea-fc33d1873614)

Fortunately, in August, **Microsoft released security updates** for their [operating systems](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36884) and [Office products](https://msrc.microsoft.com/update-guide/vulnerability/ADV230003). Security updates provided by Microsoft **reduce the delay between file extraction and the MotW comment addition** considerably and the extraction location is also **randomized** in the **Temp** directory. For example:

- Old predictable location: `..\Temp\Temp1_[victim_ip]_[hex]_file001.zip\1111.htm`
- New randomized location: `..\Temp\Tempe20f6191-989d-4498-82e5-9ad64690cba_[victim_ip]_[hex]_file001.zip\1111.htm`

These security updates fix the underlying issues that allowed the exploitation of CVE-2023-36884.

> Note: Refer to the relevant Microsoft [operating system](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36884) and [Office](https://msrc.microsoft.com/update-guide/vulnerability/ADV230003) security update guidelines for real-world applications.
