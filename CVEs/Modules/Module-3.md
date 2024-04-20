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


