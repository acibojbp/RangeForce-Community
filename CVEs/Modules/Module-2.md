# CVE-2023-38831 WinRAR - Arbitrary Code Execution

CVE-2023-38831 is a file extension spoofing vulnerability, discovered in RARLabs WinRAR versions before 6.23. It leads to an arbitrary code execution when a user attempts to open a benign file within a ZIP archive. By modifying archives in a special way, adversaries are able to exploit the vulnerability and launch a malicious script instead of the intended file. The vulnerability has been exploited in the wild from April through August 2023.

In this module, you will learn about the vulnerability and its exploitation by examining a malicious sample that was rendered non-functional.

CVSS Base Score: 7.8 HIGH
CVSS Vector: CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H

Learning outcomes

The learner will be able to

- Identify and analyze malicious archives.
- Identify and analyze malicious scripts.
- Understand how the vulnerability is exploited.
- Know how to mitigate the vulnerability.

## Contents
- [Vulnerability Overview](#vulnerability-overview)
- [Examine the Sample](#examine-the-sample)


## Vulnerability Overview

On July 10, 2023, [Group-IB Threat Intelligence](https://www.group-ib.com/blog/cve-2023-38831-winrar-zero-day/) unit discovered a previously undisclosed vulnerability in the processing of the **ZIP** file format by **WinRAR** while researching the spread of **DarkMe** malware. Specially crafted malicious archives were posted on **trading** and **crypto-trading** forums. They were advertised as containing formulas, filters, notes, tool components, etc., for traders to entice them to download and open the archives. Archives contained and delivered various malware families, such as **DarkMe**, **GuLoader** and **Remcos RAT**. The potential end goal was withdrawing funds from the victims' brokerage accounts. (Financial losses are unconfirmed.) Multiple versions of these malicious archives have been discovered by researchers. While the files inside them differ (tailored towards the target group), the structure and the exploited vulnerability are the same. Note that the exploitation of this vulnerability is not exclusive to this campaign and was actively used by other threat actors in their attacks.

The vulnerability affected **WinRAR versions before 6.23**. Group-IB notified RARLAB about the issue and the vulnerability **was fixed in WinRAR version 6.23**.

![Screenshot 2024-04-19 174050](https://github.com/acibojbp/RangeForce-Community/assets/164168280/c3010339-6e98-453e-9d8f-c288c09987ae)

When a file is executed from within a ZIP archive, WinRAR creates a temporary directory in `%Temp%` . Under normal conditions, only the file that is executed is extracted into and executed from that temporary directory. Malicious archives, however, **contain a file and a directory under the same name with a trailing space at the end**. Windows does not allow creation of directories and files under the exact same name. This is not a normal behavior. Adversaries have modified the archive to accommodate this condition intentionally.

As seen in the diagram above, there is a **directory and a file** under the name `document.pdf `  (with a trailing space). When the benign `document.pdf `  is opened, WinRAR tries to extract the requested file into the temporary directory. Due to a **bug in filename comparison** in one of the WinRAR functions, it **extracts both the contents of the `document.pdf ` directory and the requested benign `document.pdf ` into the temporary directory**.

![Screenshot 2024-04-19 174421](https://github.com/acibojbp/RangeForce-Community/assets/164168280/bd30919d-42da-450c-b4bc-e1ac9b2cc052)

During the extraction, one of the WinRAR functions **checks if the filename contains a space at the end — and removes it if it detects one**. The benign `document.pdf `  lands in the temporary directory as `document.pdf` (without a space at the end). WinRAR then passes the name of the file to the **ShellExecuteExW** to be executed. However, the filename passed to this function is `document.pdf ` (containing space at the end). The intended benign file in the temporary directory no longer matches `document.pdf ` as the trailing space was removed from its filename during the extraction. Windows matches `document.pdf ` to `document.pdf .cmd`and executes it instead.

The executed script differs depending on the sample, but usually it searches for and executes some sort of a malicious self-extracting archive that contains the final payload.

- Answer the questions.

**In which version of WinRAR was the vulnerability fixed? (format: x.xx )**  
`6.23`

**Provide one example of malware families that were distributed with the exploitation of this vulnerability.**  
`DarkMe`

**Who was the target group in this campaign?**  

Healthcare professionals and researchers  
**Traders, stock brokers, crypto-traders**  
Government agencies and military organizations  
Everyday computer users and gamers  

**How were the archives modified by the adversary to exploit the vulnerability?**  

By adding additional metadata to the archive to mislead analysis tools  
By encrypting the archive to hide its true purpose  
**By including a directory and file with the same name and a trailing space**  
By altering the file permissions of the archive to grant unauthorized access  

## Examine the Sample

The provided sample is a real-world sample that was rendered nonfunctional by replacing the payload inside the self-extracting archive with the [desktopPet (eSheep)](https://github.com/Adrianotiger/desktopPet) project. The original malicious archive was posted in one of the trading forums and enticed victims to download and open a `ReadMe.txt` file. It is safe to open the `ReadMe.txt` in this module, however, the sample still contains the parts of the original malicious payload and execution outside this module is not advised.

> Note: Do not execute or analyze real-world malicious samples on your personal or everyday devices. Always use specialized and secured environments for malware analysis to ensure your device's safety and data integrity.

The text, image, pdf, etc., decoy file that the adversary wants the victim to open is usually benign. The **BAT file ( `.cmd` )** that is executed instead, is located in the directory that shares the same name with the decoy. The contents of the script vary from sample to sample. Some may only execute the malicious **CAB SFX** file located in that directory, while others also open the decoy (in addition to CAB SFX execution) to further fool the victims.

In this particular example, the script navigates to the `%TEMP%` directory, searches for and executes the malicious CAB SFX archive.

```
start "" /min cmd.exe /k "cd %TEMP% && for /F "delims=" %%G in ('dir /b /s "<mal_cab_sfx_archive>"') do WMIC process call create "%%~G" & exit"
```

A CAB SFX (Cabinet Self-Extracting) file is a legitimate solution commonly used for packaging and distributing software or files. However, malicious actors often exploit this format by creating CAB SFX files that contain hidden malware or harmful code. When executed, these malicious CAB SFX files automatically extract and execute their harmful contents (the final payload in this case), making them one of the favored methods for delivering malware.

The analysis of the final payload (contents of the CAB SFX archive) is outside the scope of this module as parts of the payload were replaced to render it non functional.

- Examine the sample: `trading_system.zip`
- Answer the questions.

![Screenshot 2024-04-19 175520](https://github.com/acibojbp/RangeForce-Community/assets/164168280/8fbb1eb5-3cfd-48ff-915d-2ec5248a8286)

![Screenshot 2024-04-19 175539](https://github.com/acibojbp/RangeForce-Community/assets/164168280/1d742ac4-1bae-4c94-bc68-a52010909129)

**What is the filename of the BAT file that gets executed instead of the bait?**  
`ReadMe.txt .cmd`

![Screenshot 2024-04-19 175643](https://github.com/acibojbp/RangeForce-Community/assets/164168280/29bcfbac-b25c-4811-943c-4bb889c62c41)

**What is the filename of the CAB SFX archive, executed by the BAT file? (format: `filename.extension` )**  
`weakicons.com`
