## Objective

To understand and analyze a suspicious phishing email to identify potential security threats, while learning to use open-source intelligence (OSINT) tools for in-depth email investigation. Gain proficiency in evaluating email headers, SPF, and DMARC records to verify the authenticity of an email, and develop the skills to analyze email attachments for signs of malware or other malicious activities. Following incident response protocols, including forwarding suspicious emails to Security team for further analysis and mitigation of potential risks.

### Skills Learned

- Phishing Email Identification
  - Recognizing phishing tactics such as unusual sender behavior, generic greetings, and unexpected requests.
  - Spotting red flags in email content, such as suspicious attachments or abnormal formatting.
- Email Header Analysis
  - Extracting and analyzing critical metadata (e.g., sender’s IP address, Return-Path domain) from email headers.
  - Understanding the importance of email headers in identifying the true origin of an email.
 - Use of OSINT Tools
   - Utilizing tools like Whois, MxToolBox, VirusTotal, and dmarcian for investigating email origins, domains, and attachments.
   - Assessing the reputation of a domain or IP address to determine its legitimacy.
 - SPF and DMARC Record Evaluation
   - Understanding the role of SPF (Sender Policy Framework) and DMARC (Domain-based Message Authentication, Reporting & Conformance) records in email security.
   - Verifying if the email passed SPF and DMARC checks to determine its legitimacy.
 - Attachment Analysis
   - Analyzing attachments for file type, size, and hash values to identify potential malware or malicious payloads.
   - Using tools like VirusTotal for malware scanning and identifying possible threats.
 - Incident Handling and Reporting
   - Understanding the process of reporting suspicious emails to the Security team.
   - Recognizing the importance of proactive measures in mitigating potential security breaches.

### Tools Used

- Whois: For querying domain registration information and identifying the legitimacy of the domain.
- MxToolBox: To examine email headers, DNS records, and SPF configurations.
- dmarcian: For checking the DMARC records and understanding email authentication practices.
- VirusTotal: For analyzing attachments and checking for malware or malicious payloads.
- Mozilla Thunderbird: Email client to open the .eml file.
- Sublime Text: Text editor to open the .eml file.

## Practical Exercises

<p align="center">
<img src="https://imgur.com/mzloYSY.png" height="90%" width="90%" alt="Device Specification"/>
<br/>
<b>Get the hash value of the .eml file.</b>
<br/>

<p align="center">
<img src="https://imgur.com/8s5RVR7.png" height="90%" width="90%" alt="Device Specification"/>
<br/>
<b>Open the extracted .eml file to see what's the email content.</b>
<br/>

<p align="center">
<img src="https://imgur.com/gK4B43q.png" height="90%" width="90%" alt="Device Specification"/>
<br/>
<b>Open the extracted .eml file to a text editor.</b>
<br/>

<p align="center">
<img src="https://imgur.com/x9AaNFN.png" height="90%" width="90%" alt="Device Specification"/>
<br/>
<b>Extraction of the .eml for IOCs.</b>
<br/>

<p align="center">
<img src="https://imgur.com/QMCTZ6A.png" height="90%" width="90%" alt="Device Specification"/>
<br/>
<b>Originating IP address.</b>
<br/>

<p align="center">
<img src="https://imgur.com/4I7ibCi.png" height="90%" width="90%" alt="Device Specification"/>
<br/>
<b>Whois: Owner of the originating IP address.</b>
<br/>

<p align="center">
<img src="https://imgur.com/zA1TGgB.png" height="90%" width="90%" alt="Device Specification"/>
<br/>
<b>MxToolBox: SPF record for the Return-Path domain.</b>
<br/>

<p align="center">
<img src="https://imgur.com/MlDzBO1.png" height="90%" width="90%" alt="Device Specification"/>
<br/>
<b>dmarcian: DMARC record for the Return-Path domain.</b>
<br/>

<p align="center">
<img src="https://imgur.com/fe3Xz3a.png" height="90%" width="90%" alt="Device Specification"/>
<br/>
<b>Get the hash value of the email attached .cab file.</b>
<br/>

<p align="center">
<img src="https://imgur.com/lCQ4MLS.png" height="90%" width="90%" alt="Device Specification"/>
<br/>
<b>VirusTotal: For file reputation checks. Indicating that majority of vendors flag as malicious.</b>
<br/>

## Outcome

- Improved Email Security Awareness
  - Identify phishing attempts effectively and take proactive steps to prevent them.
  - Enhanced understanding of how email security protocols (SPF, DMARC) help protect against spoofing and phishing attacks. 
- Hands-on Experience with Cybersecurity Tools
  - Gaining practical experience with OSINT tools to investigate and validate suspicious communications in real-world scenarios. 
- Effective Use of Incident Response Protocols
  - Understand the importance of working with the Security team and following organizational protocols when encountering potential threats.
- Practical Understanding of Attachment Threats
  - Evaluate email attachments for signs of malware to prevent possible infections.
- Real-World Application of Cybersecurity Concepts
  - By engaging in a practical challenge, apply cybersecurity concepts such as phishing identification, email header analysis, and attachment investigation, to prepare for real-world cybersecurity tasks.

## Acknowledgements

This project combines ideas and methods from various sources, such as the TryHackMe - The Greenholt Phish room and my IT experience. These resources provided the fundamental information and techniques, which were then modified in light of practical uses.
 - [TryHackMe - The Greenholt Phish](https://tryhackme.com/r/room/phishingemails5fgjlzxc)
 - [Whois](https://www.whois.com/whois/)
 - [MxToolBox](https://mxtoolbox.com/SuperTool.aspx)
 - [dmarcian](https://dmarcian.com/dmarc-inspector/)
 - [VirusTotal](https://www.virustotal.com/gui/home/search) 
 - [Mozilla Thunderbird](https://www.thunderbird.net/en-US/)
 - [Sublime Text](https://www.sublimetext.com/)

## Disclaimer

The sole goals of the projects and activities here are for education and ethical cybersecurity research. All work was conducted in controlled environments, such as paid cloud spaces, private labs, and online cybersecurity education platforms. Online learning and cloud tasks adhered closely to all usage guidelines. Never use these projects for improper or unlawful purposes. It is always prohibited to break into any computer system or network. Any misuse of the provided information or code is not the responsibility of the author or authors.
