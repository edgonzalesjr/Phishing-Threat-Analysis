## Objective

To understand and analyze a suspicious phishing email to identify potential security threats, while learning to use open-source intelligence (OSINT) tools for in-depth email investigation. Gain proficiency in evaluating email headers, SPF, and DMARC records to verify the authenticity of an email, and develop the skills to analyze email attachments for signs of malware or other malicious activities. Additionally, the topic emphasizes the importance of following incident response protocols, including forwarding suspicious emails to a Security Operations Center (SOC) for further analysis and mitigation of potential risks.

### Skills Learned

- Phishing Email Identification:
  - Recognizing phishing tactics such as unusual sender behavior, generic greetings, and unexpected requests.
  - Spotting red flags in email content, such as suspicious attachments or abnormal formatting.

- Email Header Analysis:
  - Extracting and analyzing critical metadata (e.g., sender’s IP address, Return-Path domain) from email headers.
  - Understanding the importance of email headers in identifying the true origin of an email.

 - Use of OSINT Tools:
   - Utilizing tools like Whois, MxToolBox, VirusTotal, and dmarcian for investigating email origins, domains, and attachments.
   - Assessing the reputation of a domain or IP address to determine its legitimacy.

 - SPF and DMARC Record Evaluation:
   - Understanding the role of SPF (Sender Policy Framework) and DMARC (Domain-based Message Authentication, Reporting & Conformance) records in email security.
   - Verifying if the email passed SPF and DMARC checks to determine its legitimacy.

 - Attachment Analysis:
   - Analyzing attachments for file type, size, and hash values to identify potential malware or malicious payloads.
   - Using tools like VirusTotal for malware scanning and identifying possible threats.

 - Incident Handling and Reporting:
   - Understanding the process of reporting suspicious emails to a Security Operations Center (SOC).
   - Recognizing the importance of proactive measures in mitigating potential security breaches.

### Tools Used

- Whois: For querying domain registration information and identifying the legitimacy of the domain.
- MxToolBox: To examine email headers, DNS records, and SPF configurations.
- VirusTotal: For analyzing attachments and checking for malware or malicious payloads.
- dmarcian: For checking the DMARC records and understanding email authentication practices.
- Email Source Code Analysis: To extract email header details, including originating IP address and Return-Path domain.

## Perform Analysis

- VirusTotal
<p align="center">
<img src="https://imgur.com/IeY54C5.png" height="40%" width="40%" alt="Device Specification"/>
<br/>
<b>Instead of uploading the actual file, Use its hash value.</b>
<br/>

<p align="center">
<img src="https://imgur.com/yF7ypdf.png" height="40%" width="40%" alt="Device Specification"/>
<br/>
<b>VirusTotal is a powerful tool for malware analysis, offering extensive capabilities to uncover detailed information based on what we're seeking. By searching for a hash, it provides a reputation score and other relevant data to help quickly assess the file's nature.</b>
<br/>

## Outcome

- Improved Email Security Awareness:
  - Identify phishing attempts effectively and take proactive steps to prevent them.
  - Enhanced understanding of how email security protocols (SPF, DMARC) help protect against spoofing and phishing attacks.
 
- Hands-on Experience with Cybersecurity Tools:
  - Gaining practical experience with OSINT tools to investigate and validate suspicious communications in real-world scenarios.
 
- Effective Use of Incident Response Protocols:
  - Understand the importance of working with a SOC and following organizational protocols when encountering potential threats.

- Practical Understanding of Attachment Threats:
  - Evaluate email attachments for signs of malware to prevent possible infections.

- Real-World Application of Cybersecurity Concepts:
  - By engaging in a practical challenge, apply cybersecurity concepts such as phishing identification, email header analysis, and attachment investigation, to prepare for real-world cybersecurity tasks.

## Acknowledgements
- [TryHackMe - The Greenholt Phish](https://tryhackme.com/r/room/phishingemails5fgjlzxc)
- [Whois](https://www.whois.com/whois/)
- [MxToolBox](https://mxtoolbox.com/SuperTool.aspx)
- [VirusTotal](https://www.virustotal.com/gui/home/search)
- [dmarcian](https://dmarcian.com/dmarc-inspector/)
