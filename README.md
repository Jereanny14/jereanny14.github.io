# jereanny14.github.io

# Digital-security-in-company´s
About this proyect is about the cybersecurity in company´s, how ciberatacks be a problem a how we can avoid them.
 Just as the subtitle says, we will cover these topics, like hacking examples in Costa Rica, general problems for safe datas and the use about software or malware
The objetives about this proyect is make a awarness for protec the data for our company´s and the people be more interested in this tipe of things.

# Now we can continue in this invetigation.
According to the original research, the main question is the following: ¿what is the benefit of having updated and protected equipment for the proper functioning of the company?
Analyzing the data personally and also based on investigations, the most common thing for this response is to hire specialized personnel in the protection of this information and constantly review if it is in danger👾.
But, I decided to look for a different answer than the current one and learn about other aspects, that's where thanks to a cybersecurity manager (who will remain anonymous out of respect for data privacy) from a local clinic who helped me collect different data. And more interesting, given this, I asked him the main question where he answered the following: "It is no secret to anyone that the globalization of communications, so it is possible to find large corporate networks that are part of the Internet or the dark net or deep web,(meaning databases that are not visible through traditional browsers and other type of somewhat obscure information), in addition to encountering people who take advantage of these communications to commit crimes, scamming or robbing unsuspecting people, or demanding money after a hack, as was the recent case of the CCSS and the Ministry of Finance. In order to minimize risks, one of the good practices is to have the computer equipment updated in two ways, one at the software level and the other at the hardware level.

Software Level:
All software is made by humans, therefore all software can be violated, the more known the software is, the more likely it is to be analyzed in order to find flaws and use these flaws to carry out attacks, for the above reasons and with the aim To maintain business prestige, software production companies pay prizes to people not related to the company, when they find a fault, of course they also have their teams of specialists. Fault detections, also known as backdoors, generate what are known as patches, some in computer security (eliminate those detected faults), other patches help improve the performance of computers, servers, and communications equipment.Because software production is a trade, software production companies.They also present new versions, leaving previous versions obsolete and unsupported.Technically, known cases are the different versions of Windows (Windows 95, ME, Vista,XP, 7, 8, 8.1, 10, 11) versions lower than 10 are no longer supported so make use of them can pose a great risk, although also because they represent a very small segment of use, probably not of interest for attacksncurrent cybernetics. All of the above is valid for cell phones.

Hardware Level:
Companies must try to have their hardware updated in order to use the newer software, outdated hardware means that it can only be used unsupported software, software for which security patches will not be created.

# Now i going to show you some hacking examples. 🔐
(warning dont enter in the links pliss and thx) 

Example 1🔊

Deloitte.

Incident

CVE-2023-46604: Vulnerability in Apache ActiveMQ is being actively exploited

ID: m-u6q4sBkSnY7hhsg]fo |
Category: Potential cyber attack |
Type: IA-VI |
Risk level: Critical | Date
validation: 07-11-2023 |
Tags: Vulnerability Intelligence, Global
Summary
Impact: Remote code execution.
Apache released security patches to mitigate the CVE-2023-46604 vulnerability that is being actively exploited.This flaw affects ActiveMQ, a message broker that allows communication between clients and servers through protocols such as: AMQP, MQTT, OpenWire and STOMP; which is why it is used in multiple implementations.On the other hand, Rapid7 assures that the vulnerability has been exploited to spread the Hellokitty ransomware, however, the details are unknown, we will continue to follow up and complementary reports will be issued as soon as additional information is available.

Vulnerability details
• CVE asoclado: CVE-2023-46604
Severity: Critical
Category (CWE): CWE-502
• Execution vector: Remote

Description: Vulnerability due to the software performing the deserialization process without verifying the origin of the data received through the OpenWire protocol, which could allow an attacker to execute malicious code on the system.
⚫ Vulnerable technology:
• ActiveMQ, versions: 5.8.0-5.15.15, 5.16.05.16.6, 5.17.05.17.5, 5.18.0 - 5.18.2
• ActiveMQ Legacy OpenWire Module, versions: 5.8.0-5.15.15, 5.16.0 - 5.16.6, 5.17.0 - 5.17.5, 5.18.05.18.2
⚫ Manufacturer: Apache
• PoC available: Yes
• Exploit available: Yes
• Active exploitation: Yes
• Mitigation: Install security patch
• Workaround: N/A
Affected assets
The vulnerable technology is not found in the provisioning file, however, it is commonly used to carry out the operation in organizations, so it could represent a risk.
If you have this technology, please update the provisioning file.
recommendations:
In order to mitigate the associated risks, the Deloitte Mexico cyber intelligence team recommends the following:
1. Install security patches and follow the mitigation guide issued by Apache as soon as possible.
2. Deploy indicators of compromise (IoCs) in security tools:
• Host IoCs can be enabled in anti-malware tools, HIDS or endpoint solutions with centralized console management.
• The network IoCs provided can be deployed in tools such as Firewall,IDS, Web content filtering, UTMs, network proxy.
Commitment Indicators

To view the compromise indicators, consult the file in DISP: "IoCs_CVE-2023- 46604 07.11.2023.xlsx", in addition, they will be shared through the MISP platform so that they can be consumed in an automated manner.
Referenclas:

1. https://www.cyber.gc.ca/en/alerts-advisories/apache-security-advisory-av23-669

2. https://activemq.apache.org/security-advisories.data/CVE-2023-46604

3. https://activemq.apache.org/components/classic/download/

4. https://nvd.nist.gov/vuln/detail/CVE-2023-46604

5. https://www.bleepingcomputer.com/news/security/3-000-apache-activemq-servers-vulnerable- to-rce-attacks-exposed-online/

6. https://www.shadowserver.org/what-we-do/network-reporting/accessible-activemq-service- report/

7. https://www.rapid7.com/blog/post/2023/11/01/etr-suspected-exploitation-of-apache- activemq-cve-2023-46604/

8. https://socradar.io/critical-rce-vulnerability-in-apache-activemq-is-targeted-by-hellokitty- ransomware-cve-2023-46604/

9. https://deepkondah.medium.com/unpacking-the-apache-activemq-exploit-cve-2023-46604-92ed1c125b53 (POC)

10. https://github.com/X1r0z/ActiveMQ-RCE (exploit)

Related posts

• N/A

CLASSIFICATION: DELOITTE CONFIDENTIAL: This report and its attachments (if any) are intended solely for the use of the recipient hereof. If you are not the intended recipient of this message, you are prohibited from reading, disclosing, reproducing, distributing, disseminating, or otherwise using this transmission. Delivery of this message to any person other than the intended recipient is not intended to waive any right or privilege. If you have received this message in error, please
promptly notify the sender by reply e-mail and immediately delete this message from your system. Deloitte refers to one or more of Deloitte Touche Tohmatsu
Limited ("DTTL"), its global network of member firms and their related entities. DTTL (also referred to as "Deloitte Global") and each of its member firms are legally
separate and independent entities. DTTL does not provide services to clients, Please see www.deloitte.com/about to learn more. This report and its attachments (if
any) are provided by the Deloitte entity within the Deloitte network that Your Company has entered into an agreement with, and such agreement governs the
provision and use of this report and its attachments (if any). "Your Company" means the company, organization, or other legal entity that you work for as a partner,
principal, director, employee, or contractor and any affiliates thereof. This report and its attachments (if any) contain general information only, and none of Deloitte
Touche Tohmatsu Limited, its member firms or their related entities (collectively, the "Deloitte network") is, by means of this report and its attachments (if any).
rendering professional advice or services. Before making any decision or taking any action that may affect your finances or your business, you should consult a
qualified professional adviser. No entity in the Deloitte network shall be responsible for any loss whatsoever sustained by any person who relies on this report and its
attachments.© 2023

Example 2 🔊
MINISTRY OF SCIENCE, INNOVATION, TECHNOLOGY AND TELECOMMUNICATIONS
GOVERNMENT OF COSTA RICA

TECHNICAL ALERT MICITT-DGDCFD-DRII-AT-366-2023
TLP:CLEAR
Vulnerability found in Google Chrome
It is communicated to the Directors/Heads of Information Technology and the Cybersecurity liaisons, so that they can take the necessary measures. Google has released an emergency security update to address the fifth Chrome zero-day vulnerability, which has been exploited in attacks since the beginning of the year. The company issued a security advisory, noting that it is aware of the existence of an exploit for the CVE-2023-5217 vulnerability used by different security actors.
threats.
CVE-2023-5217
It is due to a heap-based buffer overflow weakness in the VP8 encoding of the open-source video codec library libvpx. Its consequences can vary from
•⚫ Remote code execution.
• Denial of service.
⚫ App lock.
Impact: High
Affected resources Google Chrome
⚫ Versions prior to 118.0.5993.117/.118 for Windows.
⚫ Versions prior to 118.0.5993.117 for Mac and Linux.
recommendations
• Update Google Chrome to the latest version, on Windows, Linux and Mac operating systems
• Update Google Chrome to the latest version, on all devices.
Be attentive to new updates issued by the company.
TLP:CLEAR
CSIRT-CR
WWW.MICITT.GO.CR
References:
Google. (24 octubre, 2023) Stable Channel update for desktop. Chrome Releases.

https://chromereleases.googleblog.com/2023/10/stable-channel-update-for- desktop 24.html

Google. (October 27, 2023.). Chrome Releases. Chrome Releases.

https://chromereleases.googleblog.com/search/label/Desktop%20Update+

Google. (October 25, 2023). Chrome Releases. Chrome Releases.

https://chromereleases.googleblog.com/search/label/Stable%20updates

Resolved vulnerability in Google Chrome (AL01/231025/CSIRT-ITA). (October 25, 2023.).

https://www.csirt.gov.it/contenuti/risolta-vulnerabilita-in-google-chrome- al01-231025-csirt-ita

In case of any questions or queries, you can contact the CSIRT-CR by email csirt@micitt.go.cr

TLP:CLEAR
CSIRT-CR
WWW.MICITT.GO.CR

# Conclusions 
Now we now how 1 or more peron can be a seriusly problem the diferents recomendaions, now my personal recomendation is dont share your personal information and dont trust in suspechos web sites.
     

In this proyect i using the internet and others sites, all information is legal and it is whith educational endings.
the tipe of analisis i use is a prescritip analisis i use pasta datad whit recentli datas tofound many solutions.
this proyect is ended an publish.
                                                                             
                                                          #CREDITS
                                       All the persons help me with that investigation.
                                       My father for the greats ideas, he bring me. 
                                        and Jereannny the creator of this web site
