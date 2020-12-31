# Sunbusrt_host2uid

Python script to match Sunburst victim host to unique ID decoded from c2 DNS query.

## About

Sunburst victime host sent DNS query to known C2 servers, such as the one below:

	"05q2sp0v4b5ramdf71l7.appsync-api.eu-west-1.avsvmcloud.com"

Many security reasearchers have been able to decode the first part of the DGA strings, such as "05q2sp0v4b5ramdf71l7". The decoded information contains 2 parts:

1. The full internal domain names of infected victim organizations, such as “victim.com”
2. The unique ID of infected host within the victim organizations

During investigation, victim organizations might have difficulties to identify which exact host sent those queries among possibly affected servers due to many reasons.

As long as DFIR analysts have those DNS queries, they can run many other available tools in the reference links in the "Acknowledgments" section to decode UID for possible victim host.
Then analysts can collect 3 pieces of information for each affected servers and then run the script to identify which exact host sent which DNS query in question, hopefully facilitate the investigation.

This script takes 2 input files in the order below and print any matching host name if found.

1. host_info_file - a csv file with all suppected hosts information, which contains 4 fields in the order below, one host per line.
    1) Host name:
		example: "computername"
	  2) The 1st or default operational network interface's MAC address as the format below:
		example: "00-01-02-AA-BB-CC"
    3) Computer domain name:
		example: "domain.com"
    4) UUID created by Windows from registry key "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography"
		example: "10d6a2c0-4857-42c9-b862-35c7547f945e"
	Example of one line: "computername,00-01-02-AA-BB-CC,domain.com,10d6a2c0-4857-42c9-b862-35c7547f945e"

2. UID_file - a csv file with UID decoded from subdomain strings, one UID per line:
		example: "F5D6AA262381B084"

## Usage
   
1. Collect MAC address, domain name and Windows registry vule as described above to make the host_info_file.
2. Use any tool(SunburstDomainDecoder.exe or decode_dga.py) referenced in the  "Acknowledgments" section to make the UID_file.
3. Run command below in Windows with Python 3:
	py -3 "pathtoscript\Sunburst_host2uid.py" "pathtoinputfile\host_info_file.csv" "pathtoinputfile\UID_file.csv"

4. The script will print out host name, concatented strings, md5 hash and UID if matches were found.

Happy hunting!
   

## Acknowledgments

https://www.netresec.com/?page=Blog&month=2020-12&post=Reassembling-Victim-Domain-Fragments-from-SUNBURST-DNS
https://github.com/asuna-amawaka/SUNBURST-Analysis

