# ## About

# Sunburst victime host sent DNS query to resolve known C2 servers, such as the one below:

# 	"05q2sp0v4b5ramdf71l7.appsync-api.eu-west-1.avsvmcloud.com"

# Many security reasearchers have been able to decode the first part of the DGA strings, such as "05q2sp0v4b5ramdf71l7". The decoded information contains 2 parts:

# 1. The full internal domain names of infected victim organizations, such as “victim.com”
# 2. The unique ID of infected host within the victim organizations

# During investigation, victim organizations might have difficulties to identify which exact host sent those queries among possibly affected servers due to many reasons.

# As long as DFIR analysts have those DNS queries, they can run many other available tools in the reference links in the "Acknowledgments" section to decode UID for possible victim host.
# Then analysts can collect 3 pieces of information for each affected servers and then run the script to identify which exact host sent which DNS query in question, hopefully facilitate the investigation.

# This script takes 2 input files in the order below and print any matching host name if found.

# 1. host_info_file - a csv file with all suppected hosts information, which contains 4 fields in the order below, one host per line.
#     1) Host name:
# 		example: "computername"
# 	  2) The 1st or default operational network interface's MAC address as the format below:
# 		example: "00-01-02-AA-BB-CC"
#     3) Computer domain name:
# 		example: "domain.com"
#     4) UUID created by Windows from registry key "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography"
# 		example: "10d6a2c0-4857-42c9-b862-35c7547f945e"
# 	Example of one line: "computername,00-01-02-AA-BB-CC,domain.com,10d6a2c0-4857-42c9-b862-35c7547f945e"

# 2. UID_file - a csv file with UID decoded from subdomain strings, one UID per line:
# 		example: "F5D6AA262381B084"

# ## Usage
   
# 1. Collect MAC address, domain name and Windows registry vule as described above to make the host_info_file.
# 2. Use any tool(SunburstDomainDecoder.exe or decode_dga.py) referenced in the  "Acknowledgments" section to make the UID_file.
# 3. Run command below in Windows with Python 3:
# 	py -3 "pathtoscript\Sunburst_host2uid.py" "pathtoinputfile\host_info_file.csv" "pathtoinputfile\UID_file.csv"

# 4. The script will print out host name, concatented strings, md5 hash and UID if matches were found.

import hashlib
import sys

def input_string(inputfile):
    """
    Create a intermediate list of 2-item lists, whose 1st item is host name
    and the 2nd item is concatenation of 3 parts.

    """
    results=[]

    with open(inputfile,'r') as f:
        for line in f:
            # temp list to hold host and concatenation of 3 parts.
            temp=[]
            fields=line.split(',')
            Host=fields[0].strip()
			# append host name as the 1st item
            temp.append(Host)
            MAC=fields[1].replace('-','').strip()
            Domain=fields[2].strip()
            GUID=fields[3].strip()
			# append concatenation of 3 parts as the 2nd item
            temp.append(MAC+Domain+GUID)
			# append every host to the master list
            results.append(temp)

    return results

def string_md5(str):
    m= hashlib.md5()
    m.update(str.encode('utf-8').strip())
    return m.hexdigest()

def xor_calc(md5):
    s1=md5[:16]
    s2=md5[16:]
    a1=bytearray.fromhex(s1)
    a2=bytearray.fromhex(s2)
    for i in range(len(a1)):
        a1[i] ^= a2[i]
    return a1.hex()

def main():
    parsed_string=input_string(sys.argv[1])
    host_UID_list=[]
    for item in parsed_string:
        temp=[]
        host=item[0]
        temp.append(host)
        temp.append(item[1])
        md5value=string_md5(item[1])
        xored= xor_calc(md5value)
        temp.append(md5value)
        temp.append(xored)
        host_UID_list.append(temp)

    with open(sys.argv[2],'r') as f:
        for id in f:
            for host in host_UID_list:
                if id.strip().upper() == host[3].upper():
                    print('--------------Match found!!!----------')
                    print(host)

if __name__ == '__main__':
    main()
