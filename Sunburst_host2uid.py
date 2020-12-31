# ## About

# Sunburst victime host sent DNS query to known C2 servers, such as the one below:

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

def concat_string(MAC,Domain,GUID):
    """
    Create a string as concatenation of 3 parts.

    """
    concat_string = MAC.replace('-','').strip()+Domain.strip()+GUID.strip()
    return concat_string

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
    host_UID_list=[]
    with open(sys.argv[1],'r') as f1:
        for line in f1:
            temp=[]
            fields=line.split(',')
            host=fields[0]
            input_string=concat_string(fields[1],fields[2],fields[3])
            md5value=string_md5(input_string)
            xored= xor_calc(md5value)
            with open(sys.argv[2],'r') as f2:
                for id in f2:
                    if id.strip().upper() == xored.strip().upper():
                        temp.append(host)
                        temp.append(input_string)
                        temp.append(md5value)
                        temp.append(xored)
                        host_UID_list.append(temp)
    if len(host_UID_list) > 0:
        for i in host_UID_list:
            print(i)
    else:
        print('Process finished, nothing found.')

if __name__ == '__main__':
    main()
