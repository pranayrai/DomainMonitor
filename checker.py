# This script is for Domain Monitoring. If scheduled on a cron schdule, this will check for
# the domain owner, DNS servers, and domain expiry date. If there is any change, it will notify
# the respective authority so that they can verify the change.


import sys
import whois
import csv
import tld
import dns.resolver
import collections

if(len(sys.argv)==1):
    print('Missing argument')
elif(len(sys.argv)==2):
    url=sys.argv[1]

# url = 'https://uvic.ca'

if('http' not in url or 'https' not in url):
    url = 'http://' + url
url = tld.get_tld(url, as_object=True).fld


answers = dns.resolver.query(url, 'NS')
servers = []
for server in answers:
    servers.append(server)



d = whois.whois(url)
myData = [[url,''.join(str(x + ' ') for x in d.registrant_name), d.expiration_date, ''.join(str(x) + ' ' for x in servers)]]
#print(myData)
word = ''.join(str(x + ' ') for x in d.registrant_name)
nslookup = ''.join(str(x) + ' ' for x in servers)

url_present=False
owner_same=True
expiration_date_same=True
nslookup_same = True


with open('domaincheck.csv') as File:
    reader = csv.reader(File, delimiter=',', quotechar=',', quoting=csv.QUOTE_MINIMAL)
    writer = csv.writer(File)
    for row in reader:
        if url == row[0]:
            url_present=True
            print(url + ' found. Checking previous records')
            #print((nslookup.split()))
            #print((row[3].split()))
            #print(collections.Counter((nslookup.split())) == collections.Counter((row[3].split())))
            if(str(d.expiration_date) in row and word in row and collections.Counter((nslookup.split())) == collections.Counter((row[3].split()))):
                print('No need to alert')
                break
            elif(str(d.expiration_date) not in row):
                expiration_date_same=False
                writer.writerows('')
                print('Expiry changed: Alert')
            elif(word not in row):
                owner_same=False
                print('Owner changed: Alert')
            elif(collections.Counter((nslookup.split())) == collections.Counter((row[3].split()))):
                nslookup_same=False
                print('DNS Servers changed: Alert')
            if(expiration_date_same==False or owner_same==False or nslookup_same==False):
                with open('domaincheck.csv', 'r') as f:
                    data=list(csv.reader(f))
                for rows in data:
                    if(url in rows[0]):
                        data.remove(rows)
                with open('domaincheck.csv', 'w', newline='') as out_f:
                    w = csv.writer(out_f)
                    w.writerows(data)
                    w.writerows(myData)
        else:
            continue

    if(url_present==False):
        print('New Entry:' + url)
        myFile = open('domaincheck.csv', 'a', newline='')
        with myFile:
            writer = csv.writer(myFile)
            writer.writerows(myData)
        myFile.close()

# myFile = open('domaincheck.csv', 'a', newline='')
# with myFile:
#     writer = csv.writer(myFile)
#     writer.writerows(myData)

