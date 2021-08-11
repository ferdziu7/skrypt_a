import re
import requests
import math
from urllib.request import urlopen
import ssl

# url = "https://wp.pl"
# uf = urlopen(url, context=ssl._create_unverivied_context())
# html = str(uf.read())

# ### write to file from url
# with open('ip.txt') as f:
#     html = f.read()
# html = str(html)
# ###

file = open('ip.txt', 'r')
count = 0
iplist = []
rules = []

open('/etc/suricata/rules/local.rules', 'w').close()

while True:
    
    line = file.readline()
    if not line:
        break
    #iplist.append(line)
    rules.append(line)
    count += 1

file.close()

liczbaip = 200

liczbaregul = count/liczbaip
liczbaregul = math.floor(liczbaregul)

reszta =count%liczbaip

if reszta > 0:
    liczbaregul += 1

tmp_list=[]


for i in range(liczbaregul):
    j = i * liczbaip
    tmp_list = []
    for j in range(j,j+liczbaip):
        if j >= count:
            break
        tmp_list.append(rules[j])
    #print("Rule nr {} [{}]".format(i,tmp_list))    
    tmp_list=[s.replace('\n',"") for s in tmp_list]

    listToStr = ','.join([str(elem) for elem in tmp_list])
    text_file = open("/etc/suricata/rules/local.rules","a")
    text_file.write("\nalert ip any any -> [{}".format(listToStr) + "] any (msg:\"IP\"; sid:{};rev: 1234;)".format(i+1))
    text_file.close()
    #print(listToStr)    

    

#iplist=[s.replace("'","") for s in iplist]
#remove ''\n
#print(iplist)
#print(', '.join(iplist))

#(', '.join(iplist))
#print(iplist[0])


# for i in iplist:

#print ("alert ip any any -> [{}".format(listToStr) + "] any  (msg:\"IP\";)")


# file=str.file
# file = file.replace("\n",",")
# print(file)
