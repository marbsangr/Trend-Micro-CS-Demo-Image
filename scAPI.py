import requests
import json
import os
import sys
import urllib3

#environmental variables
"""
imagetag=os.environ.get("IMAGETAG")
buildid=os.environ.get("BUILD_ID")
high_t=os.environ.get("HIGH")
medium_t=os.environ.get("MEDIUM")
low_t=os.environ.get("LOW")
negligible_t=os.environ.get("NEGLIGIBLE")
unknown_t=os.environ.get("UNKNOWN")
user=os.environ.get("USER")
password=os.environ.get("PASSWORD")
"""
imagetag='apache'
buildid='12'
high_t=1
medium_t=5
low_t=1
negligible_t=10
unknown_t=5
user='administrator'
password='Trendmicr0!'

layers=[]

def requestToken():
    url = "https://af827c5f3b55511e999e702493d213d9-1499995079.us-east-2.elb.amazonaws.com/api/sessions"
    headers = {'Content-Type': 'application/json', 'X-API-Version': '2018-05-01'}
    data = {'user': {'userID': 'administrator', 'password': 'Piloto01..'}}

    try:
        response = requests.request("POST", url, json=data, headers=headers, verify=False)
    except requests.exceptions.RequestException as e:
        print (e)
        sys.exit(1)

    return response.json()['token']

def requestScan():
    url = "https://af827c5f3b55511e999e702493d213d9-1499995079.us-east-2.elb.amazonaws.com/api/scans"
    data = {"source": {
        "type": "docker",
        "registry": "https://946007956850.dkr.ecr.us-west-2.amazonaws.com/bsecure",
        "repository": "bsecure",
        "tag": 'latest',
        "credentials": {"aws": {"region": "us-east-2"}}},
        "webhooks": [{
        "hookURL": createWebHook()}]}
    headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer'+requestToken(), 'X-API-Version': '2018-05-01'}
    try:
        response = requests.request("POST", url, json=data, headers=headers, verify=False)
    except requests.exceptions.RequestException as e:
        print (e)
        sys.exit(1)
    return response.json()['id']

def sendToSlack(message):
    url = 'https://hooks.slack.com/services/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'
    data = {"text": "!!! Scan results !!! \n"+"Image: (test) "+imagetag+'-'+buildid+"\n"+message}
    headers = {'Content-Type': 'application/json'}

    try:
        response = requests.request("POST", url, json=data, headers=headers)
    except requests.exceptions.RequestException as e:
        print (e)
        sys.exit(1)

def createWebHook():
    requests.packages.urllib3.disable_warnings()
    url = "https://af827c5f3b55511e999e702493d213d9-1499995079.us-east-2.elb.amazonaws.com/api/webhooks"
    data = { "name": "Test WebHook descriptive string",
              "hookURL": "https://af827c5f3b55511e999e702493d213d9-1499995079.us-east-2.elb.amazonaws.com/",
              "secret": "tHiSiSaBaDsEcReT",
              "events": [
                "scan-requested"
              ]
            }
    headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer'+requestToken()}
    try:
        response = requests.request("POST", url, json=data, headers=headers, verify=False)
    except requests.exceptions.RequestException as e:
        print (e)
        sys.exit(1)
    return response.json()['hookUrl']

def writeToJSONFile(path, fileName, data):
    filePathNameWExt = './' + path + '/' + fileName + '.json'
    with open(filePathNameWExt, 'w+') as fp:
        json.dump(data, fp)

def getVulnLayers(scanId):
    print(scanId)
    k=0
    dataVulnUn = ""
    message = ""
    requests.packages.urllib3.disable_warnings()
    url = "https://af827c5f3b55511e999e702493d213d9-1499995079.us-east-2.elb.amazonaws.com/api/scans/"
    headers = {'Authorization': 'Bearer'+requestToken(), 'X-API-Version': '2018-05-01'}
    querystring = {"id": scanId,"expand":"all"}
    try:
        response = requests.request("GET", url, headers=headers, params=querystring, verify=False)
        lastScan = len(response.json()['scans'])-1
        dataTmp = response.json()['scans'][lastScan]['details']['results'];

        writeToJSONFile('./','datatotal',dataTmp)
    except requests.exceptions.RequestException as e:
        print (e)
        sys.exit(1)
    for dataT in dataTmp:
        writeToJSONFile('./','datatotal',dataT['findings']['vulnerabilities']['total'])
        if len(dataT['findings']['vulnerabilities']['total']) > 0:
                layerID = dataT['id']
                url = "https://af827c5f3b55511e999e702493d213d9-1499995079.us-east-2.elb.amazonaws.com/api/scans/"+scanId+"/layers/"+layerID+"/vulnerabilities/"
                headers = {'Authorization': 'Bearer'+requestToken(), 'X-API-Version': '2018-05-01'}
                querystring = {"expand":"all"}
                try:
                    response = requests.request("GET", url, headers=headers, params=querystring, verify=False)
                    dataVulnUn = ""
                    vulnerabilitiesForLayer=response.json()['vulnerabilities']
                    if(len(response.json()['vulnerabilities']) > 0):
                        print(len(response.json()['vulnerabilities']))
                        vulnerabilities = response.json()['vulnerabilities'][0]['vulnerabilities']
                        message += response.json()['vulnerabilities'][0]['name'] + ": \n"
                        for value in vulnerabilities:
                            if value['severity'] == 'high':
                                k+=1
                                dataVulnUn += value['name'] + ".\n"
                                message += dataVulnUn +";"
                                #writeToJSONFile('./','datatotal {}'.format(k),response.json())
                    sendToSlack(message)
                except requests.exceptions.RequestException as e:
                    print (e)
                    sys.exit(1)

def requestReport():
    requests.packages.urllib3.disable_warnings()
    high, medium, low, negligible, unknown = 0, 0, 0, 0, 0
    status='pending'

    url = "https://af827c5f3b55511e999e702493d213d9-1499995079.us-east-2.elb.amazonaws.com/api/scans/"
    headers = {'Authorization': 'Bearer'+requestToken(), 'X-API-Version': '2018-05-01'}
    querystring = {"id": requestScan(),"expand":"all"}

    while status != "completed-with-findings":
        try:
            response=requests.request("GET", url, headers=headers,params=querystring,verify=False)
        except requests.exceptions.RequestException as e:
            print (e)
            sys.exit(1)

        status = response.json()['scans'][0]['status']

        if (status == "completed-no-findings"):
            break

        if status == 'failed':
            print("Scan failed!")
            sys.exit(1)

    data = response.json()
    print(len(data['scans'][0]['details']['results']))
    getVulnLayers(data['scans'][0]['details']['results'],data['scans'][0]['id'])

    if(status == "completed-with-findings" ):
        findings = data['scans'][0]['findings']
        vulnerabilities = findings['vulnerabilities']
        #print(data['scans'][0]['details']['results'][0])
        #layers.append(data['scans'][0]['details']['results'][0])
        dataVuln = "Vulnerabilities found: \n"
        dataMalw = ""

        for value in vulnerabilities['total']:
            if value == 'high':
                high = vulnerabilities['total']['high']
                dataVuln = dataVuln+"High: "+str(high)+"\n"
            if value == 'medium':
                medium = vulnerabilities['total']['medium']
                dataVuln = dataVuln+"Medium: "+str(medium)+"\n"
            if value == 'low':
                low = vulnerabilities['total']['low']
                dataVuln = dataVuln+"Low: "+str(low)+"\n"
            if value == 'negligible':
                negligible = vulnerabilities['total']['negligible']
                dataVuln = dataVuln+"Negligible: "+str(negligible)+"\n"
            if value == 'unknown':
                unknown = vulnerabilities['total']['unknown']
                dataVuln = dataVuln+"Unknown: "+str(unknown)+"\n"

        if dataVuln == "Vulnerabilities found: \n": dataVuln=""

        for value in findings:
            if value == 'malware':
                malware = findings['malware']
                dataMalw = "Malware found: "+str(malware)

        message = dataVuln+dataMalw

    if (high <= int(high_t)) and (medium <= int(medium_t)) and (low <= int(low_t)) and (negligible <= int(negligible_t)) and (unknown <= int(unknown_t) and (malware < 1)):
        sys.stdout.write('1')
        message = "Image is clean and ready to be deployed!"

    sendToSlack(message)

getVulnLayers('002653a1-0406-495e-8b11-7eb25fa20c38')
