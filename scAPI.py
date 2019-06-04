import requests
import json
import os
import sys
import urllib3

#environmental variables
imagetag=os.environ.get("IMAGETAG")
buildid=os.environ.get("BUILD_ID")
high_t=os.environ.get("HIGH")
medium_t=os.environ.get("MEDIUM")
low_t=os.environ.get("LOW")
negligible_t=os.environ.get("NEGLIGIBLE")
unknown_t=os.environ.get("UNKNOWN")
user=os.environ.get("USER")
password=os.environ.get("PASSWORD")

def requestToken():
    url = "https://a04730514863e11e9a62f028cbc55794-1947050687.us-west-2.elb.amazonaws.com/api/sessions"
    headers = {'Content-Type': 'application/json', 'X-API-Version': '2018-05-01'}
    data = {'user': {'userID': 'administrator', 'password': 'Trendmicr0!'}}

    try:
        response = requests.request("POST", url, json=data, headers=headers, verify=False)
    except requests.exceptions.RequestException as e:
        print (e)
        sys.exit(1)

    return response.json()['token']

def requestScan():
    url = "https://a04730514863e11e9a62f028cbc55794-1947050687.us-west-2.elb.amazonaws.com/api/scans"
    data = {"source": {
        "type": "docker",
        "registry": "https://786395520305.dkr.ecr.us-west-2.amazonaws.com",
        "repository": "test/apachestruts",
        "tag": 'latest',
        "credentials": {"aws": {"region": "us-west-2"}}},
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
    data = {"text": "!!! Scan results !!! \n"+"Image: "+imagetag+'-'+buildid+"\n"+message}
    headers = {'Content-Type': 'application/json'}

    try:
        response = requests.request("POST", url, json=data, headers=headers)
    except requests.exceptions.RequestException as e:
        print (e)
        sys.exit(1)

def createWebHook():
    requests.packages.urllib3.disable_warnings()
    url = "https://a04730514863e11e9a62f028cbc55794-1947050687.us-west-2.elb.amazonaws.com/api/webhooks"
    data = { "name": "Test WebHook descriptive string",
              "hookURL": "https://a04730514863e11e9a62f028cbc55794-1947050687.us-west-2.elb.amazonaws.com/",
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

def requestReport():
    requests.packages.urllib3.disable_warnings()
    high, medium, low, negligible, unknown = 0, 0, 0, 0, 0
    status='pending'

    url = "https://a04730514863e11e9a62f028cbc55794-1947050687.us-west-2.elb.amazonaws.com/api/scans/"
    headers = {'Authorization': 'Bearer'+requestToken(), 'X-API-Version': '2018-05-01'}
    querystring = {"id": requestScan(),"expand":"none"}

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

    if(status == "completed-with-findings" ):
        findings = data['scans'][0]['findings']
        vulnerabilities = findings['vulnerabilities']

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

requestReport()
