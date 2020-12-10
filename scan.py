#!/usr/bin/env python3
#
# Copyright 2019 Trend Micro and contributors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

from __future__ import print_function

import argparse
import base64
import os
import sys
import json
import time

import requests

from docker_image import reference

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


class SlightlyImprovedSession(requests.Session):
    """
    A SlightlyImprovedSession keeps track of the base URL and any kwargs that
    should be passed to requests.

    When you make a `get` or `post` request, the URL you provide will be
    `urljoin`'d with the base URL, so relative URLs will work pretty well.

    Technically, this is totally broken, because relative URLs should be
    evaluated relative to the resource that provided the URL, but for our
    purposes this works perfectly and really simplifies life, so we're
    going to ignore the pedants.
    """

    def __init__(self, base, **kwargs):
        super(SlightlyImprovedSession, self).__init__()
        self.base = base
        self.kwargs = kwargs

    def post(self, url, **kwargs):
        for k in self.kwargs:
            if not k in kwargs:
                kwargs[k] = self.kwargs[k]

        return super(SlightlyImprovedSession, self).post(
            requests.compat.urljoin(self.base, url),
            **kwargs
        )

    def get(self, url, **kwargs):
        for k in self.kwargs:
            if not k in kwargs:
                kwargs[k] = self.kwargs[k]

        return super(SlightlyImprovedSession, self).get(
            requests.compat.urljoin(self.base, url),
            **kwargs
        )


def get_session(base, user, password, **kwargs):
    """Authenticate with the service and return a session."""

    session = SlightlyImprovedSession(base, **kwargs)

    response = session.post('/api/sessions', json={
        'user': {
            'userID': user,
            'password': password
        }
    })

    if not response.ok:
        raise Exception(f'could not start session: {response}')

    token = response.json()['token']

    session.headers.update({'Authorization': f'Bearer {token}'})
    return session

def eprint(*args, **kwargs):
    """print a message to stderr"""
    print(*args, file=sys.stderr, **kwargs)


def start_scan(session, ref,
               image_pull_auth=None,
               registry_root_cas=None,
               webhook_teams=None,
               insecure_skip_registry_tls_verify=False,
               wait=True):
    """Start a scan."""

    ref = reference.Reference.parse(ref)

    hostname, name = ref.split_hostname()
    print (ref)
    print(hostname)
    print(name)

    if isinstance(image_pull_auth, str):
        try:
            image_pull_auth = json.loads(image_pull_auth)
        except json.decoder.JSONDecodeError as err:
            eprint('Unable to parse image-pull-auth value:', err)
            sys.exit(1)

    if registry_root_cas is not None:
        with open(registry_root_cas) as file:
            registry_root_cas = base64.b64encode(
                file.read().encode()
            ).decode('utf-8')
    
    registry_aux = session.get('/api/registries')
    
    print ("registries")
    
    for registry in registry_aux.json()["registries"]:
        print(registry["host"])
        print("|||")
        print(hostname)
        if(registry["host"] == hostname):
            registry_id = registry["id"]

    if(image_pull_auth == "None"):
        response = session.post('/api/scans',
                                json={
                                    'name': name,
                                    'source': {
                                        'type': 'docker',
                                        'registry': hostname,
                                        'repository': name,
                                        'tag': ref['tag'],
                                        'digest': ref['digest'],
                                        'credentials': image_pull_auth,
                                        'rootCAs': registry_root_cas,
                                        'insecureSkipVerify': insecure_skip_registry_tls_verify,
                                    }
                                })
    else:
        print("*************")
        print(registry_id)
        response = session.post("/api/registries/"+registry_id+"/scans",
                                json={
                                    "name": name,
                                    "source": {
                                        "repository": name,
                                        "tag": ref["tag"],
                                    }
                                })
        
    if not response.ok:
        eprint('could not create scan', response)
        sys.exit(1)

    scan = response.json()
    print (scan)
    print ("////////////////7")
    if wait:
        while scan['status'] in ['pending', 'in-progress']:
            print('waiting for scan to complete...', file=sys.stderr)
            time.sleep(10)

            response = session.get(scan['href'])

            if not response.ok:
                eprint('could not check scan progress', response)
                sys.exit(1)

            scan = response.json()
    if(webhook_teams != "None"):
        sendToTeams(webhook_teams, scan, ref, hostname, name)

    print(json.dumps(scan, indent='  '))

def sendToTeams(webhook_teams, scan, ref, hostname, name):
    
    if(scan['status'] == "completed-with-findings" ):
        print("Content-with-findings")
        findings = scan["details"]['results']
        
        for find in findings:
            print("FIND")
            print(find)
            vulnerabilities = find["findings"]['vulnerabilities']
            malware = find["
            print("vulnerabilities")

            dataVuln = "Vulnerabilities found: \n"
            dataMalw = ""

            for value in vulnerabilities['total']:
                if value == 'defcon1':
                    defcon1 = vulnerabilities['total']['defcon1']
                    dataVuln = dataVuln+"<b>Defcon1:</b> <strong style='color:red;'>"+str(defcon1)+"</strong>\n"
                if value == 'critical':
                    critical = vulnerabilities['total']['critical']
                    dataVuln = dataVuln+"<b>Critical:</b> <strong style='color:red;'>"+str(critical)+"</strong>\n"
                if value == 'high':
                    high = vulnerabilities['total']['high']
                    dataVuln = dataVuln+"<b>High:</b> <strong style='color:red;'>"+str(high)+"</strong>\n"
                if value == 'medium':
                    medium = vulnerabilities['total']['medium']
                    dataVuln = dataVuln+"<b>Medium:</b> <strong style='color:orange;'>"+str(medium)+"</strong>\n"
                if value == 'low':
                    low = vulnerabilities['total']['low']
                    dataVuln = dataVuln+"<b>Low:</b> <strong style='color:#cccc00;'>"+str(low)+"</strong>\n"
                if value == 'negligible':
                    negligible = vulnerabilities['total']['negligible']
                    dataVuln = dataVuln+"<b>Negligible:</b> <strong style='color:gray;'>"+str(negligible)+"</strong>\n"
                if value == 'unknown':
                    unknown = vulnerabilities['total']['unknown']
                    dataVuln = dataVuln+"<b>Unknown:</b> <strong style='color:gray;'>"+str(unknown)+"</strong>\n"

            if dataVuln == "Vulnerabilities found: \n": dataVuln=""

            for value in findings:
                if value == 'malware':
                    malware = findings['malware']
                    dataMalw = "Malware found: "+str(malware)

            message ="id:"+find["id"]+"\n"+dataVuln+dataMalw
            print("*******************MESSAGE*****************")
            print(message)
            print("*******************MESSAGE*****************")
            detailsFinfings = scan["details"]['results']
                
            data = {"text": "<pre>!!! Trend Micro - Smart Check Scan results !!! \n"+"<br><b>Image: "+name+':'+ref["tag"]+"</b>\n"+message+"</pre>"}

            url = webhook_teams
            headers = {'Content-Type': 'application/json'}

            try:
                response = requests.request("POST", url, json=data, headers=headers)
                print(response)
            except requests.exceptions.RequestException as e:
                print (e)
                sys.exit(1)

def main():
    """Mainline"""

    parser = argparse.ArgumentParser(
        description='Start a scan',
    )

    parser.add_argument('--smartcheck-host', action='store',
                        default=os.environ.get('DSSC_SMARTCHECK_HOST', None),
                        help='The hostname of the Deep Security Smart Check deployment. Example: smartcheck.example.com')
    parser.add_argument('--smartcheck-user', action='store',
                        default=os.environ.get('DSSC_SMARTCHECK_USER', None),
                        help='The userid for connecting to Deep Security Smart Check')
    parser.add_argument('--smartcheck-password', action='store',
                        default=os.environ.get(
                            'DSSC_SMARTCHECK_PASSWORD', None),
                        help='The password for connecting to Deep Security Smart Check')
    parser.add_argument('--insecure-skip-tls-verify', action='store_true',
                        default=os.environ.get(
                            'DSSC_INSECURE_SKIP_TLS_VERIFY', False),
                        help='Ignore certificate errors when connecting to Deep Security Smart Check')
    parser.add_argument('--image-pull-auth', action='store',
                        default=os.environ.get('DSSC_IMAGE_PULL_AUTH', None),
                        help='A JSON object of credentials for authenticating with the registry to pull the image from')
    parser.add_argument('--registry-root-cas', action='store',
                        default=os.environ.get('DSSC_REGISTRY_ROOT_CAS', None),
                        help='A file containing the root CAs (in PEM format) to trust when connecting to the registry')
    parser.add_argument('--insecure-skip-registry-tls-verify', action='store_true',
                        default=os.environ.get(
                            'DSSC_INSECURE_SKIP_REGISTRY_TLS_VERIFY', False),
                        help='Ignore certificate errors from the image registry')
    parser.add_argument('--no-wait', action='store_false',
                        default=os.environ.get('DSSC_NO_WAIT', True),
                        help='Exit after requesting the scan')
    parser.add_argument('--webhook-teams', action='store',
                        default=os.environ.get('DSSC_SMARTCHECK_WEBHOOK_TEAMS', None),
                        help='WebHook Teams Ds Smartcheck')
    parser.add_argument(
        'image', help='The image to scan. Example: registry.example.com/project/image:latest')

    args = parser.parse_args()

    if args.smartcheck_host is None:
        eprint('smartcheck_host is required')
        sys.exit(1)

    if args.insecure_skip_tls_verify:
        import urllib3
        urllib3.disable_warnings()

    if not args.smartcheck_host.startswith('http'):
        args.smartcheck_host = 'https://' + args.smartcheck_host

    with get_session(
        base=args.smartcheck_host,
        user=args.smartcheck_user,
        password=args.smartcheck_password,
        verify=(not args.insecure_skip_tls_verify),
    ) as session:
        start_scan(
            session,
            args.image,
            image_pull_auth=args.image_pull_auth,
            registry_root_cas=args.registry_root_cas,
            insecure_skip_registry_tls_verify=args.insecure_skip_registry_tls_verify,
            webhook_teams=args.webhook_teams,
            wait=args.no_wait,
        )


if __name__ == '__main__':
    main()
