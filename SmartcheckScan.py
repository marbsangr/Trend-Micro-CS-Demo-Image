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


class SlightlyImprovedSession(requests.Session):
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
    
    for registry in registry_aux.json()["registries"]:
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
        findings = scan["details"]['results'][0]['findings']
        vulnerabilities = findings['vulnerabilities']
        dataVuln = "Vulnerabilities found: \n"
        dataMalw = ""

        for value in vulnerabilities['total']:
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

        message = dataVuln+dataMalw
            
        data = {"text": "<pre>!!! Trend Micro - Smart Check Scan results !!! \n"+"<br><b>Image: "+name+':'+ref["tag"]+"</b>\n"+message+"</pre>"}

        adaptiveCard = json.dumps({
            "type": "message",
            "attachments": [
            {
                "type": "AdaptiveCard",
                "body": [
                {
                    "type": "ColumnSet",
                    "columns": [
                        {
                        "type": "Column",
                        "items": [
                            {"type": "Container", "backgroundImage": "https://messagecardplayground.azurewebsites.net/assets/TxP_Background.png","items": [{ "type": "Image", "horizontalAlignment": "Center", "url": "https://www.docker.com/wp-content/uploads/2022/03/Moby-logo.png", "altText": "Docker", "isVisible": false, "width": "80px"}],"bleed": true},
                            {"type": "Container","spacing": "none","style": "emphasis","items": [{"type": "TextBlock", "size": "extraLarge","weight": "lighter","color": "accent","text": "Image Name: {}".format(name+":"+ref["tag"]), "wrap": true}],"bleed": true,"height": "stretch"}
                        ],
                        "width": 45,"height": "stretch"
                        },
                        {
                            "type": "Column",
                            "items": [
                                {
                                    "type": "Container","height": "stretch",
                                    "items": [
                                        {
                                            "type": "ColumnSet",
                                            "columns": [
                                                {
                                                    "type": "Column",
                                                    "items": [
                                                        {"type": "RichTextBlock","inlines": [{"type": "TextRun", "text": "Summary Findings"} ]},
                                                        {"type": "RichTextBlock", "horizontalAlignment": "Left", "inlines": [{"type": "TextRun","size": "Medium","text": "High","wrap": true}]},
                                                        {"type": "RichTextBlock","horizontalAlignment": "Left","inlines": [{"type": "TextRun","size": "Medium","text": "Medium","wrap": true}]},
                                                        {"type": "RichTextBlock", "horizontalAlignment": "Left", "inlines": [ { "type": "TextRun", "size": "Medium","text": "Low:","wrap": true }]}
                                                    ],
                                                    "width": 1
                                                }
                                            ]
                                        }
                                    ]
                                }
                            ],
                            "width": 55
                        }
                    ],
                    "height": "stretch"
                }],
                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "version": "1.4"
            }]
        })

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

    parser.add_argument('--dssc-host', action='store',
                        default=os.environ.get('DSSC_SMARTCHECK_HOST', None),
                        help='The hostname of the Deep Security Smart Check deployment. Example: smartcheck.example.com')
    parser.add_argument('--dssc-user', action='store',
                        default=os.environ.get('DSSC_SMARTCHECK_USER', None),
                        help='The userid for connecting to Deep Security Smart Check')
    parser.add_argument('--dssc-password', action='store',
                        default=os.environ.get(
                            'DSSC_SMARTCHECK_PASSWORD', None),
                        help='The password for connecting to Deep Security Smart Check')
    parser.add_argument('--skip-tls-verify', action='store_true',
                        default=os.environ.get(
                            'DSSC_INSECURE_SKIP_TLS_VERIFY', False),
                        help='Ignore certificate errors when connecting to Deep Security Smart Check')
    parser.add_argument('--image-pull-auth', action='store',
                        default=os.environ.get('DSSC_IMAGE_PULL_AUTH', None),
                        help='A JSON object of credentials for authenticating with the registry to pull the image from')
    parser.add_argument('--skip-registry-tls-verify', action='store_true',
                        default=os.environ.get(
                            'DSSC_INSECURE_SKIP_REGISTRY_TLS_VERIFY', False),
                        help='Ignore certificate errors from the image registry')
    parser.add_argument('--webhook-teams', action='store',
                        default=os.environ.get('DSSC_SMARTCHECK_WEBHOOK_TEAMS', None),
                        help='WebHook Teams Ds Smartcheck')
    parser.add_argument(
        'image', help='The image to scan. Example: registry.example.com/project/image:latest')

    args = parser.parse_args()

    if args.dssc_host is None:
        eprint('dssc_host is required')
        sys.exit(1)

    if args.skip_tls_verify:
        import urllib3
        urllib3.disable_warnings()

    if not args.dssc_host.startswith('http'):
        args.dssc_host = 'https://' + args.dssc_host

    with get_session(
        base=args.dssc_host,
        user=args.dssc_user,
        password=args.dssc_password,
        verify=(not args.skip_tls_verify),
    ) as session:
        start_scan(
            session,
            args.image,
            image_pull_auth=args.image_pull_auth,
            insecure_skip_registry_tls_verify=args.skip_registry_tls_verify,
            webhook_teams=args.webhook_teams
        )


if __name__ == '__main__':
    main()
