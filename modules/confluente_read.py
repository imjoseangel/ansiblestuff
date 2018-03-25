#!/usr/bin/python
# -*- coding: utf-8 -*-

ANSIBLE_METADATA = {
    'metadata_version': '1.0',
    'status': ['preview'],
    'supported_by': 'community'
}

DOCUMENTATION = '''
---
module: confluence_read

short_description: Module to read Confluence pages from its API

version_added: "2.5"

description:
    - "The module uses the API described under https://developer.atlassian.com/cloud/confluence/rest"

options:
    id:
        description:
            - The Confluence Document ID.
        required: true
    endpoint:
        description:
            - The name of the enpoint
        required: false
        default: https://wiki.atlassian.net/
    username:
        description:
            - The name of the user for the endpoint
        required: false
        default: admin
    password:
        description:
            - The password of the user for the endpoint
        required: false
        default: admin
    validate_certs:
        description:
            - SSL/TLS Certificate Validation Flag
        required: false
        default: true

extends_documentation_fragment:
    - confluence

author:
    - (@imjoseangel)
'''

EXAMPLES = '''
# Get Confluence Document
- name: Get Document
    confluence_read:
      id: 283576376
'''

RETURN = '''
msg:
    description: None
    type: None
    returned: Never
    sample: "None"
'''

import base64
import httplib
import ssl
from urlparse import urlparse
import xml.etree.ElementTree as ET
import json

from ansible.module_utils.basic import *


class ConfluenceCommunicator:
    """ Confluence Communicator using http"""

    def __init__(self,
                 endpoint='https://wiki.atlassian.net',
                 username='admin',
                 password='admin',
                 validate_certs=True):
        self.endpoint = endpoint
        self.username = username
        self.password = password
        self.validate_certs = validate_certs

    def do_get(self, path):
        return self.do_it("GET", path, True)

    def do_it(self, verb, path, parse_response=True):

        ssl_context = None
        if not self.validate_certs:
            ssl_context = ssl._create_unverified_context()

        parsed_url = urlparse(self.endpoint)
        if parsed_url.scheme == "https":
            conn = httplib.HTTPSConnection(
                parsed_url.hostname, parsed_url.port, context=ssl_context)
        else:
            conn = httplib.HTTPConnection(parsed_url.hostname, parsed_url.port)

        try:
            auth = base64.encodestring('%s:%s' % (self.username,
                                                  self.password)).replace(
                                                      '\n', '')
            headers = {
                "Content-type": "application/json",
                "Accept": "application/json",
                "Authorization": "Basic %s" % auth
            }

            conn.request(verb, "/wiki/rest/api/%s" % path, headers=headers)
            response = conn.getresponse()

            # print response.status, response.reason, response.read()
            if response.status != 200 and response.status != 204:
                raise Exception(
                    "Error when requesting Confluence Server [%s]:%s" %
                    (response.status, response.reason))

            if parse_response:
                htmldoc = json.loads(str(response.read()))
                htmlbody = htmldoc['body']['storage']['value']
                htmltable = CleanHTMLTable(htmlbody)
                return htmltable.from_html()

            return None
        finally:
            conn.close()

    def __str__(self):
        return "[endpoint=%s, username=%s]" % (self.endpoint, self.username)


class CleanHTMLTable:
    """ Remove HTML Format from a HTML Table"""

    def __init__(self, html):
        self.html = html

    def from_html(self):

        # Keep table only
        tableonly = re.findall(r'<table[^>]*>[\s\S]*?<\/table>\s*', self.html)
        # Remove Table Format
        tabletags = re.sub(r'.class[^>]*>[\s\S]*?<tbody\s*', '',
                           str(tableonly))
        # Remove Table Confluence Links
        conflnktags = re.sub(r'<ac:link[^>]*>[\s\S]*?<\/ac:link>\s*', '',
                             tabletags)
        # Remove tbody and keep table simple
        tbodytags = re.sub(r'<.?tbody>', '', conflnktags)
        # Remove Strong Tags
        strongtags = re.sub(r'<.?strong>', '', tbodytags)
        # Remove Fixed Spaces
        fixspaces = re.sub(r'&nbsp;', '', strongtags)
        # Get Final Table List
        htmltable = re.findall(r'<table[^>]*>[\s\S]*?<\/table>\s*', fixspaces)

        # Convert Table to Dict
        table = ET.XML(htmltable[0])
        rows = iter(table)
        headers = [col.text for col in next(rows)]
        listtable = []

        for row in rows:
            values = [col.text for col in row]
            listtable.append(dict(zip(headers, values)))

        return listtable


class Confluence:
    """ Access to the Confluence REST API"""

    def __init__(self, communicator=None):
        self.communicator = communicator

    def read(self, id):
        doc = self.communicator.do_get('content/%s?expand=body.storage' % id)
        return doc


def main():
    module = AnsibleModule(
        argument_spec=dict(
            username=dict(default='admin'),
            password=dict(default='admin', no_log=True),
            endpoint=dict(default='https://wiki.atlassian.net'),
            validate_certs=dict(required=False, type='bool', default=True),
            id=dict(type='str', required=True)))

    communicator = ConfluenceCommunicator(
        module.params.get('endpoint'), module.params.get('username'),
        module.params.get('password'), module.params.get('validate_certs'))

    document = Confluence(communicator)
    id = module.params.get('id')

    msg = ""
    try:
        doc = document.read(id)
        module.exit_json(changed=False, msg=doc)
    except Exception as e:
        module.fail_json(
            msg="Failed to get Confluence %s on %s, about id [%s]:  %s" % (
                e, communicator, id, traceback.format_exc()))


if __name__ == '__main__':
    main()
