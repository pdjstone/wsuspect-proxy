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

try:
    from cStringIO import StringIO
except:
    from io import BytesIO as StringIO
    
try:
    from urlparse import urlparse, urlunparse
except:
    from urllib.parse import urlparse, urlunparse
    
from twisted.internet import reactor
from twisted.python.log import startLogging
from twisted.web import server, resource, proxy, http
from twisted.python.filepath import FilePath


#ProxyClient(twisted.web.http.HTTPClient)
class InterceptingProxyClient(proxy.ProxyClient):
    def handleResponsePart(self, buffer):
        #Buffer the output if we intend to modify it
        if self.father.has_response_modifiers():
            self.father.response_buffer.write(buffer)
        else:
            proxy.ProxyClient.handleResponsePart(self, buffer)
 
    def handleResponseEnd(self):
        #Process the buffered output if we are modifying it
        if self.father.has_response_modifiers():
            if not self._finished:
                #Replace the StringIO with a string for the modifiers
                data = self.father.response_buffer.getvalue()
                self.father.response_buffer.close()
                self.father.response_buffer = data

                #Do editing of response headers / content here
                self.father.run_response_modifiers()
                self.father.responseHeaders.setRawHeaders('content-length', [len(self.father.response_buffer)])
                self.father.write(self.father.response_buffer)
        proxy.ProxyClient.handleResponseEnd(self)


class InterceptingProxyClientFactory(proxy.ProxyClientFactory):
    noisy = False
    protocol = InterceptingProxyClient

#ProxyRequest(twisted.web.http.Request)
class InterceptingProxyRequest(proxy.ProxyRequest):
    def __init__(self, *args, **kwargs):
        proxy.ProxyRequest.__init__(self, *args, **kwargs)
        self.response_buffer = StringIO()
        self.request_buffer = StringIO()
        self.modifiers = self.channel.factory.modifiers
        
    def run_request_modifiers(self):
        if not self.has_request_modifiers():
            return
            
        if self.requestHeaders.hasHeader('content-length'):
            self.request_buffer = self.content.read()
            
        for m in self.modifiers:
            print('Calling %s to modify request %s' % (m.__class__.__name__, self.uri))
            m.modify_request(self)
            
        if self.requestHeaders.hasHeader('content-length'):
            self.content.seek(0,0)
            self.content.write(self.request_buffer)
            self.content.truncate()
            self.requestHeaders.setRawHeaders('content-length', [len(self.request_buffer)])

    def has_request_modifiers(self):
        ret = False
        for m in self.modifiers:
            if m.will_modify_request(self):
                ret = True
        return ret
        
    def has_response_modifiers(self):
        ret = False
        for m in self.modifiers:
            if m.will_modify_response(self):
                ret = True
        return ret

    def run_response_modifiers(self):
        for m in self.modifiers:
            print('Calling %s to modify response %s' % (m.__class__.__name__, self.uri))
            m.modify_response(self)

    def has_response_server(self):
        for m in self.modifiers:
            if m.will_serve_response(self):
                return True
        return False
        
    def serve_resource(self):
        body = None
        for m in self.modifiers:
            if m.will_serve_response(self):
                print('Calling %s to serve response %s' % (m.__class__.__name__, self.uri))
                body = m.get_response(self)
                break
        if not body:
            raise Exception('Nothing served a resource')
        self.setHeader('content-length', str(len(body)))
        self.write(body)
        self.finish()
        
    def process(self):
        host = None
        port = None
        parsed_uri = urlparse(self.uri)
        self.uri = urlunparse(('', '', parsed_uri.path, parsed_uri.params, parsed_uri.query, parsed_uri.fragment)) or "/"

        if self.has_request_modifiers():
            self.run_request_modifiers()
            
        if self.has_response_server():
            self.serve_resource()
            return 
            
        protocol = parsed_uri.scheme or 'http'
        host = host or parsed_uri.netloc
        port = port or parsed_uri.port or self.ports[protocol]

        headers = self.getAllHeaders().copy()
        if 'host' not in headers:
            headers['host'] = host
             
        if ':' in host:
            host,_ = host.split(':')

        self.content.seek(0, 0)
        content = self.content.read()
    
        clientFactory = InterceptingProxyClientFactory(self.method, self.uri, self.clientproto, headers, content, self)
        self.reactor.connectTCP(host, port, clientFactory)

#Proxy(twisted.web.http.HTTPChannel)
class InterceptingProxy(proxy.Proxy):
    requestFactory = InterceptingProxyRequest

class InterceptingProxyFactory(http.HTTPFactory):
    protocol = InterceptingProxy
    
    def add_modifier(self, m):
        self.modifiers.append(m)
        
    def __init__(self, modifier, *args, **kwargs):
        http.HTTPFactory.__init__(self, *args, **kwargs)
        self.modifiers = []
        self.add_modifier(modifier)