#!/usr/bin/env python
# -*- coding: utf-8 -*-
# vi:ts=4:et
'''
Copyright (C) 2020, Christian Folini / mailto:christian.folini@netnea.com / @ChrFolini / dune73
All rights reserved.

See https://github.com/dune73/crs-trigger for more infos about this script.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.

* Neither the name of the {organization} nor the names of its
  contributors may be used to endorse or promote products derived from
  this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
'''

import cStringIO
import pycurl
import re
import sys
import uuid
from optparse import OptionParser

import requests

try:
    from urlparse import urlparse, urlunparse
except ImportError:
    from urllib.parse import urlparse, urlunparse


__version__ = '0.1.0'
global name; name = "crs-trigger"
global user_agent; user_agent = "crs-trigger [see https://github.com/dune73/crs-trigger]"
global fake_host_header; fake_host_header = "0.0.0.0"


def urlParser(url):
    # Purpose:      parse url
    # Parameters:   url (string)
    # Return:       hostname (string), port (string), path (string), query-string (string), ssl (bool)
    # Remarks:      Return value is None if url could not be parsed

    ssl = False

    o = urlparse(url)

    if o[0] not in ['http', 'https', '']:
        return
    elif o[0] == 'https':
        ssl = True
    
    if len(o[2]) > 0:
        path = o[2]
    else:
        path = '/'

    tmp = o[1].split(':')

    if len(tmp) > 1:
        port = tmp[1]
    else:
        port = None

    hostname = tmp[0]
    query = o[4]

    return (hostname, port, path, query, ssl)


def check_url(url):
    # Purpose:      Check URL format, add prefix schema if necessary
    # Parameters:   Url (string)
    # Return:       Url (string)
    # Remarks:      None

    if not url.startswith('http'):
        url = 'http://' + url

    pret = urlParser(url)

    if pret is None:
        print('The url %s is not well formed. This is fatal. Aborting.' % url)
        sys.exit(1)

    return url


def replace_with_empty_header(headers, name):
    # Purpose:      Replace existing header with an empty header
    # Parameters:   Header list (array), header name (string)
    # Return:       Header list (array)
    # Remarks:      Libcurl sends some headers by default itself.
	#		        This default header to be removed first, or we simply get a 
    #               2nd header of the same name
    #               Basic syntax to pull this off:
    #               conn.setopt(pycurl.HTTPHEADER, ['Accept:','Accept;'])

    headers = headers + [name + ":"] + [name + ";"]

    return headers


def add_empty_header(headers, name):
    # Purpose:      Add an empty header
    # Parameters:   Header list (array), header name (string)
    # Return:       header list (array)
    # Remarks:      Libcurl sends some headers by default itself.
	#		        This default header to be removed first, or we simply get a 
    #               2nd header of the same name
    #               Basic syntax to pull this off:
    #               conn.setopt(pycurl.HTTPHEADER, ['Accept:','Accept;'])

    headers = headers + [name + ";"]

    return headers


def trigger_score_2_920310(headers):
    # Purpose:      Send empty Accept header to trigger CRS rule 920310 (PL1)
    #               for an anomaly score of 2
    # Parameters:   Header list (array)
    # Return:       Header list (array)
    # Remarks:      none

    headers = replace_with_empty_header(headers, "Accept")

    return headers


def trigger_score_2_920330(headers):
    # Purpose:      Send empty User-Agent header to trigger CRS rule 920330 (PL1)
    #               for an anomaly score of 2
    # Parameters:   Header list (array)
    # Return:       Header list (array)
    # Remarks:      none

    headers = replace_with_empty_header(headers, "User-Agent")

    return headers


def trigger_score_3_920190(headers):
    # Purpose:      Send a broken Range header to trigger CRS rule 920190 (PL1)
    #               for an anomaly score of 3
    # Parameters:   Header list (array)
    # Return:       Header list (array)
    # Remarks:      none

    headers = headers + ["Range: 2-1,"]

    return headers


def trigger_score_3_920210(headers):
    # Purpose:      Send conflicting Connection header to trigger CRS rule 920210 (PL1)
    #               for an anomaly score of 3
    # Parameters:   Header list (array)
    # Return:       Header list (array)
    # Remarks:      We send "Connection: keep-alive,close"

    headers = headers + ["Connection: keep-alive,close"]

    return headers


def trigger_score_3_920350(headers):
    # Purpose:      Send numeric host header to trigger CRS rule 920350 (PL1)
    #               for an anomaly score of 3
    # Parameters:   Header list (array)
    # Return:       Header list (array)
    # Remarks:      Not actively used right now as some servers return a 400 when
    #               this is used.

    headers = headers + ["Host: " + fake_host_header]

    return headers


def trigger_score_5_913120(headers):
    # Purpose:      Send random header beginning with x-scanner to trigger CRS rule 913120 (PL1)
    #               for an anomaly score of 5
    # Parameters:   Header list (array)
    # Return:       Header list (array)
    # Remarks:      This can be used multiple times per request

    headers = add_empty_header(headers, "x-scanner-" + uuid.uuid1().hex)

    return headers


def create_request_object(url):
    # Purpose:      Create pycurl / libcurl request object
    # Parameters:   Url (string)
    # Return:       Pycurl / libcurl request object, response headers (string)
    # Remarks:      Return value is None if url could not be parsed

    response_body = cStringIO.StringIO()
    response_headers = cStringIO.StringIO()

    c = pycurl.Curl()
    c.setopt(c.URL, url)
    c.setopt(c.USERAGENT, user_agent)
    c.setopt(c.SSL_VERIFYPEER, 0)
    c.setopt(c.SSL_VERIFYHOST, 0)
    c.setopt(c.FOLLOWLOCATION, 0)
    c.setopt(c.MAXREDIRS, 0)
    c.setopt(c.CONNECTTIMEOUT, 30)
    c.setopt(c.TIMEOUT, 300)
    c.setopt(c.NOSIGNAL, 1)
    c.setopt(c.WRITEFUNCTION, response_body.write)
    c.setopt(c.HEADERFUNCTION, response_headers.write)

    return c, response_headers


def parse_options():
    # Purpose:      Parse command line options
    # Parameters:   None
    # Return:       List of target urls (array), target anomaly score (int), followredirect (bool)
    # Remarks:      None
    
    parser = OptionParser(usage='%prog url1 [url2 [url3 ... ]]\r\nexample: %prog https://www.example.com/')

    parser.add_option('-n', '--score', dest='score', default=5,
                      help='Target anomaly score that should be triggered. Needs to be between 2 and 490. Default value 5.')
    parser.add_option('-r', '--noredirect', action='store_false', dest='followredirect',
                      default=True, help='Do not follow redirections given by 3xx responses')
    parser.add_option('--version', '-V', dest='version', action='store_true',
                      default=False, help='Print out the current version of script and exit.')

    options, args = parser.parse_args()

    if options.version:
        print('The version of ' + name + ' you have is v%s with %s.' % (__version__, pycurl.version))
        sys.exit(0)
    
    if len(args) == 0:
        print('No URL passed on the command line. This is fatal. Aborting.\r\n')
        parser.print_help()
        sys.exit(1)

    score = int(options.score)

    if score < 2:
        print("Target score %i is too low (minimal value is 2)." % score)
        sys.exit(1)
    if score > 490:
        print("Target score %i is too high (maximal value is 490)." % score)
        sys.exit(1)
        
    followredirect = options.followredirect

    target_urls = args

    return target_urls, score, followredirect


def perform_call(url, score):
    # Purpose:      Execute HTTP request
    # Parameters:   Url (string), target anomaly score (int)
    # Return:       Status code (int), response headers (string)
    # Remarks:      None

    c, response_headers = create_request_object(url)
    headers = []

    # Rules that we can trigger selectively
    #        headers = trigger_score_2_920310(headers)
    #        headers = trigger_score_2_920330(headers)
    #        headers = trigger_score_3_920190(headers)
    #        headers = trigger_score_3_920210(headers)
    #        headers = trigger_score_3_920350(headers) - not actively used right now
    #        headers = trigger_score_5_913120(headers) - cummulatively

    while score > 0:
        # We iterate through the assembly and add headers to trigger alerts / anomaly scores
        # until we hit 0.
        if score > 11:
            headers = trigger_score_5_913120(headers)
            score = score - 5
        elif score == 11:
            headers = trigger_score_5_913120(headers)
            headers = trigger_score_3_920190(headers)
            headers = trigger_score_3_920210(headers)
            score = score - 11
        elif score == 10:
            headers = trigger_score_5_913120(headers)
            headers = trigger_score_3_920190(headers)
            headers = trigger_score_2_920310(headers)
            score = score - 10
        elif score == 9:
            headers = trigger_score_5_913120(headers)
            headers = trigger_score_2_920310(headers)
            headers = trigger_score_2_920330(headers)
            score = score - 9
        elif score == 8:
            headers = trigger_score_5_913120(headers)
            headers = trigger_score_3_920190(headers)
            score = score - 8
        elif score == 7:
            headers = trigger_score_3_920190(headers)
            headers = trigger_score_2_920310(headers)
            headers = trigger_score_2_920330(headers)
            score = score - 7
        elif score == 6:
            headers = trigger_score_3_920190(headers)
            headers = trigger_score_3_920210(headers)
            score = score - 6
        elif score == 5:
            headers = trigger_score_3_920190(headers)
            headers = trigger_score_2_920310(headers)
            score = score - 5
        elif score == 4:
            headers = trigger_score_2_920310(headers)
            headers = trigger_score_2_920330(headers)
            score = score - 4
        elif score == 3:
            headers = trigger_score_3_920190(headers)
            score = score - 3
        elif score == 2:
            headers = trigger_score_2_920310(headers)
            score = score - 2
        elif score == 1:
            # We should not end up here, this ought to be caught earlier or
            # the assembly of the alerts to trigger did something wrong.
            print "Error with the assembly of alerts; hitting score 1. This is fatal. Aborting."
            sys.exit(1)

    c.setopt(c.HTTPHEADER, headers)

    try:
        c.perform()
    except Exception, e:
        print("Attempt to perform request failed. Message: %s. This is fatal. Aborting." % e[1])
        print c.getinfo(c.HTTP_CODE)
        sys.exit(1)

    status = c.getinfo(c.HTTP_CODE)

    return status, response_headers


def main():
    # Purpose:      Main loop
    # Parameters:   None
    # Return:       None
    # Remarks:      None

    target_urls, score, followredirect = parse_options()

    for url in target_urls:

        print('[*] Checking %s ...' % url)

        status = 999

        while status == 999 or status == 301 or status == 302 or status == 307:

            url = check_url(url)

            status, hdr = perform_call(url, score)

            if (status == 301 or status == 302 or status == 307):
                # This is now really complicated. We want to follow the redirect, but there
                # is a chance the redirect location header is either not a FQDN URL or it
                # is built with a fake Host header we sent. If that is the case we need 
                # to do another call to the server without the fake Host header to get a
                # proper location header.
                
                if not followredirect:
                    print("We received a redirect as reponse, but we are not following redirects (see usage). Aborting.")
                    sys.exit(0)
                    
                search = re.search('Location: (http.*)', hdr.getvalue(), re.IGNORECASE)

                if search:
                    # We have a location header with a FQDN URL
                
                    search2 = re.search("(https?:\/)?\/" + fake_host_header, hdr.getvalue(), re.IGNORECASE)

                    if search2:
                        # The redirect mirrors our numeric host header
                        # Doing a clean call to get the FQDN redirect

                        status, hdr = perform_call(url, 0)

                        if status == 301 or status == 302 or status == 307:
                            
                            search = re.search('Location: (http.*)', hdr.getvalue(), re.IGNORECASE)
                            
                            if search:
                                
                                if url == search.group(1).strip():
                                    print("Redirect points to the same URL %s. We are caught in a loop. Aborting." % search.group(1).strip())
                                    sys.exit(0)
                                else:
                                    print("1Redirect points to %s. Following redirect." % search.group(1).strip())

                        else:
                            # Landing here is very odd. But there is nothing we can do.
                            
                            print("Surprisingly, a clean request to the URI does not return a redirect.")
                            print("Do not know how to handle this. Aborting.")
                            sys.exit(0)

                    else:

                        if url == search.group(1).strip():
                            print("Redirect points to the same URL %s. We are caught in a loop. Aborting." % search.group(1).strip())
                            sys.exit(0)
                        else:
                            print("Redirect points to %s. Following redirect." % search.group(1).strip())
                            url = search.group(1).strip()

                else:
                    # probably a redirect without FQDN

                    search = re.search('Location: (\/.*)', hdr.getvalue(), re.IGNORECASE)

                    if search:
                        # FIXME: Catching redirect loop in this case
                        print("Redirect points to %s%s. Following redirect." % (url, search.group(1).strip()))
                    else:
                        print("Redirect received, but no Location header present (or readable). Do not know how to handle this. Aborting.")
                        sys.exit(0)

        if status == 200:
            print "Request successful with status code 200."
        elif status == 403:
            print "Request blocked with status code 403."
        else:
            print "Request returned status code " + str(status) + "."


if __name__ == '__main__':

    if sys.hexversion < 0x2060000:
        sys.stderr.write('Your version of python is way too old... please update to 2.6 or later\r\n')

    main()
