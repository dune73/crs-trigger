# Script crs-trigger.py

This is a script that will execute a HTTP request hitting a target anomaly score on one or multiple target URLs.

## Usage

```
Usage: crs-trigger.py url1 [url2 [url3 ... ]]
example: crs-trigger.py https://www.example.com/

Options:
  -h, --help            show this help message and exit
  -n SCORE, --score=SCORE
                        Target anomaly score that should be triggered. Needs
                        to be between 2 and 490. Default value 5.
  -r, --noredirect      Do not follow redirections given by 3xx responses
  -V, --version         Print out the current version of script and exit.
```

## Example usage

```
$> ./crs-trigger.py --score 10 https://netnea.com
[*] Checking https://netnea.com ...
Redirect points to https://netnea.com/cms/. Following redirect.
Request blocked with status code 403.
```

This gives the following access log entry on the server:
```
83.76.117.3 - - [2020-01-10 12:30:15.130027] "GET /cms/ HTTP/1.1" 403 199 "-" "crs-trigger (https://github.com/dune73/crs-trigger)" "-" 43970 www.netnea.com 192.168.3.7 443 - - + "ReqID--" XhhgRwp0SwFAd3stciLYngAAABg TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384 563 4046 -% 15889 8149 0 0 10-0-0-0 0-0-0-0 10 0
```




## License

Copyright (C) 2020, Christian Folini / mailto:christian.folini@netnea.com / @ChrFolini / dune73
All rights reserved.

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

