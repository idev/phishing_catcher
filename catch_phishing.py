#!/usr/bin/env python
# Copyright (c) 2017 @x0rz
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
import re
import math
import io
import os

import certstream
import tqdm
import yaml
import time
import datetime
import base64
import urllib
import zipfile
from Levenshtein import distance
from termcolor import colored, cprint
from tld import get_tld

from confusables import unconfuse

certstream_url = 'wss://certstream.calidog.io'

log_suspicious = os.path.dirname(os.path.realpath(__file__))+'/suspicious_domains_'+time.strftime("%Y-%m-%d")+'.log'

suspicious_yaml = os.path.dirname(os.path.realpath(__file__))+'/suspicious.yaml'

external_yaml = os.path.dirname(os.path.realpath(__file__))+'/external.yaml'

# Progress bars
pbar1 = tqdm.tqdm(desc='certificate_update', unit=' cert', position=0)
pbar2 = tqdm.tqdm(desc='domain_analysis', unit=' domain', position=1)

def domain_worker():
    saved_date = None
    date = datetime.date.today() - datetime.timedelta(1)
    encoded_date = base64.b64encode((str(date) + ".zip").encode("utf-8"))
    if date != saved_date:
        try:
            req = urllib.request.Request('https://www.whoisds.com//whois-database/newly-registered-domains/'+str(encoded_date.decode("utf-8"))+'/nrd', headers={'User-Agent' : "Magic Browser"})
            filedata = urllib.request.urlopen(req)
            datatowrite = filedata.read()

            file_like_object = io.BytesIO(datatowrite)
            zipfile_ob = zipfile.ZipFile(file_like_object)

            new_domains = None
            for name in zipfile_ob.namelist():
                data = zipfile_ob.read(name)
                new_domains = str(data).split("\\r\\n")
                break

            for d in new_domains:
                pbar2.update(1)
                score = score_domain(d.lower())
                score_evaluate(score, d)

            saved_date = date

        except Exception as e:
            print(e)
            pass


def entropy(string):
    """Calculates the Shannon entropy of a string"""
    prob = [ float(string.count(c)) / len(string) for c in dict.fromkeys(list(string)) ]
    entropy = - sum([ p * math.log(p) / math.log(2.0) for p in prob ])
    return entropy

def score_domain(domain):
    """Score `domain`.

    The highest score, the most probable `domain` is a phishing site.

    Args:
        domain (str): the domain to check.

    Returns:
        int: the score of `domain`.
    """
    score = 0
    for t in suspicious['tlds']:
        if domain.endswith(t):
            score += 20
    # Remove initial '*.' for wildcard certificates bug
    if domain.startswith('*.'):
        domain = domain[2:]
    # Removing TLD to catch inner TLD in subdomain (ie. paypal.com.domain.com)
    try:
        res = get_tld(domain, as_object=True, fail_silently=True, fix_protocol=True)
        domain = '.'.join([res.subdomain, res.domain])
    except Exception:
        pass
    # Higer entropy is kind of suspicious
    score += int(round(entropy(domain)*10))

    # Remove lookalike characters using list from http://www.unicode.org/reports/tr39
    domain = unconfuse(domain)
    words_in_domain = re.split("\W+", domain)

    # ie. detect fake .com (ie. *.com-account-management.info)
    if words_in_domain[0] in ['com', 'net', 'org']:
        score += 10
    # Testing keywords
    for word in suspicious['keywords']:
        if word in domain:
            score += suspicious['keywords'][word]

    # Testing Levenshtein distance for strong keywords (>= 70 points) (ie. paypol)
    for key in [k for (k,s) in suspicious['keywords'].items() if s >= 70]:
        # Removing too generic keywords (ie. mail.domain.com)
        for word in [w for w in words_in_domain if w not in ['email', 'mail', 'cloud']]:
            if distance(str(word), str(key)) == 1:
                score += 70

    # Lots of '-' (ie. www.paypal-datacenter.com-acccount-alert.com)
    if 'xn--' not in domain and domain.count('-') >= 4:
        score += domain.count('-') * 3
    # Deeply nested subdomains (ie. www.paypal.com.security.accountupdate.gq)
    if domain.count('.') >= 3:
        score += domain.count('.') * 3

    return score


def cert_worker():
    certstream.listen_for_events(callback, url=certstream_url)

def callback(message, context):
    """Callback handler for certstream events."""
    if message['message_type'] == "heartbeat":
        return

    if message['message_type'] == "certificate_update":
        all_domains = message['data']['leaf_cert']['all_domains']

        for domain in all_domains:
            pbar1.update(1)

            # First check if domain should be ignored by being in the whitelist
            inWhitelist = False
            for w in suspicious['whitelist']:
                if domain.endswith(w):
                    inWhitelist = True
                    break
            # If domain in whitelist, skip this iteration of the for loop and continue to next domain
            if inWhitelist:
                continue
            # Otherwise, continue
            score = score_domain(domain.lower())
            score_evaluate(score, domain)


def score_evaluate(score, domain):
    # If issued from a free CA = more suspicious
    #if "Let's Encrypt" in message['data']['chain'][0]['subject']['aggregated']:
    #    score += 10

    if score >= 100:
        tqdm.tqdm.write(
            "[!] Suspicious: "
            "{} (score={})".format(colored(domain, 'red', attrs=['underline', 'bold']), score))
    elif score >= 90:
        tqdm.tqdm.write(
            "[!] Suspicious: "
            "{} (score={})".format(colored(domain, 'red', attrs=['underline']), score))
    elif score >= 80:
        tqdm.tqdm.write(
            "[!] Likely    : "
            "{} (score={})".format(colored(domain, 'yellow', attrs=['underline']), score))
    elif score >= 65:
        tqdm.tqdm.write(
            "[+] Potential : "
            "{} (score={})".format(colored(domain, attrs=['underline']), score))

    if score >= 75:
        with open(log_suspicious, 'a') as f:
            f.write("{}\n".format("domain="+domain+","+"score="+str(score)))



if __name__ == '__main__':
    with open(suspicious_yaml, 'r') as f:
        suspicious = yaml.safe_load(f)

    with open(external_yaml, 'r') as f:
        external = yaml.safe_load(f)

    if external['whitelist'] is not None:
        suspicious['whitelist'].update(external['whitelist'])

    if external['override_suspicious.yaml'] is True:
        suspicious = external
    else:
        if external['keywords'] is not None:
            suspicious['keywords'].update(external['keywords'])

        if external['tlds'] is not None:
            suspicious['tlds'].update(external['tlds'])

#TODO: main purpose is to run via a cronjob - so a args should be trigger cert or domain_worker
#TODO: utilize dnstwist for possible corporate phishing domains
#TODO: do a separate log for cert / domain log
#TODO: CLI Logging not neccessary?!
#cert_worker()
domain_worker()
