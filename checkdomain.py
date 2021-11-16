#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Thomas Roccia | Check domain availability
# pip install pywhois

import argparse
import signal
import sys
from datetime import datetime as dt
from typing import Dict, Optional, Tuple

import pandas as pd
import whois
from tqdm import tqdm


# handle ctrl c
def signal_handler(sig, frame):
    print(' You pressed Ctrl+C!')
    sys.exit(0)

def all_none_in_dict(d):
    holder = []
    for _, value in d.items():
        if value is None:
            holder.append(True)
        else:
            holder.append(False)
    return all(holder)


# check if domain exist
def domain_is_registered(domain: str) -> Tuple[bool, Optional[Dict[str, any]]]:
    print(f'WHOIS ==> {domain}')
    try:
        whois_details = whois.whois(domain)

        if all_none_in_dict(whois_details):
            return (False, None)
        else:
            return (True, whois_details)
    
    except whois.parser.PywhoisError:
        return (False, None)

# check domains from file
def check_list(filename: str, output_path: str):
    domains = []
    with open(filename) as f:
        domains = f.readlines()

    domains = [domain.strip() for domain in domains]
    as_of = [dt.today() for _ in domains]
    status = []
    details = []
    for domain in tqdm(domains):
        current_status, whois_details = domain_is_registered(domain)
        status.append(current_status)
        details.append(whois_details)

    holder = []
    index = []
    for i, detail in enumerate(details):
        temp = pd.json_normalize(detail) if detail else None
        holder.append(temp)
        index.append(i if detail else None)
    data = {
        'domain': domains,
        'is_registered': status,
        'as_of': as_of
    }
    df = pd.DataFrame(data)
    index = [x for x in index if x is not None]
    df_details = pd.concat(holder)
    df_details['index'] = index
    df_details.set_index('index', inplace=True)
    df = df.merge(df_details, how='left', left_index=True, right_index=True)
    df.to_csv(output_path)


# check single domain exist
def check_domain(domain):
    domain_is_registered(domain)


# main function
def main():
    # select arguments
    parser = argparse.ArgumentParser(description='checkDomain.py by Thomas Roccia')
    parser.add_argument("-d", "--domain", nargs='?', help="Check single domain")
    parser.add_argument("-f", "--file", nargs='?', help="Check domain list")
    parser.add_argument('-o', '--outfile', 
                        nargs='?', 
                        type=argparse.FileType('w'), 
                        default='domains.csv', 
                        help='output file, in CSV format')
    args = parser.parse_args()

    # handle ctrl+c
    signal.signal(signal.SIGINT, signal_handler)

    if args.domain:
        check_domain(args.domain)

    if args.file:
        check_list(args.file, args.outfile)


if __name__ == '__main__':
    main()
