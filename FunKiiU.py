#!/usr/bin/python
# -*- coding: utf-8 -*-
#  FunKiiU 0.95.1

from __future__ import unicode_literals, print_function

import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import sys
import zlib

try:
    from urllib.request import urlopen
    from urllib.error import URLError, HTTPError
except ImportError:
    from urllib2 import urlopen, URLError, HTTPError

try:
    real_input = raw_input  # Python2
except NameError:
    real_input = input  # Python3

b64decompress = lambda d: zlib.decompress(base64.b64decode(d))

SYMBOLS = {
    'customary': ('B', 'KB', 'MB', 'GB', 'T', 'P', 'E', 'Z', 'Y'),
}
KEYSITE_MD5 = 'd098abb93c29005dbd07deb43d81c5df'
BLANK_CONFIG = {'keysite': ''}
MAGIC = b64decompress(
    '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'
)
TIKTEM = b64decompress(
    'eNpjYGRguRi39K3o6odSI5VmoAAE5eeX6Do7GkCAsW5EMJSZTJz+f29/nSMXMzIw'
    'nEEDKGavggJK/MfAyDDwgJFBBEiuAWIRKBsENKCuawFjZojgfwKA1k4FAKCBAYU='
)

TK = 0x140

parser = argparse.ArgumentParser()
parser.add_argument('-outputdir', action='store', dest='output_dir',
                    help='The custom output directory to store output in, if desired')
parser.add_argument('-retry', type=int, default=4, dest='retry_count',
                    choices=range(0, 10), help='How many times a file download will be attempted')
parser.add_argument('-title', nargs='+', dest='titles', default=[],
                    help='Give TitleIDs to be specifically downloaded')
parser.add_argument('-key', nargs='+', dest='keys', default=[],
                    help='Encrypted Title Key for the Title IDs. Must be in the same order as TitleIDs if multiple')
parser.add_argument('-onlinekeys', action='store_true', default=False, dest='onlinekeys',
                    help='Gets latest titlekeys.json file from *theykeysite*, saves (overwrites) it and uses as input')
parser.add_argument('-onlinetickets', action='store_true', default=False, dest='onlinetickets',
                    help='Gets ticket file from *thekeysite*, should create a \'legit\' game')
parser.add_argument('-nopatchdlc', action='store_false', default=True,
                    dest='patch_dlc', help='This will disable unlocking all DLC content')
parser.add_argument('-nopatchdemo', action='store_false', default=True,
                    dest='patch_demo', help='This will disable patching the demo play limit')
parser.add_argument('-all', action='store_true', default=False, dest='download_all',
                    help='Downloads/gets tickets for EVERYTHING from the keyfile')


def bytes2human(n, f='%(value).2f %(symbol)s', symbols='customary'):
    n = int(n)
    if n < 0:
        raise ValueError("n < 0")
    symbols = SYMBOLS[symbols]
    prefix = {}
    for i, s in enumerate(symbols[1:]):
        prefix[s] = 1 << (i + 1) * 10
    for symbol in reversed(symbols[1:]):
        if n >= prefix[symbol]:
            value = float(n) / prefix[symbol]
            return f % locals()
    return f % dict(symbol=symbols[0], value=n)


RE_16_HEX = re.compile(r'^[0-9a-f]{16}$', re.IGNORECASE)
RE_32_HEX = re.compile(r'^[0-9a-f]{32}$', re.IGNORECASE)

check_title_id = RE_16_HEX.match
check_title_key = RE_32_HEX.match


def retry(count):
    for i in range(1, count + 1):
        if i > 1:
            print("*Attempt {} of {}".format(i, count))
        yield i


def progress_bar(part, total, length=10, char='#', blank=' ', left='[', right=']'):
    percent = int((float(part) / float(total) * 100) % 100)
    bar_len = int((float(part) / float(total) * length) % length)
    bar = char * bar_len
    blanks = blank * (length - bar_len)
    return '{}{}{}{} {} of {}, {:.0%}'.format(
        left, bar, blanks, right, bytes2human(part), bytes2human(total), percent
    ) + ' ' * 20


def download_file(url, outfname, retry_count=3, ignore_404=False, expected_size=None, chunk_size=0x4096):
    for _ in retry(retry_count):
        try:
            infile = urlopen(url)

            with open(outfname, 'wb') as outfile:
                downloaded_size = 0
                while True:
                    buf = infile.read(chunk_size)
                    if not buf:
                        break
                    downloaded_size += len(buf)
                    if expected_size and len(buf) == chunk_size:
                        print(' Downloaded {}'.format(progress_bar(downloaded_size, expected_size)), end='\r')
                    outfile.write(buf)

            if expected_size is not None:
                if int(os.path.getsize(outfname)) != expected_size:
                    print('Content download not correct size\n')
                    continue
                else:
                    print(' Download complete: {}'.format(bytes2human(downloaded_size)) + ' ' * 40)
        except HTTPError as e:
            if e.code == 404 and ignore_404:
                # We are ignoring this because its a 404 error, not a failure
                return True
        except URLError:
            print('Could not download file...\n')
        else:
            return True
    return False


def load_config():
    try:
        with open('config.json', 'r') as f:
            return json.load(f)
    except IOError:
        save_config(BLANK_CONFIG)
        return BLANK_CONFIG.copy()


def save_config(config):
    with open('config.json', 'w') as f:
        json.dump(config, f)


def get_keysite():
    config = load_config()

    if hashlib.md5(config.get('keysite', '').encode('utf-8')).hexdigest() != KEYSITE_MD5:
        if sys.stdin.isatty():
            for _ in retry(3):
                print('Please type *the* keysite to access online keys and tickets')
                print('Type something like: \'aaaa.bbbbbbbbb.ccc\', no http:// or quotes')
                print('A blank response will exit')
                checkurl = real_input().lower().strip()

                if not checkurl:
                    print('Please set "keysite" to that title keys site in config.json')
                    sys.exit(0)

                elif hashlib.md5(checkurl.encode('utf-8')).hexdigest() == KEYSITE_MD5:
                    config['keysite'] = checkurl
                    save_config(config)
                    break

                else:
                    print('Incorrect keysite url!')

            else:
                print('Too many failed attempts, exiting.')
                sys.exit(2)
        else:
            print('Please set "keysite" to that title keys site in config.json')
            sys.exit(2)
    return config.get('keysite')


def patch_ticket_dlc(tikdata):
    tikdata[TK + 0x164:TK + 0x210] = b64decompress('eNpjYGQQYWBgWAPEIgwQNghoADEjELeAMTNE8D8BwEBjAABCdSH/')


def patch_ticket_demo(tikdata):
    tikdata[TK + 0x124:TK + 0x164] = bytes([0x00] * 64)


def make_ticket(titleid, key, titleversion, fulloutputpath, patch_demo=False, patch_dlc=False):
    tikdata = bytearray(TIKTEM)
    tikdata[TK + 0xA6:TK + 0xA8] = titleversion
    tikdata[TK + 0x9C:TK + 0xA4] = binascii.a2b_hex(titleid)
    tikdata[TK + 0x7F:TK + 0x8F] = binascii.a2b_hex(key)
    # not sure what the value at 0xB3 is... mine is 0 but some i see 5.
    # or 0xE0, the reserved data is...?
    typecheck = titleid[4:8]
    if typecheck == '0002' and patch_demo:
        patch_ticket_demo(tikdata)
    elif typecheck == '000c' and patch_dlc:
        patch_ticket_dlc(tikdata)
    open(fulloutputpath, 'wb').write(tikdata)


def safe_filename(filename):
    """Strip any non-path-safe characters from a filename"""
    keep = ' ._'
    return re.sub(r'_+', '_', ''.join(c if (c.isalnum() or c in keep) else '_' for c in filename)).strip('_ ')


def process_title_id(titleid, key, name=None, output_dir=None, retry_count=3, onlinetickets=False, patch_demo=False,
                     patch_dlc=False):
    if name:
        dirname = '{} - {}'.format(titleid, name)
    else:
        dirname = titleid

    rawdir = os.path.join('install', safe_filename(dirname))

    if output_dir is not None:
        rawdir = os.path.join(output_dir, rawdir)

    if not os.path.exists(rawdir):
        os.makedirs(os.path.join(rawdir))

    # download stuff
    print('Downloading TMD...')

    baseurl = 'http://ccs.cdn.c.shop.nintendowifi.net/ccs/download/{}'.format(titleid)
    tmd_path = os.path.join(rawdir, 'title.tmd')
    if not download_file(baseurl + '/tmd', tmd_path, retry_count):
        print('ERROR: Could not download TMD...')
        print('Skipping title...')
        return

    with open(os.path.join(rawdir, 'title.cert'), 'wb') as f:
        f.write(MAGIC)

    with open(tmd_path, 'rb') as f:
        tmd = f.read()

    titleversion = tmd[TK + 0x9C:TK + 0x9E]

    # get ticket from keysite, or generate ticket
    if onlinetickets:
        keysite = get_keysite()
        tikurl = 'https://{}/ticket/{}.tik'.format(keysite, titleid)
        if not download_file(tikurl, os.path.join(rawdir, 'title.tik'), retry_count):
            print('ERROR: Could not download ticket from {}'.format(keysite))
            print('Skipping title...')
            return
    else:
        make_ticket(titleid, key, titleversion, os.path.join(rawdir, 'title.tik'), patch_demo, patch_dlc)

    print('Downloading Contents...')
    content_count = int(binascii.hexlify(tmd[TK + 0x9E:TK + 0xA0]), 16)
    for i in range(content_count):
        c_offs = 0xB04 + (0x30 * i)
        c_id = binascii.hexlify(tmd[c_offs:c_offs + 0x04]).decode()
        expected_size = int(binascii.hexlify(tmd[c_offs + 0x08:c_offs + 0x10]), 16)
        print('Downloading {} of {}.'.format(i + 1, content_count))
        outfname = os.path.join(rawdir, c_id + '.app')
        outfnameh3 = os.path.join(rawdir, c_id + '.h3')

        if not download_file('{}/{}'.format(baseurl, c_id), outfname, retry_count, expected_size=expected_size):
            print('ERROR: Could not download content file... Skipping title')
            return
        if not download_file('{}/{}.h3'.format(baseurl, c_id), outfnameh3, retry_count, ignore_404=True):
            print('ERROR: Could not download content file... Skipping title')
            return

    print('\nTitle download complete\n')


def main(titles=None, keys=None, onlinekeys=False, onlinetickets=False, download_all=False, output_dir=None,
         retry_count=3, patch_demo=True, patch_dlc=True):
    print('*******\nFunKiiU by cearp\n*******\n')
    titlekeys_data = []

    if download_all or onlinekeys or onlinetickets:
        keysite = get_keysite()

        print(u'Downloading/updating data from {0}'.format(keysite))

        if not download_file('https://{0}/json'.format(keysite), 'titlekeys.json', retry_count):
            print('ERROR: Could not download data file... Exiting.\n')
            sys.exit(1)

        print('Downloaded data OK!')

        with open('titlekeys.json') as data_file:
            titlekeys_data = json.load(data_file)

    for title_id in titles:
        if not check_title_id(title_id):
            print('The Title ID(s) must be 16 hexadecimal characters long')
            print('{} - is not ok.'.format(title_id))
            sys.exit(0)
        title_key = None
        name = None

        if keys:
            title_key = keys.pop()
        elif onlinekeys or onlinetickets:
            title_data = next((t for t in titlekeys_data if t['titleID'] == title_id.lower()), None)

            if not title_data:
                print("ERROR: Could not find key for ID {}, skipping".format(title_id))
                continue

            elif onlinetickets:
                if not title_data['ticket']:
                    print('ERROR: Ticket not available online for {}'.format(title_id))
                    continue

            elif onlinekeys:
                title_key = title_data['titleKey']

            name = title_data.get('name', None)

        if not (title_key or onlinetickets):
            print('ERROR: Could not find title or ticket for {}'.format(title_id))
            continue

        process_title_id(title_id, title_key, name, output_dir, retry_count, onlinetickets, patch_demo, patch_dlc)

    if download_all:
        for title_data in titlekeys_data:
            title_id = title_data['titleID']
            title_key = title_data.get('titleKey', None)
            name = title_data.get('name', None)
            typecheck = title_id[4:8]

            # skip updates
            if typecheck in ('000e', '8005', '800f') or int(typecheck, 16) & 0x10:
                continue
            elif title_id in titles:
                continue
            process_title_id(title_id, title_key, name, output_dir, retry_count, onlinetickets, patch_demo, patch_dlc)


if __name__ == '__main__':
    arguments = parser.parse_args()
    main(titles=arguments.titles,
         keys=arguments.keys,
         onlinekeys=arguments.onlinekeys,
         onlinetickets=arguments.onlinetickets,
         download_all=arguments.download_all,
         output_dir=arguments.output_dir,
         retry_count=arguments.retry_count,
         patch_demo=arguments.patch_demo,
         patch_dlc=arguments.patch_dlc)
