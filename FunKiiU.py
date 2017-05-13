#!/usr/bin/python
# -*- coding: utf-8 -*-
#  FunKiiU 2.2

from __future__ import unicode_literals, print_function

__VERSION__ = 2.2

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
#KEYSITE_MD5 = 'd098abb93c29005dbd07deb43d81c5df'
BLANK_CONFIG = {'keysite': ''}
MAGIC = binascii.a2b_hex('00010003704138EFBBBDA16A987DD901326D1C9459484C88A2861B91A312587AE70EF6237EC50E1032DC39DDE89A96A8E859D76A98A6E7E36A0CFE352CA893058234FF833FCB3B03811E9F0DC0D9A52F8045B4B2F9411B67A51C44B5EF8CE77BD6D56BA75734A1856DE6D4BED6D3A242C7C8791B3422375E5C779ABF072F7695EFA0F75BCB83789FC30E3FE4CC8392207840638949C7F688565F649B74D63D8D58FFADDA571E9554426B1318FC468983D4C8A5628B06B6FC5D507C13E7A18AC1511EB6D62EA5448F83501447A9AFB3ECC2903C9DD52F922AC9ACDBEF58C6021848D96E208732D3D1D9D9EA440D91621C7A99DB8843C59C1F2E2C7D9B577D512C166D6F7E1AAD4A774A37447E78FE2021E14A95D112A068ADA019F463C7A55685AABB6888B9246483D18B9C806F474918331782344A4B8531334B26303263D9D2EB4F4BB99602B352F6AE4046C69A5E7E8E4A18EF9BC0A2DED61310417012FD824CC116CFB7C4C1F7EC7177A17446CBDE96F3EDD88FCD052F0B888A45FDAF2B631354F40D16E5FA9C2C4EDA98E798D15E6046DC5363F3096B2C607A9D8DD55B1502A6AC7D3CC8D8C575998E7D796910C804C495235057E91ECD2637C9C1845151AC6B9A0490AE3EC6F47740A0DB0BA36D075956CEE7354EA3E9A4F2720B26550C7D394324BC0CB7E9317D8A8661F42191FF10B08256CE3FD25B745E5194906B4D61CB4C2E000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000526F6F7400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001434130303030303030330000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007BE8EF6CB279C9E2EEE121C6EAF44FF639F88F078B4B77ED9F9560B0358281B50E55AB721115A177703C7A30FE3AE9EF1C60BC1D974676B23A68CC04B198525BC968F11DE2DB50E4D9E7F071E562DAE2092233E9D363F61DD7C19FF3A4A91E8F6553D471DD7B84B9F1B8CE7335F0F5540563A1EAB83963E09BE901011F99546361287020E9CC0DAB487F140D6626A1836D27111F2068DE4772149151CF69C61BA60EF9D949A0F71F5499F2D39AD28C7005348293C431FFBD33F6BCA60DC7195EA2BCC56D200BAF6D06D09C41DB8DE9C720154CA4832B69C08C69CD3B073A0063602F462D338061A5EA6C915CD5623579C3EB64CE44EF586D14BAAA8834019B3EEBEED3790001000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100042EA66C66CFF335797D0497B77A197F9FE51AB5A41375DC73FD9E0B10669B1B9A5B7E8AB28F01B67B6254C14AA1331418F25BA549004C378DD72F0CE63B1F7091AAFE3809B7AC6C2876A61D60516C43A63729162D280BE21BE8E2FE057D8EB6E204242245731AB6FEE30E5335373EEBA970D531BBA2CB222D9684387D5F2A1BF75200CE0656E390CE19135B59E14F0FA5C1281A7386CCD1C8EC3FAD70FBCE74DEEE1FD05F46330B51F9B79E1DDBF4E33F14889D05282924C5F5DC2766EF0627D7EEDC736E67C2E5B93834668072216D1C78B823A072D34FF3ECF9BD11A29AF16C33BD09AFB2D74D534E027C19240D595A68EBB305ACC44AB38AB820C6D426560C000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000526F6F742D43413030303030303033000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000143503030303030303062000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000137A080BA689C590FD0B2F0D4F56B632FB934ED0739517B33A79DE040EE92DC31D37C7F73BF04BD3E44E20AB5A6FEAF5984CC1F6062E9A9FE56C3285DC6F25DDD5D0BF9FE2EFE835DF2634ED937FAB0214D104809CF74B860E6B0483F4CD2DAB2A9602BC56F0D6BD946AED6E0BE4F08F26686BD09EF7DB325F82B18F6AF2ED525BFD828B653FEE6ECE400D5A48FFE22D538BB5335B4153342D4335ACF590D0D30AE2043C7F5AD214FC9C0FE6FA40A5C86506CA6369BCEE44A32D9E695CF00B4FD79ADB568D149C2028A14C9D71B850CA365B37F70B657791FC5D728C4E18FD22557C4062D74771533C70179D3DAE8F92B117E45CB332F3B3C2A22E705CFEC66F6DA3772B000100010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010004919EBE464AD0F552CD1B72E7884910CF55A9F02E50789641D896683DC005BD0AEA87079D8AC284C675065F74C8BF37C88044409502A022980BB8AD48383F6D28A79DE39626CCB2B22A0F19E41032F094B39FF0133146DEC8F6C1A9D55CD28D9E1C47B3D11F4F5426C2C780135A2775D3CA679BC7E834F0E0FB58E68860A71330FC95791793C8FBA935A7A6908F229DEE2A0CA6B9B23B12D495A6FE19D0D72648216878605A66538DBF376899905D3445FC5C727A0E13E0E2C8971C9CFA6C60678875732A4E75523D2F562F12AABD1573BF06C94054AEFA81A71417AF9A4A066D0FFC5AD64BAB28B1FF60661F4437D49E1E0D9412EB4BCACF4CFD6A3408847982000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000526F6F742D43413030303030303033000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000158533030303030303063000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000137A0894AD505BB6C67E2E5BDD6A3BEC43D910C772E9CC290DA58588B77DCC11680BB3E29F4EABBB26E98C2601985C041BB14378E689181AAD770568E928A2B98167EE3E10D072BEEF1FA22FA2AA3E13F11E1836A92A4281EF70AAF4E462998221C6FBB9BDD017E6AC590494E9CEA9859CEB2D2A4C1766F2C33912C58F14A803E36FCCDCCCDC13FD7AE77C7A78D997E6ACC35557E0D3E9EB64B43C92F4C50D67A602DEB391B06661CD32880BD64912AF1CBCB7162A06F02565D3B0ECE4FCECDDAE8A4934DB8EE67F3017986221155D131C6C3F09AB1945C206AC70C942B36F49A1183BCD78B6E4B47C6C5CAC0F8D62F897C6953DD12F28B70C5B7DF751819A98346526250001000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000')
TIKTEM = binascii.a2b_hex('00010004d15ea5ed15abe11ad15ea5ed15abe11ad15ea5ed15abe11ad15ea5ed15abe11ad15ea5ed15abe11ad15ea5ed15abe11ad15ea5ed15abe11ad15ea5ed15abe11ad15ea5ed15abe11ad15ea5ed15abe11ad15ea5ed15abe11ad15ea5ed15abe11ad15ea5ed15abe11ad15ea5ed15abe11ad15ea5ed15abe11ad15ea5ed15abe11ad15ea5ed15abe11ad15ea5ed15abe11ad15ea5ed15abe11ad15ea5ed15abe11ad15ea5ed15abe11ad15ea5ed15abe11ad15ea5ed15abe11ad15ea5ed15abe11ad15ea5ed15abe11ad15ea5ed15abe11ad15ea5ed15abe11ad15ea5ed15abe11ad15ea5ed15abe11ad15ea5ed15abe11ad15ea5ed15abe11ad15ea5ed15abe11a000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000526f6f742d434130303030303030332d585330303030303030630000000000000000000000000000000000000000000000000000000000000000000000000000feedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedface010000cccccccccccccccccccccccccccccccc00000000000000000000000000aaaaaaaaaaaaaaaa00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010014000000ac000000140001001400000000000000280000000100000084000000840003000000000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000')

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
parser.add_argument('-region', nargs="?", default=[], dest='download_regions',
                    help='Downloads/gets tickets for regions: [EUR|USA|JPN] from the keyfile')
parser.add_argument('-simulate', action='store_true', default=False, dest='simulate',
                    help="Don't download anything, just do like you would.")
parser.add_argument('-ticketsonly', action='store_true', default=False, dest='tickets_only',
                    help="Only download/generate tickets (and TMD and CERT), don't download any content")


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
    return '{}{}{}{} {} of {}, {}%'.format(
        left, bar, blanks, right, bytes2human(part), bytes2human(total), percent
    ) + ' ' * 20


def download_file(url, outfname, retry_count=3, ignore_404=False, expected_size=None, chunk_size=0x4096):
    for _ in retry(retry_count):
        try:
            infile = urlopen(url)
            # start of modified code
            if os.path.isfile(outfname):
                statinfo = os.stat(outfname)
                diskFilesize = statinfo.st_size
            else:
                diskFilesize = 0 
            log('-Downloading {}.\n-File size is {}.\n-File in disk is {}.'.format(outfname, expected_size,diskFilesize))
  
            #if not (expected_size is None):
            if expected_size != diskFilesize:
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
            else:
                print('-File skipped.')
                downloaded_size = statinfo.st_size
            # end of modified code

            if expected_size is not None:
                if int(os.path.getsize(outfname)) != expected_size:
                    print('Content download not correct size\n')
                    continue
                else:
                    print('Download complete: {}\n'.format(bytes2human(downloaded_size)) + ' ' * 40)
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

def user_input_keysite():
    print('\nPlease type *the* keysite to access online keys and tickets')
    print('Type something like: http://wiiu.xxxxxxxx.xxx')
    print('You MUST type the full address, INCLUDING http:// or https://')
    print('A blank response will exit the program')
    checkurl = real_input('Enter keysite >> ').lower().strip()

    if not checkurl:
        print('Please set "keysite" to that title keys site in config.json')
        sys.exit(0)
    config = load_config()
    config['keysite'] = checkurl
    save_config(config)
    return checkurl

def ask_update_keysite():
    print('Would you like to enter a different keysite and try again?')
    choice = real_input('Enter Y or N >> ').lower().strip()
    if choice == 'y' or choice == 'yes':
        return True
    else:
        print('Exiting program...')
        sys.exit(1)


def get_keysite():
    config = load_config()
    keysite = config.get('keysite', '')
    if not keysite:
        keysite = user_input_keysite()
    return keysite


def patch_ticket_dlc(tikdata):
    tikdata[TK + 0x164:TK + 0x210] = b64decompress('eNpjYGQQYWBgWAPEIgwQNghoADEjELeAMTNE8D8BwEBjAABCdSH/')


def patch_ticket_demo(tikdata):
    tikdata[TK + 0x124:TK + 0x164] = bytes([0x00] * 64)


def make_ticket(title_id, title_key, title_version, fulloutputpath, patch_demo=False, patch_dlc=False):
    tikdata = bytearray(TIKTEM)
    tikdata[TK + 0xA6:TK + 0xA8] = title_version
    tikdata[TK + 0x9C:TK + 0xA4] = binascii.a2b_hex(title_id)
    tikdata[TK + 0x7F:TK + 0x8F] = binascii.a2b_hex(title_key)
    # not sure what the value at 0xB3 is... mine is 0 but some i see 5.
    # or 0xE0, the reserved data is...?
    typecheck = title_id[4:8]
    if typecheck == '0002' and patch_demo:
        patch_ticket_demo(tikdata)
    elif typecheck == '000c' and patch_dlc:
        patch_ticket_dlc(tikdata)
    open(fulloutputpath, 'wb').write(tikdata)


def safe_filename(filename):
    """Strip any non-path-safe characters from a filename
    >>> print(safe_filename("Pokémon"))
    Pokémon
    >>> print(safe_filename("幻影異聞録♯ＦＥ"))
    幻影異聞録_ＦＥ
    """
    keep = ' ._'
    return re.sub(r'_+', '_', ''.join(c if (c.isalnum() or c in keep) else '_' for c in filename)).strip('_ ')


def process_title_id(title_id, title_key, name=None, region=None, output_dir=None, retry_count=3, onlinetickets=False, patch_demo=False,
                     patch_dlc=False, simulate=False, tickets_only=False):
    if name:
        dirname = '{} - {} - {}'.format(title_id, region, name)
    else:
        dirname = title_id

    typecheck = title_id[4:8]
    if typecheck == '000c':
        dirname = dirname + ' - DLC'
    elif typecheck == '000e':
        dirname = dirname + ' - Update'

    rawdir = os.path.join('install', safe_filename(dirname))

    if simulate:
        log('Simulate: Would start work in in: "{}"'.format(rawdir))
        return

    log('Starting work in: "{}"'.format(rawdir))

    if output_dir is not None:
        rawdir = os.path.join(output_dir, rawdir)

    if not os.path.exists(rawdir):
        os.makedirs(os.path.join(rawdir))

    # download stuff
    print('Downloading TMD...')

    baseurl = 'http://ccs.cdn.c.shop.nintendowifi.net/ccs/download/{}'.format(title_id)
    tmd_path = os.path.join(rawdir, 'title.tmd')
    if not download_file(baseurl + '/tmd', tmd_path, retry_count):
        print('ERROR: Could not download TMD...')
        print('MAYBE YOU ARE BLOCKING CONNECTIONS TO NINTENDO? IF YOU ARE, DON\'T...! :)')
        print('Skipping title...')
        return

    with open(os.path.join(rawdir, 'title.cert'), 'wb') as f:
        f.write(MAGIC)

    with open(tmd_path, 'rb') as f:
        tmd = f.read()

    title_version = tmd[TK + 0x9C:TK + 0x9E]

    # get ticket from keysite, from cdn if game update, or generate ticket
    if typecheck == '000e':
        print('\nThis is an update, so we are getting the legit ticket straight from Nintendo.')
        if not download_file(baseurl + '/cetk', os.path.join(rawdir, 'title.tik'), retry_count):
            print('ERROR: Could not download ticket from {}'.format(baseurl + '/cetk'))
            print('Skipping title...')
            return
    elif onlinetickets:
        keysite = get_keysite()
        tikurl = '{}/ticket/{}.tik'.format(keysite, title_id)
        if not download_file(tikurl, os.path.join(rawdir, 'title.tik'), retry_count):
            print('ERROR: Could not download ticket from {}'.format(keysite))
            print('Skipping title...')
            return
    else:
        make_ticket(title_id, title_key, title_version, os.path.join(rawdir, 'title.tik'), patch_demo, patch_dlc)

    if tickets_only:
        print('Ticket, TMD, and CERT completed. Not downloading contents.')
        return


    print('Downloading Contents...')
    content_count = int(binascii.hexlify(tmd[TK + 0x9E:TK + 0xA0]), 16)
    
    total_size = 0
    for i in range(content_count):
        c_offs = 0xB04 + (0x30 * i)
        total_size += int(binascii.hexlify(tmd[c_offs + 0x08:c_offs + 0x10]), 16)
    print('Total size is {}\n'.format(bytes2human(total_size)))

    for i in range(content_count):
        c_offs = 0xB04 + (0x30 * i)
        c_id = binascii.hexlify(tmd[c_offs:c_offs + 0x04]).decode()
        c_type = binascii.hexlify(tmd[c_offs + 0x06:c_offs + 0x8])
        expected_size = int(binascii.hexlify(tmd[c_offs + 0x08:c_offs + 0x10]), 16)
        print('Downloading {} of {}.'.format(i + 1, content_count))
        outfname = os.path.join(rawdir, c_id + '.app')
        outfnameh3 = os.path.join(rawdir, c_id + '.h3')

        if not download_file('{}/{}'.format(baseurl, c_id), outfname, retry_count, expected_size=expected_size):
            print('ERROR: Could not download content file... Skipping title')
            return
        if not download_file('{}/{}.h3'.format(baseurl, c_id), outfnameh3, retry_count, ignore_404=True):
            print('ERROR: Could not download h3 file... Skipping title')
            return

    log('\nTitle download complete in "{}"\n'.format(dirname))


def main(titles=None, keys=None, onlinekeys=False, onlinetickets=False, download_regions=False, output_dir=None,
         retry_count=3, patch_demo=True, patch_dlc=True, simulate=False, tickets_only=False):
    print('*******\nFunKiiU {} by cearp and the cerea1killer\n*******\n'.format(__VERSION__))
    titlekeys_data = []

    if download_regions is None:
        print('You need to enter a region code after \'-region\', like \'-region USA\' or \'-region JPN EUR\'')
        sys.exit(0)     
    if download_regions and (titles or keys):
        print('If using \'-region\', don\'t give Title IDs or keys, it gets all titles from the keysite')
        sys.exit(0)
    if keys and (len(keys)!=len(titles)):
        print('Number of keys and Title IDs do not match up')
        sys.exit(0)
    if titles and (not keys and not onlinekeys and not onlinetickets):
        print('You also need to provide \'-keys\' or use \'-onlinekeys\' or \'-onlinetickets\'')
        sys.exit(0)


    if download_regions or onlinekeys or onlinetickets:        
        while True:
            keysite = get_keysite()
            print(u'Downloading/updating data from {}'.format(keysite))
            try:
                if not download_file('{}/json'.format(keysite), 'titlekeys.json', retry_count):
                    print('\nERROR: Could not download data file...')
                    if ask_update_keysite():
                        user_input_keysite()
                else:
                    break
            except ValueError:
                print('\nThe saved keysite doesn\'t appear to be a valid url.')
                if ask_update_keysite():
                    user_input_keysite()
                    
        print('Downloaded data OK!')

        with open('titlekeys.json') as data_file:
            titlekeys_data = json.load(data_file)

    for title_id in titles:
        title_id = title_id.lower()
        if not check_title_id(title_id):
            print('The Title ID(s) must be 16 hexadecimal characters long')
            print('{} - is not ok.'.format(title_id))
            sys.exit(0)
        title_key = None
        name = None
        region = None

        patch = title_id[4:8] == '000e'

        if keys:
            title_key = keys.pop()
            if not check_title_key(title_key):
                print('The key(s) must be 32 hexadecimal characters long')
                print('{} - is not ok.'.format(title_id))
                sys.exit(0)
        elif onlinekeys or onlinetickets:
            title_data = next((t for t in titlekeys_data if t['titleID'] == title_id.lower()), None)

            if not patch:
                if not title_data:
                    print("ERROR: Could not find data on {} for {}, skipping".format(keysite, title_id))
                    continue
                elif onlinetickets:
                    if title_data['ticket'] == '0':
                        print('ERROR: Ticket not available on {} for {}'.format(keysite,title_id))
                        continue

                elif onlinekeys:
                    title_key = title_data['titleKey']

            if title_data:
                name = title_data.get('name', None)
                region = title_data.get('region', None)

        if not (title_key or onlinetickets or patch):
            print('ERROR: Could not find title or ticket for {}'.format(title_id))
            continue

        process_title_id(title_id, title_key, name, region, output_dir, retry_count, onlinetickets, patch_demo, patch_dlc, simulate, tickets_only)

    if download_regions:
        for title_data in titlekeys_data:
            title_id = title_data['titleID']
            title_key = title_data.get('titleKey', None)
            name = title_data.get('name', None)
            region = title_data.get('region', None)
            typecheck = title_id[4:8]
 
            if not region or (region not in download_regions):
                continue
            #only get games+dlcs+updates
            if typecheck not in ('0000', '000c', '000e'):
                continue
            if onlinetickets and (not title_data['ticket']):
                continue
            elif onlinekeys and (not title_data['titleKey']):
                continue

            process_title_id(title_id, title_key, name, region, output_dir, retry_count, onlinetickets, patch_demo, patch_dlc, simulate, tickets_only)


def log(output):
    output = output.encode(sys.stdout.encoding, errors='replace')
    if sys.version_info[0] == 3:
        output = output.decode(sys.stdout.encoding, errors='replace')
    print(output)


if __name__ == '__main__':
    arguments = parser.parse_args()
    main(titles=arguments.titles,
         keys=arguments.keys,
         onlinekeys=arguments.onlinekeys,
         onlinetickets=arguments.onlinetickets,
         download_regions=arguments.download_regions,
         output_dir=arguments.output_dir,
         retry_count=arguments.retry_count,
         patch_demo=arguments.patch_demo,
         patch_dlc=arguments.patch_dlc,
         simulate=arguments.simulate,
         tickets_only=arguments.tickets_only)
