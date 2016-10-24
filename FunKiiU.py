#!/usr/bin/python

# FunKiiU 0.95

import sys
import os
import re
import binascii
from struct import unpack, pack
import urllib2
import argparse
import string
import hashlib
import datetime
from collections import namedtuple
from collections import Counter
import json
from pprint import pprint

if not sys.version_info[:2] == (2, 7):
    print '*****\n!!!!!Warning - Only tested with Python 2.7!!!!!\n*****\n'

# Hey.  Why not catch those IndexErrors and throw out some usage when it happens.
# Should catch both improper and lack of argument scenarios.
# If it isn't handled here allow python to handle normally.
def exceptionhandler(exctype, value, traceback):
    if exctype == IndexError:
        parser.print_usage()
    else:
        sys.__excepthook__(exctype, value, traceback)
    
# Set the system exception handler to the above definition.    
sys.excepthook = exceptionhandler

magic = binascii.a2b_hex('00010003704138EFBBBDA16A987DD901326D1C9459484C88A2861B91A312587AE70EF6237EC50E1032DC39DDE89A96A8E859D76A98A6E7E36A0CFE352CA893058234FF833FCB3B03811E9F0DC0D9A52F8045B4B2F9411B67A51C44B5EF8CE77BD6D56BA75734A1856DE6D4BED6D3A242C7C8791B3422375E5C779ABF072F7695EFA0F75BCB83789FC30E3FE4CC8392207840638949C7F688565F649B74D63D8D58FFADDA571E9554426B1318FC468983D4C8A5628B06B6FC5D507C13E7A18AC1511EB6D62EA5448F83501447A9AFB3ECC2903C9DD52F922AC9ACDBEF58C6021848D96E208732D3D1D9D9EA440D91621C7A99DB8843C59C1F2E2C7D9B577D512C166D6F7E1AAD4A774A37447E78FE2021E14A95D112A068ADA019F463C7A55685AABB6888B9246483D18B9C806F474918331782344A4B8531334B26303263D9D2EB4F4BB99602B352F6AE4046C69A5E7E8E4A18EF9BC0A2DED61310417012FD824CC116CFB7C4C1F7EC7177A17446CBDE96F3EDD88FCD052F0B888A45FDAF2B631354F40D16E5FA9C2C4EDA98E798D15E6046DC5363F3096B2C607A9D8DD55B1502A6AC7D3CC8D8C575998E7D796910C804C495235057E91ECD2637C9C1845151AC6B9A0490AE3EC6F47740A0DB0BA36D075956CEE7354EA3E9A4F2720B26550C7D394324BC0CB7E9317D8A8661F42191FF10B08256CE3FD25B745E5194906B4D61CB4C2E000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000526F6F7400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001434130303030303030330000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007BE8EF6CB279C9E2EEE121C6EAF44FF639F88F078B4B77ED9F9560B0358281B50E55AB721115A177703C7A30FE3AE9EF1C60BC1D974676B23A68CC04B198525BC968F11DE2DB50E4D9E7F071E562DAE2092233E9D363F61DD7C19FF3A4A91E8F6553D471DD7B84B9F1B8CE7335F0F5540563A1EAB83963E09BE901011F99546361287020E9CC0DAB487F140D6626A1836D27111F2068DE4772149151CF69C61BA60EF9D949A0F71F5499F2D39AD28C7005348293C431FFBD33F6BCA60DC7195EA2BCC56D200BAF6D06D09C41DB8DE9C720154CA4832B69C08C69CD3B073A0063602F462D338061A5EA6C915CD5623579C3EB64CE44EF586D14BAAA8834019B3EEBEED3790001000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100042EA66C66CFF335797D0497B77A197F9FE51AB5A41375DC73FD9E0B10669B1B9A5B7E8AB28F01B67B6254C14AA1331418F25BA549004C378DD72F0CE63B1F7091AAFE3809B7AC6C2876A61D60516C43A63729162D280BE21BE8E2FE057D8EB6E204242245731AB6FEE30E5335373EEBA970D531BBA2CB222D9684387D5F2A1BF75200CE0656E390CE19135B59E14F0FA5C1281A7386CCD1C8EC3FAD70FBCE74DEEE1FD05F46330B51F9B79E1DDBF4E33F14889D05282924C5F5DC2766EF0627D7EEDC736E67C2E5B93834668072216D1C78B823A072D34FF3ECF9BD11A29AF16C33BD09AFB2D74D534E027C19240D595A68EBB305ACC44AB38AB820C6D426560C000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000526F6F742D43413030303030303033000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000143503030303030303062000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000137A080BA689C590FD0B2F0D4F56B632FB934ED0739517B33A79DE040EE92DC31D37C7F73BF04BD3E44E20AB5A6FEAF5984CC1F6062E9A9FE56C3285DC6F25DDD5D0BF9FE2EFE835DF2634ED937FAB0214D104809CF74B860E6B0483F4CD2DAB2A9602BC56F0D6BD946AED6E0BE4F08F26686BD09EF7DB325F82B18F6AF2ED525BFD828B653FEE6ECE400D5A48FFE22D538BB5335B4153342D4335ACF590D0D30AE2043C7F5AD214FC9C0FE6FA40A5C86506CA6369BCEE44A32D9E695CF00B4FD79ADB568D149C2028A14C9D71B850CA365B37F70B657791FC5D728C4E18FD22557C4062D74771533C70179D3DAE8F92B117E45CB332F3B3C2A22E705CFEC66F6DA3772B000100010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010004919EBE464AD0F552CD1B72E7884910CF55A9F02E50789641D896683DC005BD0AEA87079D8AC284C675065F74C8BF37C88044409502A022980BB8AD48383F6D28A79DE39626CCB2B22A0F19E41032F094B39FF0133146DEC8F6C1A9D55CD28D9E1C47B3D11F4F5426C2C780135A2775D3CA679BC7E834F0E0FB58E68860A71330FC95791793C8FBA935A7A6908F229DEE2A0CA6B9B23B12D495A6FE19D0D72648216878605A66538DBF376899905D3445FC5C727A0E13E0E2C8971C9CFA6C60678875732A4E75523D2F562F12AABD1573BF06C94054AEFA81A71417AF9A4A066D0FFC5AD64BAB28B1FF60661F4437D49E1E0D9412EB4BCACF4CFD6A3408847982000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000526F6F742D43413030303030303033000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000158533030303030303063000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000137A0894AD505BB6C67E2E5BDD6A3BEC43D910C772E9CC290DA58588B77DCC11680BB3E29F4EABBB26E98C2601985C041BB14378E689181AAD770568E928A2B98167EE3E10D072BEEF1FA22FA2AA3E13F11E1836A92A4281EF70AAF4E462998221C6FBB9BDD017E6AC590494E9CEA9859CEB2D2A4C1766F2C33912C58F14A803E36FCCDCCCDC13FD7AE77C7A78D997E6ACC35557E0D3E9EB64B43C92F4C50D67A602DEB391B06661CD32880BD64912AF1CBCB7162A06F02565D3B0ECE4FCECDDAE8A4934DB8EE67F3017986221155D131C6C3F09AB1945C206AC70C942B36F49A1183BCD78B6E4B47C6C5CAC0F8D62F897C6953DD12F28B70C5B7DF751819A98346526250001000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000')
tiktem = binascii.a2b_hex('00010004d15ea5ed15abe11ad15ea5ed15abe11ad15ea5ed15abe11ad15ea5ed15abe11ad15ea5ed15abe11ad15ea5ed15abe11ad15ea5ed15abe11ad15ea5ed15abe11ad15ea5ed15abe11ad15ea5ed15abe11ad15ea5ed15abe11ad15ea5ed15abe11ad15ea5ed15abe11ad15ea5ed15abe11ad15ea5ed15abe11ad15ea5ed15abe11ad15ea5ed15abe11ad15ea5ed15abe11ad15ea5ed15abe11ad15ea5ed15abe11ad15ea5ed15abe11ad15ea5ed15abe11ad15ea5ed15abe11ad15ea5ed15abe11ad15ea5ed15abe11ad15ea5ed15abe11ad15ea5ed15abe11ad15ea5ed15abe11ad15ea5ed15abe11ad15ea5ed15abe11ad15ea5ed15abe11ad15ea5ed15abe11a000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000526f6f742d434130303030303030332d585330303030303030630000000000000000000000000000000000000000000000000000000000000000000000000000feedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedface010000cccccccccccccccccccccccccccccccc00000000000000000000000000aaaaaaaaaaaaaaaa00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010014000000ac000000140001001400000000000000280000000100000084000000840003000000000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000')

##########From https://stackoverflow.com/questions/5783517/downloading-progress-bar-urllib2-python
def chunk_report(bytes_so_far, chunk_size, total_size):
    percent = float(bytes_so_far) / total_size
    percent = round(percent*100, 2)
    sys.stdout.write("Downloaded %d of %d bytes (%0.2f%%)\r" % (bytes_so_far, total_size, percent))
    if bytes_so_far >= total_size:
        sys.stdout.write('\n')

def chunk_read(response, outfname, chunk_size=2*1024*1024, report_hook=None):
    fh = open(outfname,'wb')
    total_size = response.info().getheader('Content-Length').strip()
    total_size = int(total_size)
    bytes_so_far = 0
    data = []
    while 1:
        if report_hook:
            report_hook(bytes_so_far, chunk_size, total_size)
        chunk = response.read(chunk_size)
        bytes_so_far += len(chunk)
        if not chunk:
            break
        fh.write(chunk)
    fh.close()
##########
SYMBOLS = {
    'customary'     : ('B', 'KB', 'MB', 'GB', 'T', 'P', 'E', 'Z', 'Y'),
}
def bytes2human(n, format='%(value).2f %(symbol)s', symbols='customary'):
    n = int(n)
    if n < 0:
        raise ValueError("n < 0")
    symbols = SYMBOLS[symbols]
    prefix = {}
    for i, s in enumerate(symbols[1:]):
        prefix[s] = 1 << (i+1)*10
    for symbol in reversed(symbols[1:]):
        if n >= prefix[symbol]:
            value = float(n) / prefix[symbol]
            return format % locals()
    return format % dict(symbol=symbols[0], value=n)
##########


parser = argparse.ArgumentParser()
parser.add_argument('-outputdir', action='store', dest='output_dir', help='The custom output directory to store output in, if desired')
# parser.add_argument('-nodownload', action='store_false', default=True, dest='download', help='Turn OFF content downloading - will not generate CIA files.')
parser.add_argument('-retry', type=int, default=4, dest='retry_count', choices=range(0, 10), help='How many times a file download will be attempted')
parser.add_argument('-title', nargs='+', dest='specific_titles', help='Give TitleIDs to be specifically downloaded')
parser.add_argument('-key', action='store', dest='key', help='Encrypted Title Key for the Title ID, if used, only the first Title ID is downloaded, multiple titles not supported yet')
# parser.add_argument('-ticketsonly', action='store_true', default=False, dest='ticketsonly', help='Create only tickets, output them all in one folder')
parser.add_argument('-onlinekeys', action='store_true', default=False, dest='onlinekeys', help='Gets latest titlekeys.json file from *theykeysite*, saves (overwrites) it and uses as input')
parser.add_argument('-onlinetickets', action='store_true', default=False, dest='onlinetickets', help='Gets ticket file from *thekeysite*, should create a \'legit\' game')
# parser.add_argument('-offline', action='store_true', default=False, dest='offline', help='Does not download the TMD and set the latest version in the ticket - because title version is not needed but nice to have')
parser.add_argument('-nopatchdlc', action='store_false', default=True, dest='patch_dlc', help='This will disable unlocking all DLC content')
parser.add_argument('-nopatchdemo', action='store_false', default=True, dest='patch_demo', help='This will disable patching the demo play limit')
parser.add_argument('-all', action='store_true', default=False, dest='all', help='Downloads/gets tickets for EVERYTHING from the keyfile')

arguments = parser.parse_args()

tk = 0x140
badinput = False
error = False
titlelist = []

keysite =''
config = {'keysite': ''}
#fallback incase config exists but has junk data
fallback = {'keysite': ''}

try:
    with open('config.json') as f:
        config = json.load(f)
except IOError:
    # generate the file
    with open('config.json', 'w') as f:
        json.dump(fallback, f)

if arguments.onlinekeys is not None or arguments.onlinetickets is not None:
    if hashlib.md5(config['keysite']).hexdigest() == '436b7b232e995e6ebe66f58c44c0a66b':
        keysite = config['keysite']
    else:
        print 'Please type *the* keysite to access online keys and tickets'
        print 'Type something like: \'aaaa.bbbbbbbbb.ccc\', no http:// or quotes'
        checkurl = raw_input().lower
        if hashlib.md5(checkurl).hexdigest() == '436b7b232e995e6ebe66f58c44c0a66b':
            print 'Correct url! Saving to config file...'
            config['keysite'] = checkurl
            keysite = config['keysite']
            with open('config.json', 'w') as f:
                json.dump(fallback, f)
        else:
            print 'Incorrect, exiting. (Will add multiple attempts later, sorry!)'
            sys.exit(0)


#if online keys or tickets are not being used, check that a title id and key have been provided
if (arguments.onlinekeys is None) and (arguments.onlinetickets is None):
    if (arguments.titleid is None) or (arguments.key is None):
        print 'You need to enter a Title ID and Encrypted Title Key'
        sys.exit(0)

if arguments.specific_titles is not None:
    for specific_title in arguments.specific_titles:
        if (len(specific_title) is 16) and all(c in string.hexdigits for c in specific_title):
            titlelist.append(specific_title.lower())
        else:
            print 'The Title ID(s) must be 16 hexadecimal characters long'
            print specific_title + ' - is not ok.'
            print ''
            badinput = True

if arguments.key is not None:
    if (len(arguments.key) is 32) and all(c in string.hexdigits for c in arguments.key):
        pass
    else:
        print 'The Encrytped Title Key must be 32 hexadecimal characters long'
        print arguments.key + ' - is not ok.'
        print ''
        badinput = True

if badinput: #if any input was not ok, quit
    sys.exit(0)


def makeTicket(titleid, key, titleversion, fulloutputpath):
    
    tikdata = bytearray(tiktem)
    tikdata[tk+0xA6:tk+0xA8] = titleversion
    tikdata[tk+0x9C:tk+0xA4] = binascii.a2b_hex(titleid)
    tikdata[tk+0x7F:tk+0x8F] = binascii.a2b_hex(key)
    #not sure what the value at 0xB3 is... mine is 0 but some i see 5.
    #or 0xE0, the reserved data is...?
    typecheck = titleid[4:8]
    if (typecheck == '0002'):
        if(arguments.patch_demo):
            tikdata[tk+0x124:tk+0x164] = binascii.a2b_hex('00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000')
    elif (typecheck == '000c'):
        if(arguments.patch_dlc):
            tikdata[tk+0x164:tk+0x210] = binascii.a2b_hex('00010014000000ac000000140001001400000000000000280000000100000084000000840003000000000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000')

    open(fulloutputpath,'wb').write(tikdata)


def processTitleID(titleid, key):

    if(arguments.output_dir is not None):
        rawdir = os.path.join(arguments.output_dir, 'output', titleid)
    else:
        rawdir = os.path.join('output', titleid)

    if not os.path.exists(rawdir):
        os.makedirs(os.path.join(rawdir))

    tikdata = bytearray(tiktem)

    #download stuff
    print 'Downloading TMD...'

    baseurl = 'http://ccs.cdn.c.shop.nintendowifi.net/ccs/download/' + titleid
    for attempt in range(arguments.retry_count+1):
        try:
            if(attempt > 0):
                print '*Attempt ' + str(attempt+1) + ' of ' + str(arguments.retry_count+1)
            tmd = urllib2.urlopen(baseurl + '/tmd')
        except urllib2.URLError, e:
            print 'Could not download TMD...'
            error = True
            continue
        error = False
        print 'Downloaded TMD OK!'
        break

    if error:
        print 'ERROR: Could not download TMD. Skipping title...\n'

    if not error:
        tmd = tmd.read()
        titleversion = tmd[tk+0x9C:tk+0x9E]

        #get ticket from keysite, or generate ticket
        if arguments.onlinetickets:
            tikurl = 'https://' + keysite + '/ticket/' + titleid + '.tik'
            for attempt in range(arguments.retry_count+1):
                try:
                    if(attempt > 0):
                        print '*Attempt ' + str(attempt+1) + ' of ' + str(arguments.retry_count+1)
                    onlinetik = urllib2.urlopen(tikurl)
                except urllib2.URLError, e:
                    print 'Could not download ticket from ' + keysite
                    error = True
                    continue
                error = False
                print 'Downloaded TMD OK!'
                onlinetik = onlinetik.read()
                open(os.path.join(rawdir, 'title.tik'),'wb').write(onlinetik)
                break
        else:
            makeTicket(titleid, key, titleversion, os.path.join(rawdir, 'title.tik'))


        open(os.path.join(rawdir, 'title.cert'),'wb').write(magic)
        open(os.path.join(rawdir, 'title.tmd'),'wb').write(tmd)

        print 'Downloading Contents...'
        contentCount = int(binascii.hexlify(tmd[tk+0x9E:tk+0xA0]),16)
        for i in xrange(contentCount):
            if not error:
                cOffs = 0xB04+(0x30*i)
                cID = binascii.hexlify(tmd[cOffs:cOffs+0x04])
                print 'Downloading ' + str(i+1) + ' of ' + str(contentCount) + '. This file is ' + bytes2human(int(binascii.hexlify(tmd[cOffs+0x08:cOffs+0x10]),16))
                outfname = os.path.join(rawdir, cID + '.app')
                outfnameh3 = os.path.join(rawdir, cID + '.h3')
                
                for attempt in range(arguments.retry_count+1):
                    try:
                        if(attempt > 0):
                            print 'Attempt ' + str(attempt+1) + ' of ' + str(arguments.retry_count+1)
                        response = urllib2.urlopen(baseurl + '/' + cID)
                        chunk_read(response, outfname, report_hook=chunk_report)
                        if (int(os.path.getsize(outfname)) != int(binascii.hexlify(tmd[cOffs+0x08:cOffs+0x10]),16) ):
                            print 'Content download not correct size\n'
                            continue
                    except urllib2.URLError, e:
                        print 'Could not download content file...\n'
                        error = True
                        continue
                    error = False
                    break

                #get pesky h3 files, as ugly as just seeing if they exist? (since not every content file seems to have one i think?)
                for h3attempt in range(arguments.retry_count+1): #i could keep 'attempt' name instead of 'h3attempt'
                    try:
                        h3file = urllib2.urlopen(baseurl + '/' + cID + '.h3')
                        h3file = h3file.read()
                        open(outfnameh3,'wb').write(h3file)
                    except urllib2.URLError, e:
                        continue
                    break

                if error:
                    print 'ERROR: Could not download content file... Skipping title'             
        

        if not error:
            print '\nTitle download complete\n'

                

print '*******\nFunKiiU by cearp\n*******\n'



if arguments.onlinekeys or arguments.onlinetickets:
    print 'Downloading/updating data from ' + keysite
    url = 'https://' + keysite + '/json'
    for attempt in range(arguments.retry_count+1):
        try:
            if(attempt > 0):
                print '*Attempt ' + str(attempt+1) + ' of ' + str(arguments.retry_count+1)
            thekeyfile = urllib2.urlopen(url)
        except urllib2.URLError, e:
            print 'Could not download file...'
            error = True
            continue
        error = False
        break

    if error:
        print 'ERROR: Could not download data file... Exiting.\n'

    if not error:
        thekeyfile = thekeyfile.read()
        open(os.path.join('titlekeys.json'),'wb').write(thekeyfile)
        print 'Downloaded data OK!'

    with open('titlekeys.json') as data_file:    
        data = json.load(data_file)
        for item in data:
            titleid = item["titleID"]
            key = item["titleKey"]
            
            ticketexists = item["ticket"]

            typecheck = titleid[4:8]

            if arguments.all:
                #skip updates
                if (typecheck == '000e'):
                    continue
                #skip system
                if (int(typecheck,16) & 0x10):
                    continue
                elif (typecheck == '8005'):
                    continue
                elif (typecheck == '800f'):
                    continue



            if (titleid in titlelist):
                #if we want the ticket, but it doesn't exist, skip
                if arguments.onlinetickets:
                    if not ticketexists:
                        print 'ERROR: Cannot find ticket on ' + keysite '\n'
                        continue
                #if we want key, check if it exists + ok, else skip
                if arguments.onlinekeys:
                    if key and (len(key) is 32) and all(c in string.hexdigits for c in key):
                        pass
                    else:
                        print 'ERROR: No key/bad key on ' + keysite '\n'
                        continue
                processTitleID(titleid, key)

            if arguments.all:
                if arguments.onlinetickets:
                    if not ticketexists:
                        continue
                if arguments.onlinekeys:
                    if key and (len(key) is 32) and all(c in string.hexdigits for c in key):
                        pass
                    else:
                        continue
                processTitleID(titleid, key)


else:
    processTitleID(titlelist[0], arguments.key)