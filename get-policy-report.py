#!/usr/bin/env python
# ========================================================================
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
# ========================================================================
# Requests library is not standard and
# may require extra install.
# Run the following at a command prompt (linux/macOS)
# ========================================================================
# pip install requests
# ========================================================================
# TODO
# - Add string output formatting

# This code is based on interactions with Panorama.


try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    raise ValueError('requests support not available, please install module')
import xml.etree.ElementTree as ET
import re


# Default for management ports on Palo Alto Networks devices.


fwip = '192.168.0.1'
username = 'admin'
password = 'admin'

# Initializing default generate key url

keycall = "https://%s/api/?type=keygen&user=%s&password=%s" % (fwip,username,password)


def getfwipfqdn():
    while True:
        try:
            fwipraw = raw_input("Please enter an IP or FQDN: ")
            ipr = re.match(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$", fwipraw)
            fqdnr = re.match(r"(?=^.{4,253}$)(^((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$)", fwipraw)
            if ipr:
                print("IPv4 Success")
                break
            elif fqdnr:
                print("FQDN Success")
                break
            else:
                print("There was something wrong with your entry. Please try again.\n")
        except:
            print("There was some kind of problem entering your IP or FQDN. Please try again.\n")
    return fwipraw


def getuname():
    while True:
        try:
            username = raw_input("Please enter a user name (note, must have API access): ")
            usernamer = re.match(r"^[a-z0-9_-]{3,24}$", username) # 3 - 24 characters {3,24}
            if usernamer:
                print("Success")
                break
            else:
                print("There was something wrong with your entry. Please try again.\n")
        except:
            print("There was some kind of problem entering your user name. Please try again.\n")
    return username

def getpass():
    while True:
        try:
            password = raw_input("Please enter your password: ")
            passwordr = re.match(r"^.{5,50}$",password) # simple validate PANOS has no password characterset restrictions
            if passwordr:
                print("Success")
                break
            else:
                print("There was something wrong with your entry. Please try again.\n")
        except:
            print("There was some kind of problem entering your password. Please try again.\n")
    return password


def getkey(fwip):
    try:
        fwipgetkey = fwip
        username = getuname()
        password = getpass()
        keycall = "https://%s/api/?type=keygen&user=%s&password=%s" % (fwipgetkey,username,password)
        r = requests.get(keycall, verify=False)
        tree = ET.fromstring(r.text)
        if tree.get('status') == "success":
            apikey = tree[0][0].text
    except requests.exceptions.ConnectionError as e:
        print("There was a problem connecting to the firewall.  Please check the connection information and try again.")
    return apikey

def getpolicy(passkey,fwip):
    try:
        type = "config"
        action = "get"
        devicegroup = "Shared"
        fwkey = passkey
        fwipl = fwip
        xpath = "/config/shared/pre-rulebase/security"
        call = "https://%s/api/?type=%s&action=%s&xpath=%s&key=%s" % (fwipl, type, action, xpath, fwkey)
        r = requests.get(call, verify=False)
        with open('policydump.xml', 'w') as f:
            f.write(r.text)
            f.close()
    except requests.exceptions.ConnectionError as e:
        print("There was a problem in getting your objects. \n Please vent frustrations in a safe manner and throw a candy bar at the wall! \n If this is helpful the error was captured as: " + e)

def main():
    try:
        fwip = getfwipfqdn()
        mainkey = getkey(fwip)
        results = getpolicy(mainkey,fwip)
        print("\npolicydump.xml was created from" + " " + fwip + " Successfully\n")
        print("========================Please Note================================\n")
        print("                  This file is a raw dump!\n")
        print("========================Please Note================================")
    except:
        print("Something happened and your output didn't.")


if __name__ == "__main__":
    main()
