'''
Written by: Predrag Petrovic <me@predrag.dev>
Purpose: Script is used to validate if traffic flow is allowed by Palo Alto Firewall.
Description: This script will connect to a PAN-OS firewall and check if traffic flow is allowed.
The traffic flow and its parameters are defined in the CSV file called 'validate.csv'.
The script will read the CSV file and for each row it will check if traffic flow is allowed.

The CSV has the following data:
    sourceip: source IP for the traffic flow
    sourcezone: source zone for the traffic flow
    destinationip: destination IP for the traffic flow
    destinationzone: destination zone for the traffic flow
    proto: protocol number, e.g. 17 for UDP and 6 for TCP.
    appid: web-browsing, dns, ssl etc...
    port: 443, 80, 53 etc...
'''

import requests, xmltodict, csv, getpass
from datetime import datetime
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

currentTime = datetime.now().strftime('%Y%m%d%H%M%S')
exeTime = datetime.now().strftime('%H%M%S')

def output(search, Action, RuleName):
    print(search, '\n\t\t\tAction:', Action, "\n\t\t\tRule:", RuleName)

def createCSV(filename):
    pathToCSV = filename + '.csv'
    with open(pathToCSV, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Timestamp", "Message", "Result", "Policy Name"])

def writeCSV(filename, timestamp, message, result, policyname):
    pathToCSV = filename + '.csv'
    with open(pathToCSV, 'a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow([timestamp, message, result, policyname])

def getToken(username, password, url):
    try:
        request = url + '?type=keygen&user=' + username + '&password=' + password
        response = requests.post(request, verify=False)
        dictData = xmltodict.parse(response.content)
        return dictData['response']['result']['key']
    except:
        print('Could not connect to firewall and obtain API key. Please check your credentials and firewall IP address.')

def testPolicy(url, token, SourceIp, DestinationIp, From, To, AppId, DestinationPort, Protocol):
    try:
        request = (url + '?type=op&cmd=<test><security-policy-match><application>'
            + AppId + '</application><source>' + SourceIp + '</source><from>' + From + '</from><to>'
            + To + '</to><destination>' + DestinationIp + '</destination><protocol>' + Protocol
            + '</protocol><destination-port>' + DestinationPort
            + '</destination-port></security-policy-match></test>&key='
            + token)
        response = requests.post(request, verify=False)
        return xmltodict.parse(response.content)
    except Exception as e:
        print('Parsing error: ', e)

def readCsv(filename, url, token):
    try:
        with open("validate.csv", 'r') as file:
            csvReader = csv.reader(file)
            next(csvReader, None) # skipping headers
            for row in csvReader:
                data = testPolicy(url, token, row[0], row[2], row[1], row[3], row[5], row[6], row[4])
                searchData = row[0] + '(' +row[1] + ')' + "->" + row[2] + '(' + row[3] + ')' + ":" + row[6] + ":" + row[5]
                if data['response']['result'] is None:
                    output(searchData, 'No match', 'No match')
                    writeCSV(filename, exeTime, searchData, 'No match', 'No match')
                else:
                    action = data['response']['result']['rules']['entry']['action']
                    ruleName = data['response']['result']['rules']['entry']['@name']
                    writeCSV(filename, exeTime, searchData, action, ruleName)
                    output(searchData, action, ruleName)
    except Exception as e:
        print('Processing error: ', e)

def main():
    user = input('Enter username: ')
    password = getpass.getpass('Enter password: ')
    url = input('Enter IP address of firewall: ')
    port = input('Enter the port number for the management interface: ')

    baseUrl = 'https://' + url + ":" + port + '/api/'

    token = getToken(user, password, baseUrl)
    filename = currentTime + '-' + url
    createCSV(filename)
    readCsv(filename, baseUrl, token)
    print('Result file is saved as: ' + filename + '.csv')

if __name__ == "__main__":
    main()
