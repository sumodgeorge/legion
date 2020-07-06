"""
LEGION (https://govanguard.com)
Copyright (c) 2020 GoVanguard

    This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public
    License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later
    version.

    This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
    warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
    details.

    You should have received a copy of the GNU General Public License along with this program.
    If not, see <http://www.gnu.org/licenses/>.
"""
import requests, json

from db.entities.host import hostObj
from db.entities.port import portObj
from db.entities.service import serviceObj
from db.entities.osint import osintObj
from db.repositories.HostRepository import HostRepository


class RiskIQ(object):
    def __init__(self, auth, baseUrl='https://api.passivetotal.org'):
        if auth:
            self.auth = (auth['username'], auth['apiKey'])
        else:
            self.auth = ("","")
        print("\nRISK IQ SCRIPT GOT AUTH: ", auth, "END AUTH\n")
        self.baseUrl = baseUrl
        self.basePath = {
            'account': '/v2/account',
            'project': '/v2/project',
            'artifact': '/v2/artifact',
            'monitor': '/v2/monitor',
            'actions': '/v2/actions',
            'enrichment': '/v2/enrichment',
            'trackers': '/v2/trackers/search',
            'whois': '/v2/whois',
            'hostAttributes': '/v2/host-attributes',
            'dns': '/v2/dns',
            'ssl': '/v2/ssl-certificate',
            'services': '/v2/services'
        }

    # Request builders
    
    def get(self, path, query=None):
        if query:
            response = requests.get(self.baseUrl + path, auth=self.auth, json=query)
        else:
            response = requests.get(self.baseUrl + path, auth=self.auth)
        return response.json()
    
    def post(self, path, payload):
        response = requests.post(self.baseUrl + path, auth=self.auth, json=payload)
        return response.json()
    
    def delete(self, path, query):
        response = requests.delete(self.baseUrl + path, auth=self.auth, json=query)
        return response.json()

    def put(self, path, resource):
        response = requests.put(self.baseUrl + path, auth=self.auth, json=resource)
        return response.json()
    
    # Accounts

    def account(self):
        path = self.basePath['account']
        return self.get(path)

    def getAccountHistory(self):
        path = self.basePath['account'] + '/history'
        return self.get(path)

    def getAccountMonitors(self):
        path = self.basePath['account'] + '/monitors'
        return self.get(path)

    def getAccountOrg(self):
        path = self.basePath['account'] + '/organization'
        return self.get(path)

    def getAccountQuotas(self):
        path = self.basePath['account'] + '/quota'
        return self.get(path)

    def getAccountSources(self, source):
        path = self.basePath['account'] + '/sources'
        return self.get(path, {'source': source})

    def getAccountTeamstream(self, data):
        path = self.basePath['account'] + '/organization/teamstream'
        return self.get(path, data)

    def getAccountClassifications(self, classification):
        path = self.basePath['account'] + '/classifications'
        return self.get(path, {'classification': classification})
    
    # Projects
    
    def getProject(self, data={'success': False}):
        path = self.basePath['project']
        return self.get(path, data)
        
    
    def createProject(self, data):
        path = self.basePath['project']
        return self.put(path, data)
    
    def deleteProject(self, data):
        path = self.basePath['project']
        return self.delete(path, {'project': data})

    def updateProject(self, data):
        path = self.basePath['project']
        return self.post(path, data)

    # Project Tags

    def setProjectTags(self, project, tags):
        path = self.basePath['project'] + '/tag'
        return self.put(path, {'project': project, 'tags': tags})

    def removeProjectTags(self, project, tags):
        path = self.basePath['project'] + '/tag'
        return self.delete(path, {'project': project, 'tags': tags})

    def addProjectTags(self, project, tags):
        path = self.basePath['project'] + '/tag'
        return self.post(path, {'project': project, 'tags': tags})

    # Artifacts

    def getArtifact(self, data=None):
        path = self.basePath['artifact']
        return self.get(path, data)
    
    def createArtifact(self, data, isBulk=False):
        path = self.basePath['artifact']
        if isBulk:
            path += '/bulk'
        return self.put(path, data)
    
    def deleteArtifact(self, artifact, isBulk=False):
        path = self.basePath['artifact']
        if isBulk:
            path += '/bulk'
        return self.delete(path, {'artifact': artifact})

    def updateArtifact(self, data, isBulk=False):
        path = self.basePath['artifact']
        if isBulk:
            path += '/bulk'
        return self.post(path, data)

    # Artifact Tags

    def setArtifactTags(self, artifact, tags):
        path = self.basePath['artifact'] + '/tag'
        return self.put(path, {'artifact': artifact, 'tags': tags})

    def removeArtifactTags(self, artifact, tags):
        path = self.basePath['artifact'] + '/tag'
        return self.delete(path, {'artifact': artifact, 'tags': tags})

    def addArtifactTags(self, artifact, tags):
        path = self.basePath['artifact'] + '/tag'
        return self.post(path, {'artifact': artifact, 'tags': tags})
    
    def getArtifactTags(self, artifact):
        path = self.basePath['artifact'] + '/tag'
        return self.get(path, {'artifact': artifact})

    # Monitor

    def getAlerts(self, data):
        path = self.basePath['monitor']
        return self.get(path, data)

    # Actions

    def getClassificationStatus(self, domain, isBulk=False):
        path = self.basePath['actions']
        if isBulk:
             path += '/bulk'
        path += '/classification'
        return self.get(path, {'query': domain})
    
    def getCompromisedStatus(self, domain):
        path = self.basePath['actions'] + '/server-compromized'
        return self.get(path, {'query': domain})

    def getDynamicDNSStatus(self, domain):
        path = self.basePath['actions'] + '/dynamic-dns'
        return self.get(path, {'query': domain})
    
    def getMonitorStatus(self, domain):
        path = self.basePath['actions'] + '/monitor'
        return self.get(path, {'query': domain})

    def getSinkholeStatus(self, ip):
        path = self.basePath['actions'] + '/sinkhole'
        return self.get(path, {'query': ip})
    
    def setClassificationStatus(self, domain, classification, iskBulk=False):
        path = self.basePath['actions']
        if isBulk:
             path += '/bulk'
        path += '/classification'
        return self.post(path, {'query': domain, 'classification': classification})

    def setCompromisedStatus(self, domain, status):
        path = self.basePath['actions'] + '/server-compromized'
        return self.post(path, {'query': domain, 'status': status})

    def setDynamicDNSStatus(self, domain, status):
        path = self.basePath['actions'] + '/dynamic-dns'
        return self.post(path, {'query': domain, 'status': status})

    def setSinkholeStatus(self, ip, status):
        path = self.basePath['actions'] + '/sinkhole'
        return self.post(path, {'query': ip, 'status': status})

    # Action Tags

    def setActionTags(self, action, tags):
        path = self.basePath['actions'] + '/tag'
        return self.put(path, {'query': action, 'tags': tags})

    def removeActionTags(self, action, tags):
        path = self.basePath['actions'] + '/tag'
        return self.delete(path, {'query': action, 'tags': tags})

    def addActionTags(self, action, tags):
        path = self.basePath['actions'] + '/tag'
        return self.post(path, {'query': action, 'tags': tags})
    
    def getActionTags(self, action):
        path = self.basePath['actions'] + '/tag'
        return self.get(path, {'query': action})

    def searchActionTags(self, tag):
        path = self.basePath['actions'] + '/tag/search'
        return self.get(path, {'query': tag})

    # Enrichment

    def getEnrichment(self, domain, isBulk=False):
        path = self.basePath['enrichment']
        if isBulk:
            path += '/bulk'
        return self.get(path, {'query': domain})

    def getMalware(self, domain, isBulk=False):
        path = self.basePath['enrichment'] + '/malware'
        if isBulk:
            path += '/bulk'
            response = self.get(path, {'query': domain})
            return self.results(response)
        return self.results(response)
    
    def getOSINT(self, domain, isBulk=False):
        path = self.basePath['enrichment'] + '/osint'
        if isBulk:
            path += '/bulk'
            response = self.get(path, {'query': domain})
            return self.results(response)
        return self.results(response)
    
    def getSubdomains(self, domain):
        path = self.basePath['enrichment'] + 'subdomains'
        response = self.get(path, {'query': domain})
        return self.results(response, keyName='subdomains')

    # Trackers

    def getTrackers(self, domain, trackerType):
        path = self.basePath['trackers']
        return self.get(path, {'query': domain, 'type': trackerType})

    # Whois

    def getWhois(self, domain):
        path = self.basePath['whois']
        return self.get(path, {'query': domain})

    def searchWhois(self, domain, field=None, isKeywordSearch=True):
        path = self.basePath['whois'] + '/search'
        if isKeywordSearch:
            path += '/keyword'
            return self.results(self.get(path, {'query': domain}), requireSuccess=False)
        else:
            return self.results(self.get(path, {'query': domain, 'field': field}), requireSuccess=False)

    # Host Attributes

    def getHostComponents(self, data):
        path = self.basePath['hostAttributes'] + '/components'
        response = self.get(path, data)
        return self.results(response)
    
    def getHostPairs(self, data):
        path = self.basePath['hostAttributes'] + '/pairs'
        return self.get(path, data)

    def getHostTrackers(self, domain):
        path = self.basePath['hostAttributes'] + '/trackers'
        return self.get(path, data)

    # Passive DNS

    def getPassiveDNS(self, data, isUnique=False):
        path = self.basePath['dns'] + '/passive'
        if isUnique:
            path += '/unique'
            return self.get(path, data)
        return self.results(self.get(path, data, requireSuccess=False))

    def searchPassiveDNS(self, keyword):
        path = self.basePath['dns'] + '/passive/search/keyword'
        return self.results(self.get(path, {'query': keyword}), requireSuccess=False)

    # SSL Certificates

    def getSSLCertHistory(self, hashOrIP):
        path = self.basePath['ssl'] + '/history'
        response = self.get(path, {'query': hashOrIP})
        return self.results(response)
    
    def getSSLCert(self, hash):
        path = self.basePath['ssl']
        return self.get(path, {'query': hash})
    
    def searchSSLCert(self, key, value = None, isKeywordSearch = False):
        path = self.basePath['ssl'] + '/search'
        if isKeywordSearch:
            path += '/keyword'
            return self.get(path, {'query': key})
        else:
            return self.get(path, {'field': key, 'query': value})

    # Services

    def getServices(self, ip):
        path = self.basePath['services']
        response = self.get(path, {'query': ip})
        return self.results(response)

    # Helpers

    def getHostInformation(self, ip):
        hostInfo = { 'enrichment': self.getEnrichment(ip),
            'components': self.getHostComponents(ip),
            'services': self.getServices(ip),
            'dns': self.getPassiveDNS(ip),
            'certificates': [],
            'malware': [],
            'osint': []
        }
        
        # Malware Information
        classification = hostInfo['enrichment']['classification']
        if  classification == 'malicious' or classification == 'suspicious':
            hostInfo['malware'] = self.getMalware(ip)
            hostInfo['osint'] = self.getOSINT(ip)

        # Certificate Information
        certificateHistory = self.getSSLCertHistory(ip).results
        for record in certificateHistory:
            hostInfo.certificates.append(self.getSSLCert(record['sha1']))

        return hostInfo

    def results(self, response, requireSuccess=True, keyName='results'):
        if requireSuccess:
            if response['success']:
                return response[keyName]
            else:
                return []
        elif response[keyName]:
            return response[keyName]
        else:
            return []

class riskIQScript():
    def __init__(self, creds=None):
        self.dbHost = None
        self.session = None
        self.creds = creds

    def setDbHost(self, dbHost):
        self.dbHost = dbHost
    
    def setSession(self, session):
        self.session = session
    
    def run(self):
        print("Running passivetotal.org RiskIQ script")
        if self.dbHost:
            if self.dbHost.ip:
                iq = RiskIQ(self.creds)
                hostExtrainfo = []
                hostInformation = iq.getHostInformation(self.dbHost.ip)
                print('\n\nGOT HOST INFORMATION: \n', hostInformation, " END HOST INFO\n\n")

                hostExtrainfo.append(hostInformation)

                # Create new OSINT entities
                if hostInformation['osint']:
                    dbOsints = self.session.query(osintObj).filter_by(osintObj.hostId = self.dbHost.id).all()
                    for hostOsint in hostInformation['osint']:
                        if not self.anyDupe(dbOsints, 'sourceUrl'):
                            self.session.add(osintObj(osint['source'], hostOsint['sourceUrl'], tags=hostOsint['tags'], self.dbHost.id))

                # Ports and service entities
                if hostInformation.get('services', {}).get('currentServices', {}):
                    dbPorts = self.session.query(portObj).filter(portObj.hostId == self.dbHost.id).all()
                    for hostPort in hostInformation['services']:
                        if self.anyDupe(dbPorts, hostPort, 'portId'):
                            # There already is a port. See if we need to make any missing services.
                            dbServices = self.session.query(serviceObj).filter(serviceObj.port == dbPort.id).filter().all()
                            for hostService in hostPort['currentServices']:
                                if not self.anyDupe(dbServices, hostService, 'name', dataKey='label'):
                                    # Its not a duplicate service. Create it.
                                    name = hostService['category'] + ' - ' + hostService['label']
                                    extrainfo = {
                                        'currentService': {
                                            'firstSeen': hostService['firstSeen'],
                                            'lastSeen': hostService['lastSeen']
                                        }
                                        'banners': json.dumps(hostPort['banners']),
                                        'recentServices': json.dumps(hostPort['recentServices'])
                                    }
                                    self.session.add(serviceObj(name, hostService['label'], hostService['version'], json.dumps(extraInfo)))
                        else:
                            # We need to make a port. Then the services.
                            portNumber = hostPort['portNumber']
                            protocol = ''
                            if portNumber == 80:
                                protocol = 'http'
                            elif portNumber == 443:
                                protocol = 'https'
                            elif hostPort['protocol']:
                                protocol = hostPort['protocol']
                            
                            newPort = portObj(portNumber, protocol, hostPort['status'])
                            self.session.add(newPort)
                            self.session.flush() # We need to flush the uncommited changes to get the ID for the newPort.
                            # No need to check the new port for existing services. Create each one returned by RiskIQ.
                            for hostService in hostPort['currentServices']:
                                name = hostService['category'] + ' - ' + hostService['label']
                                extrainfo = {
                                    'currentService': {
                                        'firstSeen': hostService['firstSeen'],
                                        'lastSeen': hostService['lastSeen']
                                    }
                                    'banners': json.dumps(hostPort['banners']),
                                    'recentServices': json.dumps(hostPort['recentServices'])
                                }
                                self.session.add(serviceObj(name, hostService['label'], hostService['version'], json.dumps(extraInfo), '', newPort.id))

                if self.dbHost.hostname:
                    whois = iq.getWhois(self.dbHost)
                    print('\n\nGOT DOMAIN INFORMATION: ', whois, " END DOMAIN INFO\n\n")
                    hostExtrainfo.append(whois)
                
                self.dbHost.extrainfo = json.dumps(hostExtrainfo)
                self.session.add(self.dbHost)

    def anyDupe(self, db, data, fieldKey, datakey=''):
        if not dataKey:
            dataKey = fieldKey
        isDupe = False
        for dbRecord in db:
            if getattr(dbRecord, fieldKey) == data[dataKey]:
                isDupe = True
                break
        return isDupe



if __name__ == "__main__":
    pass