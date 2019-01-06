#!/usr/bin/env python

import json
import requests
import os.path
import datetime
import base64
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

"""
The script emulates classical DHCP snooping functionality in BCF. It collects info about 
DHCP offers by Analytics Node API and blocks DHCP servers what aren't in a whitelist. 
Additionally, it blocks affected DHCP clients, what have recieved IPv4 configuration from 
rogue DHCP servers.

The logic is:
1. The script is started periodically and collects info about last DHCP OFFERs by BMF Analytics 
Node API (except what were produced by legal DHCP servers (ClassScriptConfig.legal_dhcp_list). 
The period to collect DHCP offers is managed by ClassScriptConfig.start_time and should be equal 
to script's schedule period.
2. If illegal DHCP OFFERs were existed, script creates BCF static endpoints for rogue DHCP server
and shuts down it (special thanks to @Salman Zahid for the idea).
3. For each illegal DHCP server script collects info about produced DHCP ACK, creates static 
endpoint for the affected clients and shuts their down if they are exist. This behaviour works 
only if rogue DHCP server or affected DHCP client aren't static endpoint (the idea is if it is static, 
then ops know what it is and it is legal)

For any questions or comments please contact by aleksandr.shilkin@bigswitch.com

"""



class ClassScriptConfig():
  """
  The class for script configuration. Please change the folloing parameters if it
  is needed.
  """
  def __init__(self):
    # The BCF controller section. If account's cookie exist,
    # it is more preferable then username/password
    self.controller_ip = '192.168.10.21'
    self.controller_username = 'admin'
    self.controller_password = 'admin'
    self.controller_api_cookie = ''
    self.contorller_api_port = '8443'
    self.controller_api_login_path = '/api/v1/auth/login'
    self.tenant = 'se.bsn.vpc'

    # The BMF analytics node section
    self.analytics_ip = '192.168.70.33'
    self.analytics_username = 'admin'
    self.analytics_password = 'bsn123'
    self.analytics_api_port = '443'
    self.AnalyticsNode_search_url = '/es/api/dhcp-*/_search'
    
    # The legal DHCP servers list
    self.legal_dhcp_list = ['10.0.4.20']
    
    # How often the script will be started by external scheduler (in seconds)
    schedule_period = 5000
    self.start_time = datetime.datetime.today() - datetime.timedelta(seconds=schedule_period)

    # These prefixes will be used for BCF static endpoints
    self.rogue_dhcp_server_prefix = 'ILLEGAL_DHCP_SERVER'
    self.affected_dhcp_client_prefix = 'AFFECTED_DHCP_CLIENT'

  def api_login(self, api_type = 'Controller'):
      """
      Just internal function to get API token. There are different ways for 
      BCF controller and BMF analytics node (HTTP Basic auth)
      """
      if api_type == 'Controller':
        if self.controller_api_cookie:
          session_cookie = self.controller_api_cookie
        else:
          url = 'https://{}:8443{}'.format(self.controller_ip, self.controller_api_login_path)
          login_dictionary = {'user': self.controller_username, 'password': self.controller_password}
          data = json.dumps(login_dictionary)
          headers = {'content-type': 'application/json'}
          try:
              response = requests.request('POST', url, data = data, headers=headers, verify=False)
              session_cookie = response.json()['session_cookie']
          except:
              session_cookie = None
      if api_type == 'Analytics':
        session_cookie = base64.standard_b64encode('{}:{}'.format(self.analytics_username, self.analytics_password).encode('ASCII')).decode()
      if session_cookie:
        return session_cookie
      else:
        return False
  
  def api_request(self, session_cookie, path, api_type = 'Controller', method = 'GET', data = ''):
      """
      Just internal function to make API call. There are different ways for 
      BCF controller and BMF analytics node 
      """
      if api_type == 'Controller':
        url = 'https://{}:{}{}'.format(self.controller_ip, self.contorller_api_port, path)
        headers = {"content-type": "application/json"}
        headers['Cookie'] = 'session_cookie={}'.format(session_cookie)
      if api_type == 'Analytics':
        url = 'https://{}:{}{}'.format(self.analytics_ip, self.analytics_api_port, path)
        headers = {"content-type": "application/json"}
        headers['Authorization'] = 'Basic {}'.format(session_cookie)
      response = requests.request(method, url, data=data, headers=headers, verify=False)
      return (response)
  
  
  def api_logout(self, session_cookie, api_type = 'Controller'):
      """
      Just internal function to log out from BCF contoller and wipe session token
      """
      if api_type == 'Controller':  
        logout_path = '/api/v1/data/controller/core/aaa/session[auth-token="{}"]'.format(session_cookie)
        url = 'https://{}:{}{}'.format(self.controller_ip, self.contorller_api_port, logout_path)
        headers = {'content-type': 'application/json', 'Cookie': 'session_cookie={}'.format(session_cookie)}
        try:
            response = requests.request('DELETE', url, headers=headers, verify=False)
            return True
        except:
            return False   
    

class ClassAnalyticsNode(ClassScriptConfig):
  """
  The class describes BMF analytics node. Uses ClassScriptConfig as a parrent
  to use configuration parammeters and api methods.
  """
  def __init__(self):
    ClassScriptConfig.__init__(self)
    self.session_cookie = self.api_login(api_type = 'Analytics')
  
  def return_rogue_dhcp_servers_list(self):
    """
    This method is for return list of DHCP servers what aren't in a whitelist
    The method retruns list of strings (DHCP IP address).
    """
    for counter, legal_dhcp_server in enumerate(self.legal_dhcp_list):
      self.legal_dhcp_list[counter] = {"term": {"siaddr": "{}".format(legal_dhcp_server)}} 
    
    dsl_filter_rogue_dhcp_server =  {
                                      "_source": ["siaddr"],
                                      "size": 1000,
                                      "query": {
                                        "bool": {
                                          "filter": [
                                                      {"term": {"type": "dhcpoffer"}},
                                                      {"range": {"@timestamp": {"gte": "{}".format(self.start_time.isoformat(sep='T'))}}}
                                                    ],
                                          "must_not": self.legal_dhcp_list
                                                }
                                               }
                                    }


    rogue_dhcp_servers_list = list()
    response = self.api_request(session_cookie = self.session_cookie, 
                                path = self.AnalyticsNode_search_url, 
                                api_type = 'Analytics',
                                data = json.dumps(dsl_filter_rogue_dhcp_server)).json()
    if int(response['hits']['total']) > 0:
      for rogue_dhcp_server in response['hits']['hits']:
        if (rogue_dhcp_server['_source']['siaddr'] not in rogue_dhcp_servers_list):
          rogue_dhcp_servers_list.append(rogue_dhcp_server['_source']['siaddr'])
    return (rogue_dhcp_servers_list)

  def return_affected_dhcp_clients_list(self, server_ip):
    """
    This method is for return list of DHCP clients what got IP settings 
    from rogue DHCP servers. It checks DHCP ACKs what were produced by the server 
    by BMF AN API.

    The method uses rogue DHCP server IP address (string) as argument and 
    retruns list of dicts what describe affected DHCP clients.
    The returned format is [{"ip":<dhcp client ip (yiaddr)>, "mac": <dhcp client mac addr>}].
    
    """
    dsl_filter_affected_dhcp_client = {
                                         "_source": ["siaddr", "yiaddr", "chaddr"],
                                         "size": 1000,
                                         "query": {
                                           "bool": {
                                             "filter":  [
                                                         {"term": {"type": "dhcpack"}},
                                                         {"term": {"siaddr": server_ip}},
                                                         {"range": {"@timestamp": {"gte": "{}".format(self.start_time.isoformat(sep='T'))}}}
                                                        ]
                                                    }
                                                  }
                                      }

    affected_dhcp_client_list = list()
    already_seen_dhcp_client_list = list()
    response = self.api_request(session_cookie = self.session_cookie, 
                                path = self.AnalyticsNode_search_url, 
                                api_type = 'Analytics',
                                data = json.dumps(dsl_filter_affected_dhcp_client)).json()
    if int(response['hits']['total']) > 0:
      for dhcp_client in response['hits']['hits']:
        if dhcp_client['_source']['yiaddr'] not in already_seen_dhcp_client_list:
          already_seen_dhcp_client_list.append(dhcp_client['_source']["yiaddr"])
          affected_dhcp_client_list.append({"ip": dhcp_client['_source']["yiaddr"], "mac": dhcp_client['_source']["chaddr"]})
    return affected_dhcp_client_list
      
class ClassBCFController(ClassScriptConfig):
  def __init__(self):
    """
    The class describes BCF controller. Uses ClassScriptConfig as a parrent
    to use configuration parammeters and api methods.
    """
    ClassScriptConfig.__init__(self)
    self.session_cookie =  self.api_login(api_type = 'Controller')
    self.url_collect_endpoint_mac_segment = "/api/v1/data/controller/applications/bcf/info/endpoint-manager/endpoint[tenant='{tenant}']\
                                             /ip-address[ip-address='{ip_address}']?select=segment&select=mac"
    self.url_collect_endpoint_details = "/api/v1/data/controller/applications/bcf/info/endpoint-manager/endpoint[tenant='{tenant}']\
                                         [segment='{endpointSegment}'][mac='{endpointMAC}']?select=ip-address&select=attachment-point&select=attachment-point-state\
                                         &select=vlan&select=name"
  
    self.url_check_endpoint_name = "/api/v1/data/controller/applications/bcf/info/endpoint-manager/endpoint[tenant='{tenant}']?select=name".format(tenant = self.tenant)
    
    # This variable is used to check how many blocked DHCP servers already exist in BCF.
    # This is because the script is stateless and we need to provide unique endpoint name to 
    # each endpoint. The blocked DHCP server format is 
    # "ClassScriptConfig.rogue_dhcp_server_prefix_ClassBCFController.number_of_blocked_dhcp_servers"
    self.number_of_blocked_dhcp_servers = 0
    endpoints_with_name = self.api_request(session_cookie = self.session_cookie,
                                           path = self.url_check_endpoint_name, 
                                           api_type = 'Controller',
                                           method = 'GET',
                                           data = '').json()
    for endpoint in endpoints_with_name:
      if endpoint['name'].startswith(self.rogue_dhcp_server_prefix):
        self.number_of_blocked_dhcp_servers+=1
  
  def return_endpoint_mac_and_segment_by_ip(self, endpointIP):
    """
    This method is to return endpoint's L2 details (mac address and BCF segment) using 
    IPv4 address. It is needed to collect other endpoint details to make endpoint object.

    The method uses IPv4 address (string) as the argument and return list of dicts 
    [{"mac": <endpoint mac address>, "segment: <endpoint segment>"}]
    """
    endpoint_list = list()
    ip_address_url = self.url_collect_endpoint_mac_segment.format(tenant = self.tenant,
                                                             ip_address = endpointIP)
    endpoint_response = self.api_request(session_cookie = self.session_cookie, path = ip_address_url, 
                       api_type = 'Controller', method = 'GET', data = '').json()
    for endpoint_details in endpoint_response:
      endpoint_list.append({"mac": endpoint_details['mac'], "segment": endpoint_details['segment']})

    return endpoint_list


  def return_endpoint (self, endpointMAC, endpointSegment):
    """
    This method is to return endpoint object by mac address and BCF segment. 

    The method uses endpoint MAC (string) and segment (string) as arguments and
    returns endpoint object (ClassBCFEndpoint) 
    """
    endpoint_details_url = self.url_collect_endpoint_details.format(tenant = self.tenant,
                                                                    endpointSegment = endpointSegment,
                                                                    endpointMAC = endpointMAC)

    endpoint_details_response = self.api_request(session_cookie = self.session_cookie,
                                                 path = endpoint_details_url, 
                                                 api_type = 'Controller',
                                                 method = 'GET',
                                                 data = '').json()
    return ClassBCFEndpoint(endpoint_details_response[0])

class ClassBCFEndpoint(ClassScriptConfig):
  def __init__(self, endpoint_details_dict):
    """
    The class describes BCF endpoint. Uses ClassScriptConfig as a parrent
    to use configuration parammeters and api methods.
    """
    ClassScriptConfig.__init__(self)
    self.url_create_endpoint = "/api/v1/data/controller/applications/bcf/tenant[name='{tenant}']/segment[name='{segment}']/endpoint"
    
    # It is needed to create class atributes automatecly, but '-' can't be used as 
    # variable name.
    for argument, value in endpoint_details_dict.items():
      setattr(self, argument.replace('-', '_'), value)

  def is_ip_here(self, interested_ip_address):
    """
    The method to check whether does IP address exist
    in the endpoint object. 

    The method uses interested_ip_address (string) as argument and
    returns boolean.
    """
    for ip_address in self.ip_address:
      if ip_address['ip-address'] == interested_ip_address:
        return True
    else:
      return False

  def make_me_static(self, session_cookie, endpointName, description, do_make_it_shutted_down = False):
    """
    The method is to make the endpoint static. 

    The method uses BCF controller session cookie (string), endpointName (string), description (string) and 
    do_make_it_shutted_down (boolean, do shutted down this endpoint right now or not).

    The method returns True if endpoint created and False if not. 
    """
    self.name = endpointName
    self.description = description
    self.is_shutdown = do_make_it_shutted_down

    if self.attachment_point['type'] == 'interface-group':
      attachment_point_dict = {"interface-group": self.attachment_point['interface-group'], "vlan": self.vlan}
    if self.attachment_point['type'] == 'switch-interface':
       attachment_point_dict = {"interface": self.attachment_point['interface'], "switch": self.attachment_point['switch'], "vlan": self.vlan}
    ip_address_list = list()
    for ip_address in self.ip_address:
      ip_address_list.append({"ip-address": ip_address['ip-address']})
    endpoint_create_url = self.url_create_endpoint.format(tenant = self.tenant,
                                                          segment = self.segment)
    data =  {
                "name": self.name,
                "shutdown": self.is_shutdown,
                "description": self.description,
                "mac": self.mac,
                "attachment-point": attachment_point_dict,
                "ip-address": ip_address_list,
                "origination": "bcf-dhcp-protect-script"
            }
    response = self.api_request(session_cookie = session_cookie, 
                                path = endpoint_create_url, 
                                api_type = 'Controller',
                                method = 'POST',
                                data = json.dumps(data)
                                )

    if response.status_code == '204':
      return False
    else:
      return True

def main():
    """
    To make objects for script isself, analytics node and BCF controller.
    """
    ScriptConfig = ClassScriptConfig()
    AnalyticsNode = ClassAnalyticsNode()
    BCFController = ClassBCFController()

    # Return list of DHCP servers IP addresses (except legal) what produced DHCP OFFER in the period.
    rogue_dhcp_servers_list = AnalyticsNode.return_rogue_dhcp_servers_list()
    
    # MAC address and segment are returned for each DHCP server's IP address
    for rogue_dhcp_server_IP in rogue_dhcp_servers_list:
      rogue_dhcp_server_l2_details = BCFController.return_endpoint_mac_and_segment_by_ip(rogue_dhcp_server_IP)

      # Endpoint object is returned for each DHCP server's MAC address 
      for rogue_dhcp_server_mac_and_segment in rogue_dhcp_server_l2_details:
        dhcp_server = BCFController.return_endpoint(endpointMAC = rogue_dhcp_server_mac_and_segment['mac'],
                                                     endpointSegment = rogue_dhcp_server_mac_and_segment['segment'])
        
        # The static endpoint is created and shutted down for each DHCP server endpoint object if 
        # the existed endpoint isn't static only
        if dhcp_server.attachment_point_state != 'static':
          BCFController.number_of_blocked_dhcp_servers+=1
          if dhcp_server.make_me_static(session_cookie = BCFController.session_cookie,
                                        endpointName = '{}_{}'.format(BCFController.rogue_dhcp_server_prefix,
                                                                   BCFController.number_of_blocked_dhcp_servers),
                                        description = 'This endpoint was created and shutted down because it is illegal DHCP server',
                                        do_make_it_shutted_down = True):
            
            print ('{timestamp} The DCHP server with IP address {dhcp_server_ip} was blocked by ' \
                    'static endpoint {dhcp_server_endpoint_name}'.format(timestamp = datetime.datetime.today().isoformat(sep='T'),
                                                                        dhcp_server_ip = rogue_dhcp_server_IP,
                                                                        dhcp_server_endpoint_name = dhcp_server.name
                                                                        ))
          else:
            print ('{timestamp} Something wrong with making {dhcp_server_ip} static. ' \
                    'Maybe this endpoint already exist'.format(timestamp = datetime.datetime.today().isoformat(sep='T'),
                                                              dhcp_server_ip = rogue_dhcp_server_IP))

          # A list of DHCP clients is returned for the blocked DHCP server.
          affected_dhcp_clients = AnalyticsNode.return_affected_dhcp_clients_list(rogue_dhcp_server_IP)
          
          # The endpoint is returned for each DHCP client
          for dhcp_client in affected_dhcp_clients:
            dhcp_client_endpoint = BCFController.return_endpoint(endpointMAC = dhcp_client['mac'],
                                                                  endpointSegment = rogue_dhcp_server_mac_and_segment['segment'])
            
            # The static endpoint is created and shutted down only if the current BCF endpoint isn't static and
            # IP address from DHCP ACK (yiaddr) exist in the endpoint object.
            if dhcp_client_endpoint.attachment_point_state != 'static' and dhcp_client_endpoint.is_ip_here(dhcp_client['ip']):
              if dhcp_client_endpoint.make_me_static(session_cookie = BCFController.session_cookie,
                                                     endpointName = '{}_{}'.format(dhcp_client_endpoint.affected_dhcp_client_prefix,
                                                                                   dhcp_client_endpoint.mac).replace(':','_'),
                                                     description = 'This endpoint was created and shutted down because this host has got IP settings from illegal DHCP server {}'.format(rogue_dhcp_server_IP),
                                                     do_make_it_shutted_down = True):
                print ('{timestamp} The DCHP client with IP address {dhcp_client_ip} affected by {dhcp_server_ip} was blocked by ' \
                       'static endpoint {dhcp_client_endpoint_name}'.format(timestamp = datetime.datetime.today().isoformat(sep='T'),
                                                                          dhcp_client_ip = dhcp_client['ip'],
                                                                          dhcp_server_ip = rogue_dhcp_server_IP,
                                                                          dhcp_client_endpoint_name = dhcp_client_endpoint.name
                                                                          ))
              else:
                print ('{timestamp} Something wrong with making {dhcp_client_ip} static.' \
                       ' Maybe this endpoint already exist'.format(timestamp = datetime.datetime.today().isoformat(sep='T'),
                                                                  dhcp_client_ip = dhcp_client['ip']))

    # Logout from BCF controller.
    BCFController.api_logout(BCFController.session_cookie)

if __name__ == '__main__':
      main()
