from pox.core import core
from pox.lib.addresses import * 
from pox.lib.packet import *
from pox.lib.recoco.recoco import *
import re

# Get a logger
log = core.getLogger("fw")

FLOWTIMEOUT = 30 #in seconds
DEBUG = False
INC   = False

class Firewall (object):
  """
  Firewall class.
  Extend this to implement some firewall functionality.
  Don't change the name or anything -- the eecore component
  expects it to be firewall.Firewall.
  """
  def merge_search_buffer(self, curr_flow, reverse): 
    if DEBUG:
      if reverse:
        log.debug("in_packet_buffer: " + str(self.in_packet_buffer))
      else:
        log.debug("out_packet_buffer: " + str(self.out_packet_buffer))

    merged_http_packets = ''
    if reverse:
      packet_buffer = self.in_packet_buffer[curr_flow]
    else:
      packet_buffer = self.out_packet_buffer[curr_flow]

    if DEBUG:
      log.debug("packet_buffer: " + str(packet_buffer))
    for http_packet in packet_buffer:
        merged_http_packets += str(http_packet)
    if INC:
      log.debug("merged_http_packets: " + str(merged_http_packets))
      #log.debug("length of merged packets: " + str(len(merged_http_packets)))

    longest_string_len = 0
    dst_addr = curr_flow[2]
    for string in self.monitored_strings[dst_addr]:
      if INC: 
        log.debug("searching for: " + string )

      if longest_string_len < len(string):
        longest_string_len = len(string)

      regex       =  re.compile(r"%s" % string)
      matched     = regex.findall(merged_http_packets)
      num_matched = len(matched)

      curr_string_list = self.flows.get(curr_flow,False)
      if curr_string_list is not False:
        if curr_string_list.get(string, False) is not False:
          self.flows[curr_flow][string] += num_matched
        else:
          self.flows[curr_flow][string] = num_matched
      else:
        self.flows[curr_flow] ={string: num_matched}

      if INC:
          log.debug("Matched %s times" % str(num_matched))
          log.debug("updated flows: " + str(self.flows))
          log.debug("curr_flow: %s \n" % str(curr_flow))
    
    #search and replace
    for string in self.monitored_strings[dst_addr]:
      rep_regex   = (r"%s" % string)
      replaced    = re.sub(rep_regex, '', merged_http_packets)
      if DEBUG:
        log.debug("replaced merged_http_packet: %s for search: %s" %(replaced, string))
      merged_http_packets = replaced

    
    if DEBUG:
      log.debug("longest_string_length: " + str(longest_string_len))
    merged_http_packets = merged_http_packets[-(longest_string_len):]
    if DEBUG:
      log.debug('merged_http_packets after match' + merged_http_packets)
    if reverse:
      self.in_packet_buffer[curr_flow] = [merged_http_packets]
    else:
      self.out_packet_buffer[curr_flow] = [merged_http_packets]
      
   
    if DEBUG:
      #update the current flow's count for the given string
      log.debug("self.flows: " + str(self.flows))
      if reverse:
        log.debug("in_packet_buffer after merge: " + str( self.in_packet_buffer[curr_flow]))
      else:
        log.debug("out_packet_buffer after merge: " + str( self.out_packet_buffer[curr_flow]))



  def cleanup_flow_and_write_count(self, curr_flow):
    if self.timers.get(curr_flow, False) is not False:
      self.timers[curr_flow].cancel()

    flows_keys = self.flows.keys()
    counts = open('/root/pox/ext/counts.txt','a+')
    if DEBUG:
        log.debug("Counts opened" )
        log.debug("curr_flow" + str(curr_flow))
      
    for flow in flows_keys:
      if DEBUG:
        log.debug("all flows: " + str(self.flows) )
        log.debug("curr_flow" + str(curr_flow))
        log.debug("flow: " + str(flow))
        log.debug("[2] :" + str(flow[2] == curr_flow[2]))
      if flow[2] == curr_flow[2]:
        string_list = self.monitored_strings[flow[2]]
        for string in string_list:
          curr_strings = self.flows.get(flow, False)
          if curr_strings is not False:
            curr_count   = curr_strings.get(string, False)
            if curr_count is not False:

              write_string = ("%s,%s,%s,%s\n" % 
                              (flow[2], flow[3],string,curr_count))
              if DEBUG:
                log.debug("will delete flow for " + str(curr_flow))
                log.debug("writing to counts.txt: " + write_string)
              counts.write(write_string)
    counts.close()
            
    if self.flows.get(curr_flow, False) is not False:
      del self.flows[curr_flow]
    if self.in_packet_buffer.get(curr_flow, False) is not False:
      del self.in_packet_buffer[curr_flow]
    if self.out_packet_buffer.get(curr_flow, False) is not False:
      del self.out_packet_buffer[curr_flow]
    if self.timers.get(curr_flow, False) is not False:
      del self.timers[curr_flow]
        
  def timeout(self, curr_flow):
    if DEBUG:
      log.debug("Before clean_up timers: " + str(self.timers))
      log.debug("curr_flow: " + str(curr_flow))
      log.debug("self.flows: " + str(self.flows)) 
    flows_keys = self.flows.keys()
    for flow in flows_keys:
      if flow[2] == curr_flow[2]: 
        self.merge_search_buffer(flow, True)  #incoming buff
        self.merge_search_buffer(flow, False) #outgoing buff
    self.cleanup_flow_and_write_count(curr_flow)
    if DEBUG:
      log.debug("TIMEOUT: flow %s has timed_out" % str(curr_flow))
      log.debug("After clean_up timers: " + str(self.timers))

  def is_banned_domain(self, http_domain):
    banned = False
    for b_domain in self.banned_domains:
      split_b_domain = b_domain.split(".")
      split_b_domain.reverse()
      split_http_domain = http_domain.split(".")
      split_http_domain.reverse()
      if DEBUG:
        log.debug("http_domain: " + str(split_http_domain))
        log.debug("b_domain: " + b_domain)
        log.debug("b_domains: " + str(self.banned_domains))
      for seg in split_b_domain:
        if DEBUG:
          log.debug("b_domain seg: " + seg)
        if len(split_http_domain) == 0:
          if DEBUG:
            log.debug("length http_domain is 0")
          return False
        seg_http = split_http_domain.pop(0)
        if DEBUG:
          log.debug("%s equal? %s: %s" % (seg, seg_http, str(seg == seg_http)))
        if seg != seg_http: 
          banned = False
          break
        else:
          banned = True
      if banned:
        return True
    return False

  def match_http_domain(self, string):
    regex = r'HOST:\s*(\S*)\s*\n'
    match = re.search(regex, string, re.M|re.I)
    if match != None:
      http_domain = match.group(1)
      has_port = re.search(r':[\d]*$',http_domain,re.M|re.I)
      if has_port is not None:
        has_port_group = http_domain
        if DEBUG:
          log.debug("has_port_group: " + has_port_group)
        addr,port = has_port_group.split(':',1)
        if DEBUG:
          log.debug("addr, port: " + addr + ", " + port)
        return addr
      else:
        return http_domain
    else:
      return 'No match found'
    
  def extract_flow(self, packet, reverse):
    packet = str(packet)
    regex = r'[\w|\d|:]*\[([\d|\.|>]*)\]\)\{([\d|>]*)}'
    match = re.search(regex, packet, re.M|re.I)

    if match != None:
      ip = match.group(1)
      tcp = match.group(2)
      src,dst = ip.split(">")
      srcport,dstport = tcp.split(">")
      if reverse:
        return (dst,dstport,src,srcport)
      else:
        return (src,srcport,dst,dstport)
      
    else:
      return 'No match found'

  def __init__(self):
    """
    Constructor.
    Put your initialization code here.
    """
    file_ban_ports   = open('/root/pox/ext/banned-ports.txt').read().splitlines()
    file_ban_domains = open('/root/pox/ext/banned-domains.txt').read().splitlines()
    file_monitor_str = open('/root/pox/ext/monitored-strings.txt').read().splitlines()
    self.banned_ports       = {}
    self.banned_domains     = {}
    self.monitored_strings  = {}
    self.flows              = {} 
    self.in_packet_buffer   = {} #ingoing
    self.out_packet_buffer  = {} #outgoing
    self.longest_string     = {}
    self.timers     = {}

    for port in file_ban_ports:
      self.banned_ports[port] = True
    for domain in file_ban_domains:
      self.banned_domains[domain] = True
    for entry in file_monitor_str:
      address, search_string = entry.split(":", 1)
      if self.monitored_strings.get(address,False):
        self.monitored_strings[address].append(search_string)
      else:
        self.monitored_strings[address] = [search_string]

    if DEBUG:
      log.debug("banned_port: %s" % str(self.banned_ports))
      log.debug("banned_domains: %s" % str(self.banned_domains))
      log.debug("monitored_strings: %s" % str(self.monitored_strings))

      log.debug("Firewall initialized.")

  def _handle_ConnectionIn (self, event, flow, packet):
    """
    New connection event handler.
    You can alter what happens with the connection by altering the
    action property of the event.
    """
    if DEBUG:
      log.debug("In handled Connection")

    if DEBUG:
      log.debug("Allowed connection [" + str(flow.src) + ":" + str(flow.srcport) + "," + str(flow.dst) + ":" + str(flow.dstport) + "]" )
    dst_port = str(flow.dstport)
    if DEBUG:
      log.debug("monitored_address: %s" % str(self.monitored_strings))
  #    log.debug("tcp dest port: %s with value %s" % (str(dst_port), str(self.banned_ports.get(dst_port, False))))
  #    log.debug("Ethernet packet: " + str(packet))
  #    log.debug("IP packet: " + str(packet.payload))
      log.debug("TCP packet: " + str(packet.payload.payload))
      
    curr_flow = self.extract_flow(packet, reverse= False)
    dst_address = str(curr_flow[2])

    if DEBUG:
      log.debug("dst_address is " + dst_address)

    if curr_flow in self.flows:
      if DEBUG:
        log.debug("Received SYN during connection for flow: " + str(curr_flow))
       # log.debug("Timers: " + str(self.timers))
      self.timeout(curr_flow)
      #creating new flow
      strings_list = self.monitored_strings[dst_address]
      longest_string_length = 0
      for string in strings_list:
        if longest_string_length < len(string):
          longest_string_length = len(string)
        self.flows[curr_flow] = {string: 0}
      self.longest_string[curr_flow] = longest_string_length   
      self.in_packet_buffer[curr_flow]  = ['']
      self.out_packet_buffer[curr_flow] = ['']
      event.action.monitor_forward = event.action.monitor_backward = True
      event.action.forward = True

      new_timer = Timer(FLOWTIMEOUT,self.timeout,args=[curr_flow])
      self.timers[curr_flow]=new_timer



    if self.banned_ports.get(dst_port, False):
      event.action.deny = True
      if DEBUG:
        log.debug("PACKET for port %s was DENIED" % str(dst_port))
    elif dst_address in self.monitored_strings:
      if DEBUG:
        log.debug("Monitoring connection to " + dst_address + 
                  "for string " + str(self.monitored_strings[dst_address]))

      if DEBUG:
        log.debug("all flows in connection_in" + str(self.flows))
      strings_list = self.monitored_strings[dst_address]
      longest_string_length = 0
      for string in strings_list:
        if longest_string_length < len(string):
          longest_string_length = len(string)
        self.flows[curr_flow] = {string: 0}
      self.longest_string[curr_flow] = longest_string_length   
      self.in_packet_buffer[curr_flow]  = ['']
      self.out_packet_buffer[curr_flow] = ['']
      event.action.monitor_forward = event.action.monitor_backward = True
      event.action.forward = True
    else:
      if DEBUG:
        log.debug("Deferred connection to " + dst_address)
      event.action.defer = True

    curr_flow = self.extract_flow(packet,reverse=False)
    if DEBUG:
      log.debug("curr_flow in handle_connection: " +str( curr_flow))

      

  def _handle_DeferredConnectionIn (self, event, flow, packet):
    """
    Deferred connection event handler.
    If the initial connection handler defers its decision, this
    handler will be called when the first actual payload data
    comes across the connection.
    """
    if DEBUG:
      log.debug("In Deferred Connection In")
    if DEBUG:
      log.debug("Ethernet packet: " + str(packet))
      log.debug("IP packet: " + str(packet.payload))
      log.debug("TCP packet: " + str(packet.payload.payload))
      log.debug("HTTP info: " + str(packet.payload.payload.payload))
    http_data = str(packet.payload.payload.payload)
    if DEBUG:
      log.debug("About to print domain")
    http_domain = self.match_http_domain(http_data)
    if DEBUG:
      log.debug("Http Domain: " + http_domain)

    curr_flow = self.extract_flow(packet,reverse=True)
    dst_addr = curr_flow[2]
    event.action.forward = True  
    if http_domain != 'No match found':
        if self.is_banned_domain(http_domain):
          if DEBUG:
            log.debug("%s is a banned domain" % http_domain)
          event.action.forward = False
          event.action.deny = True


#    log.debug("About to print header")
 #   m = re.search(r'HOST:\s*(\S*)\s*\n', http_header, re.M|re.I)
  #  log.debug("HTTP host captured: " + str(m.group(1)))    

  def _handle_MonitorData (self, event, packet, reverse):
    """
    Monitoring event handler.
    Called when data passes over the connection if monitoring
    has been enabled by a prior event handler.
    """
    if DEBUG:
      log.debug("In Monitored Connection")

    ip_packet = packet.payload
    if False:
      log.debug("IP packet: " + str(ip_packet))
    tcp_packet = ip_packet.payload
    if DEBUG:
      log.debug("TCP packet: " + str(tcp_packet))
    http_data   = tcp_packet.payload  #includes http data and header
    if DEBUG:
      log.debug("HTTP data: " + str(http_data))

    src,srcport,dst,dstport = curr_flow = self.extract_flow(packet,reverse) #(src,srcport,dst,dstport)
    if INC:
      log.debug("current flow in monitored: " + str(curr_flow))
      log.debug("all flows: " + str(self.flows))
      #log.debug("monitored_strings: " + str(self.monitored_strings))

    if self.timers.get(curr_flow, False):
      curr_timer = self.timers[curr_flow]
      curr_timer.cancel()            
      if DEBUG:
        log.debug("canceling existing timer and reseting: %s" % str(curr_timer))
      del self.timers[curr_flow]
    #make a fresh timer for current flow
    if DEBUG:
      log.debug("making new timer for flow: " + str(curr_flow))
    phresh_timer = Timer(FLOWTIMEOUT, self.timeout, args=[curr_flow])
    self.timers[curr_flow] = phresh_timer
    
    if DEBUG:
      log.debug("dst: " + dst)
      log.debug("monitored_strings: " + str(self.monitored_strings))
      log.debug("http_data: " + str(http_data)) 

    if reverse:
      if DEBUG:
        log.debug("in_packet_buff before append "
                  + str(self.in_packet_buffer[curr_flow]))
      self.in_packet_buffer[curr_flow].append(http_data)
      if DEBUG:
        log.debug("in_packet_buff after append "
                  + str(self.in_packet_buffer[curr_flow]))
    else:
      if DEBUG:
        log.debug("out_packet_buff before append "
                  + str(self.out_packet_buffer[curr_flow]))
      self.out_packet_buffer[curr_flow].append(http_data)
      if DEBUG:
        log.debug("out_packet_buff after append "
                  + str(self.out_packet_buffer[curr_flow]))


    longest_string_length = self.longest_string[curr_flow]
    if reverse:
      buffer_length = len(self.in_packet_buffer[curr_flow])
    else:
      buffer_length = len(self.out_packet_buffer[curr_flow])
    if buffer_length >= longest_string_length:
      self.merge_search_buffer(curr_flow, reverse)
                
       
