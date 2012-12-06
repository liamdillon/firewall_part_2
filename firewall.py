from pox.core import core
from pox.lib.addresses import * 
from pox.lib.packet import *
from pox.lib.recoco.recoco import *
import re

MAX_COMMON_PORT = 1023
MAX_TCP_PORT    = 65535
DEBUG           = False
INC             = True
LONGEST_NOTICE  = 100 
TIMEOUT         = 10

# Get a logger
log = core.getLogger("fw")

class Firewall (object):
  """
  Firewall class.
  Extend this to implement some firewall functionality.
  Don't change the name or anything -- the eecore component
  expects it to be firewall.Firewall.
  """
  def timeout(self, curr_flow):
    if INC:
      log.debug("open_connections before cleanup: " + str(self.open_ftp_connections))
      log.debug("TIMEOUT for " + str(curr_flow))
    self.cleanup(curr_flow)
    if INC:
      log.debug("open_connections after cleanup: " + str(self.open_ftp_connections))
    

  def extract_flow(self, packet, reverse):
    packet = str(packet)
    regex = r'[\w|\d|:]*\[([\d|\.|>]*)\]\)\{([\d|>]*)}'
    match = re.search(regex, packet, re.M|re.I)

    if match != None:
      ip = match.group(1)
      tcp = match.group(2)
      src,dst = ip.split(">")
      srcport,dstport = tcp.split(">")
      if reverse: #incoming
        return (dst,dstport,src,srcport) 
      else:
        return (src,srcport,dst,dstport)
    else:
      return 'No match found'

  def cleanup(self, curr_flow):
    data_flow = self.cmd_to_data.get(curr_flow, False)
    if data_flow is not False:
      del self.cmd_to_data[curr_flow]
      if self.open_ftp_connections.get(data_flow, False) is not False:
        self.open_ftp_connections[data_flow].cancel()
        del self.open_ftp_connections[data_flow]      
    if self.open_ftp_connections.get(curr_flow, False) is not False:
      self.open_ftp_connections[curr_flow].cancel()
      del self.open_ftp_connections[curr_flow]
    if self.in_packet_buffer.get(curr_flow, False) is not False:
      del self.in_packet_buffer[curr_flow]



#    if self.in_packet_buffer.get(data_flow, False) is not False:
#    del self.in_packet_buffer[data_flow]
    
  def merge_search_buffer(self, curr_flow): 
    merged_ftp_packets = ''
    merged_ftp_packets =  self.in_packet_buffer[curr_flow]
    matched = None
    regex_pass    = r'(?:^227|\n227) .*\n'
    regex_extpass = r'(?:^229|\n229) .*\n'
    match_pass    = re.search(regex_pass, merged_ftp_packets, re.M)
    match_extpass = re.search(regex_extpass, merged_ftp_packets, re.M)
    data_ip = False
    port = False
    if match_pass is not None:
      reg_get_port = r'\((\d+,\d+,\d+,\d+),(\d+),(\d+)\).*\n(.*)'
#r'\(\d+,\d+,\d+,\d+,(\d+),(\d+)\)(.)*'
      matched      = re.search(reg_get_port, merged_ftp_packets, re.M) 
      if matched is not None:
        adv_ip    = re.sub(r',', '.', matched.group(1))
        actual_ip = curr_flow[1]
        port      = int(matched.group(2)) * 256 + int(matched.group(3))
        port      = str(port)

        if adv_ip != actual_ip:
          data_ip = adv_ip
        else:
          data_ip = False
      else:
        port = False
        data_ip = False

    elif match_extpass is not None:
      reg_get_port = r'\(\|\|\|(\d+)\|\).*\n(.*)'
      matched  = re.search(reg_get_port, merged_ftp_packets, re.M) 
      if matched is not None:
        port     = str(matched.group(1))
    else:
      port = False
      data_ip = False

    if DEBUG:
      log.debug("matched is: " + str(matched))
      log.debug("port is: " + str(port))
    if port is not False and int(port) <= MAX_TCP_PORT:
      if data_ip:
        new_flow = (curr_flow[0],data_ip,port)
      else:
        new_flow = (curr_flow[0],curr_flow[1],port)
      
      cmd_flow = (curr_flow[0],curr_flow[1],'21')
      if DEBUG:
        log.debug("new_flow: " + str(new_flow))
        log.debug("About to add to open_ftp_connections: " + str(self.open_ftp_connections))
        log.debug("About to add to cmd_to_data: " + str(self.cmd_to_data))
      new_timer = Timer(TIMEOUT,self.timeout,args=[curr_flow])
      self.open_ftp_connections[new_flow] = new_timer #True
      self.cmd_to_data[cmd_flow] = new_flow
      self.in_packet_buffer[new_flow]     = ''
      if DEBUG:
        log.debug("After setting open_ftp_connections: " + str(self.open_ftp_connections))
        log.debug("After to add to cmd_to_data: " + str(self.cmd_to_data))
      #search and replace
      if match_pass is not None:
        replaced = str(matched.group(4)) #changed from 3
      else:
        replaced = str(matched.group(2)) #changed from 2
      if DEBUG:
        log.debug("merged_ftp_packets before replacement: " + merged_ftp_packets)
      merged_ftp_packets = replaced
      if DEBUG:
        log.debug("merged_ftp_packets after replacement: " + merged_ftp_packets)
    #else:
    #  merged_ftp_packets = merged_ftp_packets[-(LONGEST_NOTICE):]
    self.in_packet_buffer[curr_flow] = merged_ftp_packets    

  def __init__(self):
    """
    Constructor.
    Put your initialization code here.
    """
    log.debug("Firewall initialized.")
    self.open_ftp_connections = {} # key in form of (src, dst, dstport) 
    self.in_packet_buffer     = {} #key curr_flow
    self.cmd_to_data  = {}
  def _handle_ConnectionIn (self, event, flow, packet):
    """
    New connection event handler.
    You can alter what happens with the connection by altering the
    action property of the event.
    """
    #Active FTP
    #PAssive FTP
    #Extended Passive Mode
    curr_flow = (str(flow.src), str(flow.dst), str(flow.dstport))
    ftp_connection = self.open_ftp_connections.get(curr_flow, None)
    if INC:
      log.debug("curr_flow in Handle_Conn: " + str(curr_flow))
      log.debug("open_ftp_connections in Handle_Conn: " + str(self.open_ftp_connections))
      log.debug("is curr_flow in open_ftp_connections in Handle_Conn: " + str(ftp_connection))

    if flow.dstport >= 0 and flow.dstport <= MAX_COMMON_PORT: # port btwn 0 and 1023 inclusive
      if flow.dstport == 21:
        event.action.monitor_forward = event.action.monitor_backward = True
        curr_buff = self.in_packet_buffer.get(curr_flow, None)
        if curr_buff is None:
          self.in_packet_buffer[curr_flow] = ''
      event.action.forward = True
    elif ftp_connection is not None:
      event.action.monitor_forward = event.action.monitor_backward = True
      event.action.forward = True
    else:
      event.action.deny = True

  def _handle_DeferredConnectionIn (self, event, flow, packet):
    """
    Deferred connection event handler.
    If the initial connection handler defers its decision, this
    handler will be called when the first actual payload data
    comes across the connection.
    """
    pass
    
  def _handle_MonitorData (self, event, packet, reverse):
    """
    Monitoring event handler.
    Called when data passes over the connection if monitoring
    has been enabled by a prior event handler.
    """
    if DEBUG:
      log.debug("In Monitor")
      if reverse:
        log.debug("Incoming packet is: " + str(packet))
      else:
        log.debug("Outgoing packet is: " + str(packet))
    full_curr_flow = self.extract_flow(packet, reverse)
    curr_flow = (full_curr_flow[0], full_curr_flow[2], full_curr_flow[3])
    cmd_flow  = (full_curr_flow[0], full_curr_flow[2], '21')

    if DEBUG:
      log.debug("curr_flow in Monitored: " + str(curr_flow))
      log.debug("in_packet_buffer: " + str(self.in_packet_buffer.keys()))
      log.debug("open_ftp_connections: " + str(self.open_ftp_connections))

    ftp = str(packet.payload.payload.payload)
    if cmd_flow in self.in_packet_buffer:
      #refresh timer associated with cmd_flow
      reset_timer = Timer(TIMEOUT,self.timeout,args=[curr_flow])
      if self.open_ftp_connections.get(curr_flow, False) is not False:
        self.open_ftp_connections[curr_flow].cancel()
      self.open_ftp_connections[curr_flow] = reset_timer
      if curr_flow[2] != '21':
        if self.open_ftp_connections.get(cmd_flow, False) is not False:
          self.open_ftp_connections[cmd_flow].cancel()
        self.open_ftp_connections[cmd_flow] = reset_timer
      if reverse:
        if DEBUG:
          log.debug("in_packet_buff: " + str(self.in_packet_buffer))
        self.in_packet_buffer[curr_flow] += ftp
        self.merge_search_buffer(curr_flow)
    
      
      
#TODO: FIGURE OUT WHERE TO UPDATE TIMEOUT
