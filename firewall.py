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

  def open_data_connection(self, curr_flow, data_ip, port):
    if port is not False and int(port) <= MAX_TCP_PORT:
      if data_ip:
        new_flow = (curr_flow[0],data_ip,port)
      else:
        new_flow = (curr_flow[0],curr_flow[1],port)
      
      cmd_flow = (curr_flow[0],curr_flow[1],'21')
  
      new_timer = Timer(TIMEOUT,self.timeout,args=[curr_flow, cmd_flow])
      if self.open_ftp_connections.get(new_flow, False) is not False:
        self.open_ftp_connections[new_flow].cancel()
      self.open_ftp_connections[new_flow] = new_timer #True
      if new_flow != cmd_flow:
        if self.cmd_to_data.get(cmd_flow, False) is not False:
          many_data_flows = self.cmd_to_data[cmd_flow]
          if new_flow not in many_data_flows:
            self.cmd_to_data[cmd_flow].append(new_flow)
        else:
          self.cmd_to_data[cmd_flow] = [new_flow]
      self.in_packet_buffer[new_flow]     = ''


  def timeout(self, curr_flow, cmd_flow):
    if INC:
      log.debug("TIMEOUT for " + str(curr_flow))
      log.debug("open_connections before timeout: " + str(self.open_ftp_connections.keys()))
      log.debug("cmd_to_data before timeout: " + str(self.cmd_to_data))

    data_flow = False
    many_data_flows = self.cmd_to_data.get(cmd_flow, [])
    if curr_flow == cmd_flow:
      for the_data_flow in many_data_flows:
        if self.open_ftp_connections.get(the_data_flow, False) is not False:
          log.debug(str(the_data_flow) + " has been canceled")
          self.open_ftp_connections[the_data_flow].cancel()
          del self.open_ftp_connections[the_data_flow]
      if self.open_ftp_connections.get(curr_flow, False) is not False:
        log.debug(str(curr_flow) + " has been canceled")
        self.open_ftp_connections[curr_flow].cancel()
        del self.open_ftp_connections[cmd_flow]
      if self.in_packet_buffer.get(curr_flow, False) is not False:
        del self.in_packet_buffer[curr_flow]
      if self.cmd_to_data.get(cmd_flow, False) is not False:
        del self.cmd_to_data[cmd_flow]
    else:
      if curr_flow in many_data_flows:
        data_flow = curr_flow
      if data_flow is not False:
        self.cmd_to_data[cmd_flow].remove(data_flow)
        if self.open_ftp_connections.get(data_flow, False) is not False:
          self.open_ftp_connections[data_flow].cancel()
          del self.open_ftp_connections[data_flow]      
        if self.open_ftp_connections.get(data_flow, False) is not False:
          self.open_ftp_connections[data_flow].cancel()
          del self.open_ftp_connections[data_flow]
        if self.in_packet_buffer.get(data_flow, False) is not False:
          del self.in_packet_buffer[data_flow]
        if self.cmd_to_data.get(data_flow, False) is not False:
          del self.cmd_to_data[data_flow]

    if INC:
      log.debug("open_connections after cleanup: " + str(self.open_ftp_connections.keys()))
      log.debug("cmd_to_data after timeout: " + str(self.cmd_to_data))


  def merge_search_buffer(self, curr_flow): 
    merged_ftp_packets = ''
    merged_ftp_packets =  self.in_packet_buffer[curr_flow]
    matched_on_pass = matched_on_extpass = None
    regex_pass    = r'(?:^227|\n227) .*\n'
    regex_extpass = r'(?:^229|\n229) .*\n'
    match_pass    = re.search(regex_pass, merged_ftp_packets, re.M)
    match_extpass = re.search(regex_extpass, merged_ftp_packets, re.M)
    data_ip = False #only used for pass not extpass
    port_pass = port_extpass = False
    if match_pass is not None:
      reg_get_port = r'\((\d+,\d+,\d+,\d+),(\d+),(\d+)\).*\n(.*)'
#r'\(\d+,\d+,\d+,\d+,(\d+),(\d+)\)(.)*'
      matched_on_pass      = re.search(reg_get_port, merged_ftp_packets, re.M) 
      if matched_on_pass is not None:
        adv_ip    = re.sub(r',', '.', matched_on_pass.group(1))
        actual_ip = curr_flow[1]
        port_pass      = int(matched_on_pass.group(2)) * 256 + int(matched_on_pass.group(3))
        port_pass      = str(port_pass)
        if adv_ip != actual_ip:
          data_ip = adv_ip
        self.open_data_connection(curr_flow, data_ip, port_pass)
    if match_extpass is not None:
      reg_get_port = r'\(\|\|\|(\d+)\|\).*\n(.*)'
      matched_on_extpass  = re.search(reg_get_port, merged_ftp_packets, re.M) 
      if matched_on_extpass is not None:
        port_extpass  = str(matched_on_extpass.group(1))
        self.open_data_connection(curr_flow, False, port_extpass) #data_ip = False

      #search and replace
      replaced = False
      replaced_pass = replaced_extpass = None
      if match_pass is not None:
        replaced_pass = str(matched_on_pass.group(4)) #changed from 3
        replaced = replaced_pass
      if match_extpass is not None:
        replaced_extpass = str(matched_on_extpass.group(2)) #changed from 2
        replaced = replaced_extpass
      if match_pass is not None and match_extpass is not None:
        if len(replaced_pass) < len(replaced_extpass):
          replaced = replaced_pass
        else:
          replaced = replaced_extpass
      if replaced is not False:
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
      reset_timer = Timer(TIMEOUT,self.timeout,args=[curr_flow, cmd_flow])
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
