from pox.core import core
from pox.lib.addresses import * 
from pox.lib.packet import *
import re

MAX_COMMON_PORT = 1023
DEBUG          = False
INC            = True
LONGEST_NOTICE = 100 

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


  def merge_search_buffer(self, curr_flow): 
    merged_ftp_packets = ''
    if INC:
      log.debug("curr_flow: " + str(curr_flow))
      log.debug("in_packet_buff: " + str(self.in_packet_buffer))
    merged_ftp_packets =  self.in_packet_buffer[curr_flow]
    matched = None
    regex_pass    = r'Entering (Passive Mode) \((.*)\)' #227
    regex_extpass = r'Entering (Extended Passive Mode) \((.*)\)' #229
    match_pass    = re.search(regex_pass, merged_ftp_packets, re.M)
    match_extpass = re.search(regex_extpass, merged_ftp_packets, re.M)
    if match_pass is not None:
      ftp_info = match_pass.group(2).split(',')
      matched = match_pass.group()
      port    = int(ftp_info[-2]) * 256 + int(ftp_info[-1])
    elif match_extpass is not None:
      ftp_info = match_extpass.group(2).split('|')
      matched  = match_extpass.group()
      port     = int(ftp_info[-2])
    else:
      port = False

    if INC:
      log.debug("port is: " + port)
    if port is not False:
      new_flow = (curr_flow[0], curr_flow[1], curr_flow[2], port)
      if INC:
        log.debug("About to add to open_ftp_connections: " + str(self.open_ftp_connections))
      self.open_ftp_connections[new_flow] = True
      if INC:
        log.debug("After setting open_ftp_connections: " + str(self.open_ftp_connections))
      #search and replace
      if INC:
        log.debug("Matched regex: " + matched)
      rep_regex   = (r"%s" % matched)
      replaced    = re.sub(rep_regex, '', merged_ftp_packets)
      merged_ftp_packets = replaced
    #else:
    #  merged_ftp_packets = merged_ftp_packets[-(LONGEST_NOTICE):]
    self.in_packet_buffer[curr_flow] = merged_ftp_packets    

  def __init__(self):
    """
    Constructor.
    Put your initialization code here.
    """
    log.debug("Firewall initialized.")
    self.open_ftp_connections = {} # key in form of (src, srcport(or data port), dst, dstport)
    self.in_packet_buffer     = {} #key curr_flow
  def _handle_ConnectionIn (self, event, flow, packet):
    """
    New connection event handler.
    You can alter what happens with the connection by altering the
    action property of the event.
    """
    #Active FTP
    #PAssive FTP
    #Extended Passive Mode
    curr_flow = (str(flow.src), str(flow.srcport), str(flow.dst), str(flow.dstport))
    ftp_connection = self.open_ftp_connections.get(curr_flow, None)


    if flow.dstport >= 0 and flow.dstport <= MAX_COMMON_PORT+1: # port btwn 0 and 1023 inclusive
      if flow.dstport == 21:
        if INC:
          log.debug("Sent to Monitored")
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
    if INC:
      log.debug("In Monitor")
      if reverse:
        log.debug("Incoming packet is: " + str(packet))
      else:
        log.debug("Outgoing packet is: " + str(packet))
    curr_flow = self.extract_flow(packet, reverse)
    if INC:
      log.debug("curr_flow in Monitored: " + str(curr_flow))

    ftp = str(packet.payload.payload.payload)
    if reverse:
      self.in_packet_buffer[curr_flow] += ftp
      self.merge_search_buffer(curr_flow)

    if INC:
      log.debug("FTP: " + str(ftp))
      
      

    
    
