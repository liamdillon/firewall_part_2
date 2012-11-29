
def extract_flow(packet, reverse):
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
    
