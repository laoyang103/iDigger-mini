import pyshark

dfilter = None
decodes_cap = None
summarys_cap = None
psummary_list = []

def get_summary_list(start, limit):
    global summarys_cap, psummary_list
    if None == summarys_cap: set_dfilter('');
    return psummary_list[start: start+limit]

def set_dfilter(dflt):
    global summarys_cap, psummary_list, dfilter

    dfilter = dflt
    psummary_list = []
    summarys_cap = pyshark.FileCapture('./capture_test.pcapng', only_summaries=True, display_filter=dfilter, keep_packets=True)
    try:
        while True:
            pdict = summarys_cap.next()._fields
            pdict['No'] = pdict['No.']
            psummary_list.append(pdict)
    except: pass

def get_pkt_decode(pkt_num):
    global decodes_cap
    if None == decodes_cap:
        decodes_cap = pyshark.FileCapture('./capture_test.pcapng', keep_packets=True)
    if 0 == len(decodes_cap._packets):
        try:
            while True: decodes_cap.next()
        except: pass
    return decodes_cap._packets[pkt_num - 1]

