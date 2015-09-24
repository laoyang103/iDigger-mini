import pyshark

dfilter = None
analy_fname = 'capture_test.pcapng'
stat_cache = {}
decodes_cap = None
summarys_cap = None
psummary_list = None
curr_decode_num = 0
analy_basedir = '/opt/iDigger-mini/'

def get_summary_list():
    global summarys_cap, psummary_list
    if None == summarys_cap: 
        i = 0
        psummary_list = []
        summarys_cap = pyshark.FileCapture(analy_basedir + analy_fname, only_summaries=True, display_filter=dfilter, keep_packets=True)
        for summary in summarys_cap: 
            i += 1
            if i > 2000: break
            summary._fields['No'] = i
            psummary_list.append(summary._fields)
    return psummary_list 

def set_dfilter(dflt):
    global summarys_cap, decodes_cap, dfilter, curr_decode_num, stat_cache
    dfilter = dflt
    stat_cache = {}
    curr_decode_num = 0
    summarys_cap = decodes_cap = None 
    
def set_fname(fname):
    global analy_fname
    analy_fname = fname
    set_dfilter('')

def get_pkt_decode(pkt_num):
    global decodes_cap
    if None == decodes_cap: 
        decodes_cap = pyshark.FileCapture(analy_basedir + analy_fname, display_filter=dfilter, keep_packets=True)

    global curr_decode_num
    if pkt_num > curr_decode_num:
        i = pkt_num - curr_decode_num
        while i >= 0:
            decodes_cap.next()
            i -= 1
        curr_decode_num = pkt_num
    return decodes_cap._packets[pkt_num]

def set_stat_cache(stat_name, stat_value):
    stat_cache[stat_name] = stat_value

def get_stat_cache(stat_name):
    if stat_cache.has_key(stat_name):
        return stat_cache[stat_name]
    return None

def get_curr_fname_path():
    return analy_basedir + analy_fname

