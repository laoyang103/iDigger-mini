import os
import datetime
import sys
import json
import sqlite3
import subprocess as sp
sys.path.append('./env/lib/python2.7/site-packages/')

import web
import cached
urls = (
    '/', 'home',
    '/conv', 'conv',
    '/analy', 'analy',
    '/plist', 'plist',
    '/decode', 'decode',
    '/expertinfo', 'expertinfo',
    '/capinfo', 'capinfo',
    '/follow_tcp_stream', 'follow_tcp_stream',
    '/filter_expression', 'filter_expression',
    '/packet_len', 'packet_len',
    '/io_phs', 'io_phs',
    '/ip_hosts', 'ip_hosts',
    '/uflts', 'uflts',
    '/uflts/add', 'uflts_add',
    '/res/(.*)', 'res',
    '/iDiggers/(.*)', 'iDiggers',
    '/set_dfilter', 'set_dfilter'
)
db = web.database(dbn='sqlite', db="/opt/iDigger-mini/db.sqlite3")
layername = {'UDP': 'Transmission', 'TCP': 'Transmission', 'IP': 'Network', 'ETH': 'Ethernet'}

class res:
    def GET(self, name):
        f = open('res/'+ name)
        return f.read()

class iDiggers:
    def GET(self, name):
        f = open('iDiggers/'+ name)
        return f.read()

class home:
    def GET(self):
        fnamelist = os.listdir(cached.analy_basedir)
        web.header('Access-Control-Allow-Origin', '*')
        html  = "<html>"
        html += "<body>"
        html += "<table border=\"5\">"
        html += "<caption>Packet file list</caption>"
        html += "<tr><th>File</th><th>Time</th><th>Bytes</th><th>Size (MB)</th><th>Analysis</th></tr>"
        html += "<tbody>"
        for fname in fnamelist: 
            html += "<tr>"
            html += "<td>" + fname + "</td>"
            time = os.path.getmtime(cached.analy_basedir + fname)
            html += "<td>" + str(datetime.datetime.fromtimestamp(time)) + "</td>"
            size = os.path.getsize(cached.analy_basedir + fname)
            if 0 == size: size = 1
            html += "<td>" + str(size) + "</td>"
            html += "<td>" + str(size / 1024 / 1024) + "</td>"
            html += "<td><a href=\"/analy?fname=" + fname + "\">Analysis</td>"
            html += "</tr>"
        html += "</tbody>"
        html += "</table>"
        html += "</body>"
        html += "</html>"
        return html

class analy:
    def GET(self):
        params = web.input(fname='')
        cached.set_fname(params.fname)
        raise web.redirect('/iDiggers/iDigger.html')

class plist:
    def GET(self):
        psummary_list = cached.get_summary_list()
        web.header('Access-Control-Allow-Origin', '*')
        return json.dumps(psummary_list)

class set_dfilter:
    def GET(self):
        params = web.input(dflt='')
        cached.set_dfilter(params.dflt)
        web.header('Access-Control-Allow-Origin', '*')
        return 'Y'

class decode:
    def GET(self):
        params = web.input(num=1)
        decode_dict, pkt = {}, cached.get_pkt_decode(int(params.num))
        for layer in pkt.layers: 
            if not layername.has_key(layer.layer_name.upper()): 
                decode_dict[layer.layer_name.upper()] = layer._all_fields
            else: 
                decode_dict[layername[layer.layer_name.upper()] + ' (' + layer.layer_name.upper() + ')'] = layer._all_fields
        web.header('Access-Control-Allow-Origin', '*')
        return json.dumps(decode_dict)

class expertinfo:
    def GET(self):
        expert = cached.get_stat_cache('expertinfo')
        if None == expert: 
            FILTER, FREQUENCY, GROUP, PROTOCOL, SUMMARY = range(5)
            expert = {'Errors': [], 'Warns': [], 'Notes': [], 'Chats': []}
            cached.set_stat_cache('expertinfo', expert)
            base_args = ['tshark', '-q', '-r', cached.get_curr_fname_path(), '-z']
            p = sp.Popen(gen_statistics_args(base_args, 'expert', cached.dfilter), stdin=sp.PIPE, stdout=sp.PIPE, close_fds=True)

            currinfo = None
            line = p.stdout.readline()
            while line:
                line = p.stdout.readline()
                if '\n' == line or '====' in line or 'Frequency' in line: 
                    continue
                fields = line.strip().split(None, 4)
                if 0 == len(fields): continue
                if not fields[0].isdigit() and expert.has_key(fields[0]): 
                    currinfo = expert[fields[0]]
                    continue
                record = {}
                record['Filter']            = fields[FILTER]
                record['Frequency']         = fields[FREQUENCY]
                record['Group']             = fields[GROUP]
                record['Protocol']          = fields[PROTOCOL]
                record['Summary']           = fields[SUMMARY]
                currinfo.append(record)
            p.stdout.close()
            p.stdin.close()
        web.header('Access-Control-Allow-Origin', '*')
        return json.dumps(expert)

class capinfo:
    def GET(self):
        capinfo = cached.get_stat_cache('capinfo')
        if None == capinfo: 
            capinfo = {}
            cached.set_stat_cache('capinfo', capinfo)
            NAME, VALUE = SOCK_ADDR, SOCK_PORT = range(2)
            p = sp.Popen(['/usr/local/bin/capinfos', cached.get_curr_fname_path()], stdin=sp.PIPE, stdout=sp.PIPE, close_fds=True)
            line = p.stdout.readline()
            while line:
                fields = line.split(':', 1)
                capinfo[fields[NAME]] = fields[VALUE].strip()
                line = p.stdout.readline()
            p.stdout.close()
            p.stdin.close()
        web.header('Access-Control-Allow-Origin', '*')
        return json.dumps(capinfo)

class conv:
    def GET(self):
        outconv = cached.get_stat_cache('conv')
        if None == outconv: 
            outconv = []
            cached.set_stat_cache('conv', outconv)
            NAME, VALUE = SOCK_ADDR, SOCK_PORT = range(2)
            SRCINFO, CONVSTR, DSTINFO, PACKETS_DST2SRC, BYTES_DST2SRC, PACKETS_SRC2DST, BYTES_SRC2DST, PACKETS, BYTES, REL_START, DURATION = range(11)

            base_args = ['tshark', '-q', '-nn', '-r', cached.get_curr_fname_path(), '-z']
            p = sp.Popen(gen_statistics_args(base_args, 'conv,tcp', cached.dfilter), stdin=sp.PIPE, stdout=sp.PIPE, close_fds=True)

            line = p.stdout.readline()
            while line:
                line = p.stdout.readline()
                if '<->' not in line: continue
                fields = line.split()
                srcsock = fields[SRCINFO].split(':')
                dstsock = fields[DSTINFO].split(':')
                conv = {}
                conv['Address SRC']         = srcsock[SOCK_ADDR]
                conv['Port SRC']            = srcsock[SOCK_PORT]
                conv['Address DST']         = dstsock[SOCK_ADDR]
                conv['Port DST']            = dstsock[SOCK_PORT]
                conv['Total Packets']       = fields[PACKETS]
                conv['Total Bytes']         = fields[BYTES]
                conv['Packets SRC -> DST']  = fields[PACKETS_SRC2DST]
                conv['Bytes SRC -> DST']    = fields[BYTES_SRC2DST]
                conv['Packets DST -> SRC']  = fields[PACKETS_DST2SRC]
                conv['Bytes DST -> SRC']    = fields[BYTES_DST2SRC]
                conv['Rel Start']           = fields[REL_START]
                conv['Duration']            = fields[DURATION]
                conv['Filter-IP']           = '(ip.addr eq %s and ip.addr eq %s)' % (srcsock[SOCK_ADDR], dstsock[SOCK_ADDR])
                conv['Filter-TCP']          = '(ip.addr eq %s and ip.addr eq %s) and (tcp.port eq %s and tcp.port eq %s)' % \
                                               (srcsock[SOCK_ADDR], dstsock[SOCK_ADDR], srcsock[SOCK_PORT], dstsock[SOCK_PORT])
                conv['Filter-TCP-Stream']   = '%s:%s,%s:%s' % (srcsock[SOCK_ADDR], srcsock[SOCK_PORT], dstsock[SOCK_ADDR], dstsock[SOCK_PORT])
                outconv.append(conv)
            p.stdout.close()
            p.stdin.close()
            print len(outconv)
        web.header('Access-Control-Allow-Origin', '*')
        return json.dumps(outconv)

class follow_tcp_stream:
    def GET(self):
        params = web.input(tcp_stream_flt='')
        base_args = ['tshark', '-q', '-r', cached.get_curr_fname_path(), '-z']
        p = sp.Popen(gen_statistics_args(base_args, 'follow,tcp,ascii', params.tcp_stream_flt), stdin=sp.PIPE, stdout=sp.PIPE, close_fds=True)
        lines = txt2html(p.stdout.read())
        p.stdout.close()
        p.stdin.close()
        web.header('Access-Control-Allow-Origin', '*')
        return lines

class filter_expression:
    def GET(self):
        with open('./static/filter_expression') as f: 
            web.header('Access-Control-Allow-Origin', '*')
            return f.read()

class packet_len:
    def GET(self):
        out_json = cached.get_stat_cache('packet_len')
        if None == out_json: 
            out_json = []
            cached.set_stat_cache('packet_len', out_json)
            base_args = ['tshark', '-q', '-r', cached.get_curr_fname_path(), '-z', 'plen,tree']
            field_names = ['Topic / Item', 'Count', 'Average', 'Min val', 'Max val', 'Rate (ms)', 'Percent', 'Burst rate', 'Burst start']
            p = sp.Popen(base_args, stdin=sp.PIPE, stdout=sp.PIPE, close_fds=True)
            line = p.stdout.readline()
            while line:
                line = p.stdout.readline().replace('Packet Lengths', 'Packet-Lengths')
                fields = line.split()
                if len(fields) != len(field_names): continue
                out_json.append(dict(zip(field_names, fields)))
            p.stdout.close()
            p.stdin.close()
        web.header('Access-Control-Allow-Origin', '*')
        return json.dumps(out_json)

class ip_hosts:
    def GET(self):
        out_json = cached.get_stat_cache('ip_hosts')
        if None == out_json: 
            out_json = []
            cached.set_stat_cache('ip_hosts', out_json)
            base_args = ['tshark', '-q', '-r', cached.get_curr_fname_path(), '-z', 'ip_hosts,tree']
            field_names = ['Topic / Item', 'Count', 'Rate (ms)', 'Percent', 'Burst rate', 'Burst start']
            p = sp.Popen(base_args, stdin=sp.PIPE, stdout=sp.PIPE, close_fds=True)
            line = p.stdout.readline()
            while line:
                line = p.stdout.readline().replace('IP Addresses', 'IP Addresses')
                fields = line.split()
                if len(fields) != len(field_names): continue
                out_json.append(dict(zip(field_names, fields)))
            p.stdout.close()
            p.stdin.close()
        web.header('Access-Control-Allow-Origin', '*')
        return json.dumps(out_json)

class io_phs:
    def GET(self):
        out_json = cached.get_stat_cache('io_phs')
        if None == out_json: 
            base_args = ['tshark', '-q', '-r', cached.get_curr_fname_path(), '-z', 'io,phs']
            p = sp.Popen(base_args, stdin=sp.PIPE, stdout=sp.PIPE, close_fds=True)
            out_json = p.stdout.read()
            cached.set_stat_cache('io_phs', out_json)
            p.stdout.close()
            p.stdin.close()
        web.header('Access-Control-Allow-Origin', '*')
        return out_json

class uflts:
    def GET(self):
        reslist = []
        flts = list(db.select('tshark_userflt', what='name', group='name'))
        for flt in flts: reslist.append({'name': flt.name})
        web.header('Access-Control-Allow-Origin', '*')
        return json.dumps(reslist)

class uflts_add:
    def GET(self):
        params = web.input(name='')
        db.insert('tshark_userflt', name=params.name)
        web.header('Access-Control-Allow-Origin', '*')
        return 'Y'

def gen_statistics_args(base_args, statistics, flt):
    if None != flt and '' != flt: 
        base_args.append(statistics + ',' + flt)
    else:
        base_args.append(statistics)
    return base_args

def txt2html(txt):
    def escape(txt):
        txt = txt.replace('&','&#38;')
        txt = txt.replace(' ','&#160;')
        txt = txt.replace('<','&#60;')
        txt = txt.replace('>','&#62;')
        txt = txt.replace('"','&#34;')
        txt = txt.replace('\'','&#39;')
        return txt
    txt = escape(txt)
    lines = txt.split('\n')
    for i, line in enumerate(lines):
        lines[i] = '<p>' + line + '</p>'
    txt = ''.join(lines)
    return txt

if __name__ == "__main__":
    app = web.application(urls, globals())
    app.run()
