#!/usr/bin/env python
import sys
import datetime
import re
import argparse


HDRS = []
CALLS = {}

FAILURES_BY_REASON = {}
WARNINGS_BY_REASON = {}
STATS_BY_REASON = {}

def addr2int(addr):
    return reduce(lambda x, y: (x << 8) + int(y), addr.split("."), 0)

def match_prefix(addr, pref, len):
    addr_int = addr2int(addr)
    pref_int = addr2int(pref)
    
    mask_int = 0
    for i in range(0,32):
        mask_int <<= 1
        if (i < len):
            mask_int |= 1
            
    if (addr_int & mask_int) == pref_int:
        return True
    
    return False

class Candidate(object):
    def __init__(self, t, c):
        self.time_ = t
        self.txt_ = c;
        v = c.split()
        label = v.pop(0)
        if label != "a=candidate" and label != "candidate":
            die("Not a candidate: %s"%c)
            
        self.index_ = int(v.pop(0))
        self.component_ = int(v.pop(0))
        self.transport_ = v.pop(0)
        self.priority_ = int(v.pop(0))
        self.addr_ = v.pop(0)
        self.port_ = int(v.pop(0))
        if v.pop(0) != "typ":
            print("Missing 'typ' field")
        self.type_ = v.pop(0)


    def is_public(self):
        if (match_prefix(self.addr_, "10.0.0.0", 8)):
            return False

        if (match_prefix(self.addr_, "172.16.0.0", 12)):
            return False

        if (match_prefix(self.addr_, "192.168.0.0", 16)):
            return False

        return True
                          
    def __str__(self):
        return "%s: %s"%(self.time_, self.txt_)
        
class Event(object):
    def __init__(self, v):
        self.val_ = v['sdp']
        self.time_ = self.convert_date(v['date'])

    def __str__(self):
        return "%s: %s"%(self.time_, self.val_)

    def convert_date(self, d):
        dd = d.split(".")
        e = datetime.datetime.utcfromtimestamp(0)
        return (datetime.datetime.strptime(dd[0], "%Y-%m-%d %H:%M:%S") - e).total_seconds()
    
class Call(object):
    def __init__(self, callid):
        self.failed_ = None
        self.warnings_ = []
        self.callid_ = callid
        self.offer_ = None
        self.offer_time_ = None
        self.answer_ = None
        self.answer_time_ = None
        self.direction_ = None
        self.candidates_ = []

    def add_value(self, v):
        vv = Event(v)
        if v['type'] == "offer":
            self.add_offer(vv)
        if v['type'] == "answer":
            self.add_answer(vv)
        if v['type'] == "candidate":
            self.add_candidate(vv)
    
    def add_offer(self, val):
        if self.offer_ is not None:
            die("Can't have multiple offers")
        self.offer_ = val

    def add_answer(self, val):
        if self.answer_ is not None:
            die("Can't have multiple answers")
        self.answer_ = val

    def add_candidate(self, val):
        self.candidates_.append(val)

    def expand_candidates(self):
        self.offer_candidates_=[]
        for l in self.offer_.val_:
            if l.find("a=candidate") != -1:
                self.offer_candidates_.append(Candidate(self.offer_.time_, l))

        self.answer_candidates_=[]            
        for l in self.answer_.val_:
            if l.find("a=candidate") != -1:
                self.answer_candidates_.append(Candidate(self.answer_.time_, l))

        for c in self.candidates_:
            self.answer_candidates_.append(Candidate(c.time_, c.val_[0]))

    def dump(self, file):
        file.write("OFFER: %s:\n"%self.offer_)
        file.write("ANSWER: %s\n"%self.answer_)
        file.write("OFFER CANDIDATES:\n");
        for c in self.offer_candidates_:
            file.write("  %s\n"%c)
        file.write("ANSWER CANDIDATES:\n")
        for c in self.answer_candidates_:
            file.write("  %s\n"%c)
        file.write("\n")

    def break_up_by_m_lines(self, value):
        RES = []
        for l in value:
            m = re.match("m=(\S+)", l)
            if m is not None:
                RES.append([])
            if len(RES) > 0:
                RES[-1].append(l)
        return RES
            
    def expand(self):
        self.expanded_offer_ = self.break_up_by_m_lines(self.offer_.val_)
        self.expanded_answer_ = self.break_up_by_m_lines(self.answer_.val_)
        self.expand_candidates()
        self.count_accepted_m_lines()

    def count_accepted_m_lines(self):
        self.accepted_ = 0
        for ml in self.expanded_answer_:
            seen_accepted = False
            for l in ml:
                if not seen_accepted:
                    m = re.match("a=(sendrecv|recvonly|sendonly|inactive)", l)
                    if m is not None:
                        self.direction_ = m.group(1)
                        if m.group(1) != "inactive":
                            seen_accepted = True
                            self.accepted_ += 1

    def expected_components(self):
        return self.accepted_ * 2
    
    def failed(self, reason, extra=None):
        ex = ""
        if extra is not None:
            ex = " (%s)"%extra
        print "Call %s failed because of %s%s"%(self.callid_, reason, ex)
        if not reason in FAILURES_BY_REASON:
            FAILURES_BY_REASON[reason] = []
        FAILURES_BY_REASON[reason].append(self)
        self.failed_ = reason

    def warn(self, reason, extra=None):
        ex = ""
        if extra is not None:
            ex = " (%s)"%extra
        print "Call %s warning: %s%s"%(self.callid_, reason, ex)
        if not reason in WARNINGS_BY_REASON:
            WARNINGS_BY_REASON[reason] = []
        WARNINGS_BY_REASON[reason].append(self)
        self.warnings_.append(reason)

    def stats(self, reason):
        if not reason in STATS_BY_REASON:
            STATS_BY_REASON[reason] = []
        STATS_BY_REASON[reason].append(self)

    def analyze(self):
        if self.offer_ is None:
            self.failed('no_offer')
            return
        if self.answer_ is None:
            self.failed('no_answer')
            return
        if self.answer_.time_ - self.offer_.time_ > 5:
            self.warn('long_lag_time')
        self.expand()
        if self.direction_ is not None:
            self.stats(self.direction_)
        else:
            self.warning("no_direction")
        if (len(self.answer_candidates_) == 0):
            self.failed('no_answer_candidates')
            return
        if (len(self.answer_candidates_) < self.expected_components()):
            self.failed('too_few_answer_candidates', "%d < %d"%(len(self.answer_candidates_),
                                                                self.expected_components()))

        public = 0
        for c in self.answer_candidates_:
            if c.is_public():
                public += 1
        
        if (public < self.expected_components()):
            self.failed('too_few_public_candidates',
                        "%d < %d"%(public, self.expected_components()))
        
def die(msg):
    sys.stderr.write(msg)
    sys.stderr.write("\n")
    sys.exit(1)
    
def strip_quotes(lst):
    return [x.strip('" ') for x in lst]

def parse_file(inf):
    global HDRS
    l = inf.readline()
    l = l.strip()
    HDRS = strip_quotes(l.split(","))

    for l in inf:
        l = l.strip()
        ll = strip_quotes(l.split(","))
        if len(ll) != len(HDRS):
            die("Bogus length")

        
        val = {}
        for i in range(0,len(ll)):
            val[HDRS[i]] = ll[i]
        val['sdp'] = val['sdp'].split('????')

        if not val['callid'] in CALLS:
            CALLS[val['callid']] = Call(val['callid'])

        CALLS[val['callid']].add_value(val)
        
parser = argparse.ArgumentParser()
parser.add_argument('file')
parser.add_argument('--unknown', dest="unknowns", default=None, help="Dump unknown calls")
args = parser.parse_args()

f = open(args.file)
parse_file(f)

for callid in CALLS:
    CALLS[callid].analyze()


print "Total calls: %d"%len(CALLS.keys())
for r in FAILURES_BY_REASON:
    print "%s: %d"%(r, len(FAILURES_BY_REASON[r]))

print "WARNINGS"
for r in WARNINGS_BY_REASON:
    print "%s: %d"%(r, len(WARNINGS_BY_REASON[r]))

print "STATS"
for r in STATS_BY_REASON:
    print "%s: %d"%(r, len(STATS_BY_REASON[r]))

if args.unknowns is not None:
    u = open(args.unknowns, "w")
    for call in CALLS:
        if CALLS[call].failed_ is None:
            CALLS[call].dump(u)
        
