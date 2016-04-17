# -*- coding: utf-8 -*-
"""
Created on Thu Mar 24 12:40:27 2016

@author: Alberto Bregliano
"""
import os
import redis
import sys

rlocal = redis.StrictRedis()



def start(idunivoco):
    "starta la raccolta dati"
    if int(rlocal.setnx('fruizione',idunivoco)) == 0:
	print "Devi prima spegnere"
    else:
        print "Raccolta statistiche avviata"

def stop(idunivoco):
    'interrompe lo sniffing'
    rlocal.delete('fruizione')
    print "Raccolta statistiche interrotta"
    
def elabora(idunivoco):
    "crea file csv da stats"
    out_file = open(idunivoco+'.csv',"w")
    idvidoteca =     str(rlocal.hget("stats:"+idunivoco,"idvideoteca"))
    qoeatt     =     str(rlocal.hget("stats:"+idunivoco,"qoeatt")[:5])
    bufferings =     str(rlocal.hget("stats:"+idunivoco,"buffering"))
    errori     =     str(rlocal.hget("stats:"+idunivoco,"errori"))
    ttsmin     =     str(rlocal.hget("stats:"+idunivoco,"min")[:5])
    ttsmax     =     str(rlocal.hget("stats:"+idunivoco,"max")[:5])
    ttsavg     =     str(rlocal.hget("stats:"+idunivoco,"avg")[:5])
    ttsstddev  =     str(rlocal.hget("stats:"+idunivoco,"stddev")[:5])
    out_file.write("idvideoteca;qoeatt;bufferings;errori;ttsmin;ttsmax;ttsavg;ttsstddev\n")
    out_file.write(idvidoteca+";"+qoeatt+";"+bufferings+";"+errori+";"+ttsmin+";"+ttsmax+";"+ttsavg+";"+ttsstddev+"\n")
    out_file.close()


if len(sys.argv[:]) != 3:
	print "sintassi: [start|stop|elabora] <idunivoco>"
	sys.exit()
else:
	if sys.argv[1] == "start":
		start(sys.argv[2])
	if sys.argv[1] == "stop":
        	stop(sys.argv[2])
	if sys.argv[1] == "elabora":
        	elabora(sys.argv[2])

