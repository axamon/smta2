#!/root/TIM/venv/bin/python2.7
# -*- coding: utf-8 -*-
"""
Created on Thu Mar 24 12:40:27 2016

@author: Alberto Bregliano
"""
import os
from scapy.all import TCP, IP, sniff
from scapy_http import http
import urllib2
from lxml import etree
import redis

rlocal = redis.StrictRedis()


def process_tcp_packet(packet):
    '''
    Sniffa il traffico e recupera la richiesta del manifest
    '''
    #if not packet.haslayer(http):
    #   return
    try:
            if packet.haslayer(http.HTTPRequest):
                http_layer = packet.getlayer(http.HTTPRequest)
		#print http_layer.summary
                ip_layer = packet.getlayer(IP)
                tcp_layer = packet.getlayer(TCP)
                global request
                request = 'http://{1[Host]}{1[Path]}'.format(ip_layer.fields, http_layer.fields)
                print request
                caricamanifest(request)
                global requestwindow
                requestwindow = '{[window]}'.format(tcp_layer.fields)
                global requestack
                requestack = '{[ack]}'.format(tcp_layer.fields)
                global requesttime
                requesttime = float(packet.time)
                #print requestack, packet.time, tcpwindow, request
                #print packet.show()
            if packet.haslayer(http.HTTPResponse):
                http_layer = packet.getlayer(http.HTTPResponse)
                ip_layer = packet.getlayer(IP)
                tcp_layer = packet.getlayer(TCP)
                response = '{1[Status-Line]}'.format(ip_layer.fields, http_layer.fields).split()[1]
                #tcpwindow = '{[window]}'.format(tcp_layer.fields)
                responseseq = '{[seq]}'.format(tcp_layer.fields)
                if requestack == responseseq:
                        tts = float(packet.time)-requesttime
                        #print idvideoteca, request, tts, requestwindow, response
                        try:
                                idunivoco = rlocal.get('fruizione')
                                update_stats(idunivoco, tts, requestwindow, request, response)
                        except:
                                pass
                #print packet.show()
    except:
                pass
            


def start(idunivoco):
    "starta la raccolta dati"
    rlocal.set('fruizione',idunivoco)

def stop(idunivoco):
    'interrompe lo sniffing'
    rlocal.delete('fruizione')
    
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
    
        

def caricamanifest(url):
    #url = "http://se-mi1-5.se.vodabr.cb.ticdn.it/videoteca2/V3/SerieTV/2015/10/50521039/SS/10756324/10756324_TV_HD.ism/manifest"
    print url
    #url = "http://"+url
    idvideoteca = url.split("/")[8]
    print idvideoteca
    if idvideoteca.isdigit():
        if rlocal.exists(idvideoteca) is False:
            print "rompo le palle a videoteca"
            m = url.split("ism")[0]
            manifesturl = m+"ism/manifest"
            request = urllib2.Request(manifesturl)
            rawPage = urllib2.urlopen(request)
            manifest = rawPage.read()
            tree = etree.XML(manifest)
            rlocal.hset(idvideoteca,"duration",int(tree.xpath('/SmoothStreamingMedia')[0].attrib['Duration']))
            rlocal.hset(idvideoteca,"qualitylevels",int(tree.xpath('/SmoothStreamingMedia/StreamIndex')[0].attrib['QualityLevels']))
            rlocal.hset(idvideoteca,"chunks",int(tree.xpath('/SmoothStreamingMedia/StreamIndex')[0].attrib['Chunks']))
            r = tree.xpath('/SmoothStreamingMedia/StreamIndex/QualityLevel')
            #print len(r)
            for i in range(len(r)):
                #print r[i].attrib
                    #per escludere audio prendo solo bitrate elevati
                if int(r[i].attrib['Bitrate']) > 250000:
                    #rlocal.set(idvideoteca+":livellovideo"+r[i].attrib['Index'], int(r[i].attrib['Bitrate']))
                    #crea un hash in redis con idvideoteca il bitrate e il livello associato
                    rlocal.hset(idvideoteca, int(r[i].attrib['Bitrate']), int(r[i].attrib['Index']))
                    rlocal.hset(idvideoteca, int(r[i].attrib['Index']), int(r[i].attrib['Bitrate']))
    return idvideoteca

def update_stats(context, value, requestwindow, request, response, type='test'):
        destination = 'stats:%s'%(context)
        idvideoteca = caricamanifest(request)
        print idvideoteca
        rlocal.hset(destination, 'idvideoteca', idvideoteca)
        rlocal.hsetnx(destination, 'min', value) #setta il min
        rlocal.hsetnx(destination, 'max', value) #setta il max
        rlocal.hsetnx(destination, 'errori', 0) #setta a zero gli errori
        rlocal.hsetnx(destination, 'buffering', 0) #setta a zero gli errori
        if value < float(rlocal.hget(destination, 'min')):
                rlocal.hset(destination, 'min', value)
        if value > float(rlocal.hget(destination, 'max')):
                rlocal.hset(destination, 'max', value)
        count = int(rlocal.hincrby(destination, 'count',1))
        somma = float(rlocal.hincrbyfloat(destination, 'sum', value))
        sumq = float(rlocal.hincrbyfloat(destination, 'sumq', value*value))
        avg = somma/count
        stddev = float(((sumq / count) - (avg ** 2)) ** .5)
        rlocal.hset(destination,'avg',avg)
        rlocal.hset(destination,'stddev',stddev)
        #se la tcpwindow è troppo piccola segna un buffering
        if int(requestwindow) < 5000:
                            rlocal.hincrby(destination, 'buffering', 1)
        #se httstatus è superiore a 200 segna un errore
        if int(response) > 399:
                            rlocal.hincrby(destination,'errori', 1)
        ql = request.replace('(','/').replace(')','/').split("/")[13]
        level = rlocal.hget(idvideoteca,ql)
        #print level
        rlocal.hincrby(destination,"qoe",level) #aumenta del livello fruito il contatore qoe
        rlocal.hincrby(destination,"cvf",1) #aumenta di uno i chunk video fruiti cvf chunks veramente fruiti
        qoenav = int(rlocal.hget(destination,"qoe"))
        #print qoe
        cvf = int(rlocal.hget(destination,"cvf"))
        #print cvf
        #qoenav = int(qoe)*int(cvf)
        #print qoenav
        maxliv = int(rlocal.hget(idvideoteca,"qualitylevels"))-1
        qoemax = maxliv * cvf
        #print qoemax
        qoeatt = float(qoenav)/float(qoemax) #quality of experience attuale
        #print qoeatt
        rlocal.hset(destination,"qoeatt",qoeatt)

if __name__ == "__main__":             
    sniff(filter='tcp and port 80', prn=process_tcp_packet, store=0)
