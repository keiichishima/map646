import os
import socket
import sys
import time

SOCK_FILENAME = '/tmp/map646_stat'

def com(s, command):
   s.send(command)
   size = int(s.recv(1024))
   s.send("ok")
   return s.recv(size)

def a0ifnec(s):
   if len(s) == 1:
      return '0'+s
   else:
      return s

def ts2array(tm):
   year = str(tm.tm_year)
   mon = a0ifnec(str(tm.tm_mon))
   mday = a0ifnec(str(tm.tm_mday))
   hour = a0ifnec(str(tm.tm_hour))
   mn = a0ifnec(str(tm.tm_min))
   return [year, mon, mday, hour, mn]

def ts2str(tm, delimiter=''):
   return reduce(lambda x, y: x + delimiter + y, ts2array(tm))

def connect():
   s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
   s.connect(SOCK_FILENAME)
   return s

def main_loop():
   try:
      while True:
         s = connect()
         c = raw_input('>> ')
         print com(s, c)
   except KeyboardInterrupt:
      s.close()

def command(c):
   s = connect()
   return com(s, c)

if __name__ == "__main__":
   main_loop()
