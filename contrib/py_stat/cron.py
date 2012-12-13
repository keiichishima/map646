#!/usr/bin/python
import client
import sys
import os
import time

def accum_array(string, delimiter):
   array = string.split(delimiter)
   return [reduce(lambda x, y: x + delimiter + y, array[:i]) for i in range(1, len(array)+1)]

def recurs_mkdir(dirname):
   dirarray = accum_array(dirname, '/')
   dirarray.pop(0)
   try:
      [os.mkdir(x) for x in dirarray if os.path.isdir(x) == False]
   except:
      print "mkdir error"
      exit(1)

def main():
   argvs = sys.argv
   argc = len(argvs)

   try:
      i = argvs.index("-d")
      dirname = argvs[i+1]
      ctime = time.localtime()
      dirname = dirname + '/' + client.ts2str(ctime, '/')
      dirname = dirname[:-3]
      recurs_mkdir(dirname)
      filename = str("/map646_") + client.ts2str(ctime) + str(".stat")
      f = open(dirname+filename, 'a')
   except:
      print "exception caught: failed to open file"
      exit()

   try:
      f.write('#lastflush: ' + client.command("time") + '\n')
      f.write(client.command("show"))
      client.command("flush")
   except:
      print "exception caught"

if __name__ == "__main__":
   main()
