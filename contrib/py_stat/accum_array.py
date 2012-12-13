import os
import sys

def accum_array(string, delimiter):
   array = string.split(delimiter)
   #not efficient implementation
   return [reduce(lambda x, y: x + delimiter + y, array[:i]) for i in range(1, len(array)+1)]
   

if __name__ == "__main__":
   
   argvs = sys.argv
   argc = len(argvs)

   try:
      i = argvs.index("-d")
      dirname = argvs[i+1]
   except:
      print "usage: -d dirname"
      exit(1)

   dirarray =  accum_array(dirname, '/')
   dirarray.pop(0)
   try:
      [os.mkdir(x) for x in dirarray if os.path.isdir(x) == False]
   except:
      print "mkdir error"

