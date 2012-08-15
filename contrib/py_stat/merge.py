import sys
import os
import glob
import json

#merge a to b
def merge(a, b):
   try:
      for i in a:
         if b.has_key(i):
            if type(a[i]) == int:
               b[i] = b[i] + a[i]
            elif type(a[i]) == dict:
               merge(a[i], b[i])
         else:
            b[i] = a[i]

      return b
   except:
      pass
   

def main():
   argvs = sys.argv
   argc = len(argvs)

   try:
      dirname = argvs[argvs.index('-d') + 1]
      time = argvs[argvs.index('-t') + 1]
   except:
      print "usage: -d dirname, -t timerange, [-w filename]"

   try:
      writename = argvs[argvs.index('-w') + 1]
      w = open(writename, 'w')
   except:
      w = sys.stdout
         
   os.chdir(dirname)
   
   j = []
   for filename in glob.glob("map646_"+time+".stat"):
      f = open(filename)
      j.append(json.loads(f.read()))
      f.close()

   r = {}
   for a in j:
      merge(a, r)

   w.write(json.dumps(r, sort_keys=True, indent=4))


if __name__ == "__main__":
   main()
