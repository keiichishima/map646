#include <iostream>
#include <fstream>
#include <sstream>
#include <string>

#include <stdlib.h>
#include <stdio.h>
#include "stat_file.h"


stat_file::stat_file(std::string filename0, std::string dirname0 ):filename(filename0), dirname(dirname0){
   std::cout << "stat_file constructor: filename: " << filename << std::endl;
   std::string sdate = filename.substr(7);
   std::cout << "sdate: " << sdate << std::endl;
   std::string::size_type index = sdate.find(".stat");
   if(index == std::string::npos)
   {
      std::cout << "invalid filename" << std::endl;
   }else{
      sdate = sdate.substr(0, index);
      std::cout << "sdate: " << sdate << std::endl;
      if(filedate.set_time(sdate) < 0){
         std::cout << "set_time() failed. set to current time" << std::endl;
      }
   }
}

bool stat_file::operator==(stat_file& rhs){
   return filedate == rhs.filedate;
}
bool stat_file::operator<(stat_file& rhs){
   return filedate < rhs.filedate;
}
bool stat_file::operator>(stat_file& rhs){
   return filedate > rhs.filedate;
}

std::string stat_file::get_filename(){
   return filename;
}
date stat_file::get_date(){

#ifdef DEBUG
   std::cout << "get_date(): filename: " << filename<< std::endl;
   std::cout << "get_date(): date: " << filedate.get_stime() <<std::endl;
#endif
   return filedate;
}

int stat_file::remove(){
   return ::remove((dirname+"/"+filename).c_str());
}

void stat_file::write(json_object* jobj){
   std::fstream fs;
   fs.open((dirname+"/"+filename).c_str(), std::ios::out | std::ios::trunc);

   fs << json_object_to_json_string(jobj);

   fs.close();
}

json_object* stat_file::get_jobj(){
   std::fstream fs;
   fs.open((dirname+"/"+filename).c_str(), std::ios::in);

   std::string stat, buf;

   while(fs && getline(fs, buf)){
      stat += buf;
   }

   json_object* jobj = json_tokener_parse(stat.c_str());

   if(is_error(jobj)){
      std::cout << "parse failed" << std::endl;
      return NULL;
   }

   fs.close();

   return jobj;

}

