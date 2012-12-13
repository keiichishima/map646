#include "stat_file_manager.h"

#include <iostream>
#include <string>
#include <vector>

#include <algorithm>
#include <dirent.h>
#include <sys/types.h>

#include <json/json.h>

stat_file_manager::stat_file_manager(std::string dirname0):dirname(dirname0){
   DIR *dp = opendir(dirname.c_str());

   if(dp != NULL){
      dirent* dent;
      do{
         dent = readdir(dp);
         if(dent != NULL){
            std::string filename(dent->d_name);
            if((filename.length() == 24  || filename.length() == 22 || filename.length() == 20 || filename.length() == 18)
                  && filename.find("map646_") != std::string::npos 
                  && filename.find(".stat") != std::string::npos ){
               stat_file file(filename, dirname);
               stat_files.push_back(file);
            }
         }
      }while(dent != NULL);

      closedir(dp);
   }
}

date stat_file_manager::get_lastupdate_date(){
   std::vector<stat_file>::iterator max_it = std::max_element(stat_files.begin(), stat_files.end());
   return max_it->get_date(); 
}

int stat_file_manager::merge(date time){
   std::vector<stat_file>::iterator it = stat_files.begin();
   json_object* jobj = json_object_new_object();
   bool update = false;

   while(it != stat_files.end()){
      if(time.is_child(it->get_date())){
         json_object* jelement = it->get_jobj();
         if(jelement != NULL){
            json_object_object_add(jobj, it->get_filename().c_str(), jelement);
#ifdef DEBUG
            std::cout << "remove(): " << it->get_filename() << std::endl;
#endif
            it->remove();
            update = true;
         }
      }
      it++;
   }

   if(update == false){
      return -1;
   }

   json_merge(jobj);

#ifdef DEBUG
   std::cout << "write(): " << time.get_stime() << std::endl;
#endif
   write(time.get_stime(), jobj);

   return 0;
}

int stat_file_manager::update(date ctime){

   date lastupdate(get_lastupdate_date());

#ifdef DEBUG
   std::cout << "ctime: " <<std::endl;
   std::cout << ctime.get_stime() << std::endl;
   std::cout << "lastupdate: " << std::endl;
   std::cout << lastupdate.get_stime() << std::endl;
#endif


   if(ctime.s_year() == lastupdate.s_year()){
      if(ctime.s_month() == lastupdate.s_month()){
         if(ctime.s_day() == lastupdate.s_day()){
            if(ctime.s_hour() == lastupdate.s_hour()){
               if(ctime.s_min() == lastupdate.s_min()){
                  std::cout << "entry already exists" << std::endl;
                  return -1;
               }
            }else{
               std::cout << "stat_file_manager::update(): merge hour" << std::endl;
               lastupdate.get_time().tm_min = -1;
               if(merge(lastupdate) < 0){
                  std::cout << "merge() failed" << std::endl;
                  return -1;
               }
            }
         }else{
            std::cout << "stat_file_manager::update(): merge day" << std::endl;
            lastupdate.get_time().tm_min = -1;
            if(merge(lastupdate) < 0){
               std::cout << "merge() failed" << std::endl;
               return -1;
            }

            lastupdate.get_time().tm_hour = -1;
            if(merge(lastupdate) < 0){
               std::cout << "merge() failed" << std::endl;
               return -1;
            }
         }
      }else{
         std::cout << "stat_file_manager::update(): merge month" << std::endl;
         lastupdate.get_time().tm_min = -1;
         if(merge(lastupdate) < 0){
            std::cout << "merge() failed" << std::endl;
            return -1;
         }
         lastupdate.get_time().tm_hour = -1;
         if(merge(lastupdate) < 0){
            std::cout << "merge() failed" << std::endl;
            return -1;
         }
         lastupdate.get_time().tm_mday = -1;
         if(merge(lastupdate) < 0){
            std::cout << "merge() failed" << std::endl;
            return -1;
         }

      }
   }else{
      std::cout << "stat_file_manager::update(): merge year" << std::endl;
      lastupdate.get_time().tm_min = -1;
      if(merge(lastupdate) < 0){
         std::cout << "merge() failed" << std::endl;
         return -1;
      }
      lastupdate.get_time().tm_hour = -1;
      if(merge(lastupdate) < 0){
         std::cout << "merge() failed" << std::endl;
         return -1;
      }
      lastupdate.get_time().tm_mday = -1;
      if(merge(lastupdate) < 0){
         std::cout << "merge() failed" << std::endl;
         return -1;
      }
      lastupdate.get_time().tm_mon = -1;
      if(merge(lastupdate) < 0){
         std::cout << "merge() failed" <<std::endl;
         return -1;
      }
   }

   return 0;
}

bool stat_file_manager::empty(){
   return stat_files.empty();
}

void stat_file_manager::show(){
   std::vector<stat_file>::iterator it = stat_files.begin();
   while(it != stat_files.end()){
      std::cout << it->get_filename() << std::endl;
      it++;
   }
}

/* should check filename validance */
int stat_file_manager::write(std::string stime, json_object* jobj){
   stat_file file("map646_"+stime+".stat", dirname);
   file.write(jobj);
   stat_files.push_back(file);
   return 0;
}


