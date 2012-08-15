#ifndef STAT_FILE_MANAGER_H
#define STAT_FILE_MANAGER_H


#include <string>
#include <vector>
#include <json/json.h>
#include "stat_file.h"
#include "json_util.h"

class stat_file_manager{
   private:
      std::string dirname;
      std::vector<stat_file> stat_files;
      int merge(date);
   public:
      stat_file_manager(std::string dirname0);
      int update(date ctime);
      date get_lastupdate_date();
      void show();
      bool empty();
      int write(std::string stime, json_object* jobj);
};

#endif
