
#include <iostream>
#include <string>
#include <sstream>
#include <time.h>

#include "date.h"

date::date(){
   time_t timer = time(NULL);
   ts = *(localtime(&timer));
}

date::date(tm ts0):ts(ts0){
}

date::date(std::string ts0){
   set_time(ts0);
}

void date::set_time(tm ts0){
   ts = ts0;
}

int date::set_time(std::string ts0){

   int range = ts0.length();

   if(range != 12 
         && range != 10 
         && range != 8
         && range != 6
         && range != 4){
      std::cout << "date::set_time(): invalid lastupdate time" << std::endl;
      return -1;
   }

   std::stringstream ss;
   int year = -1, month = -1, day = -1, hour = -1, min = -1;

   ss << ts0.substr(0, 4) << std::endl;
   ss >> year;
   ss.str("");
   if(year < 1900 || year > 3000){
      std::cout << "date::set_time(): invalid year value" << std::endl;
      return -1;
   }

   if(range > 4){
      ss << ts0.substr(4, 2) << std::endl;
      ss >> month;
      ss.str("");
      if(month < 1 || month > 12){
         std::cout << "date::set_time(): invalid month value" << std::endl;
         return -1;
      }
      if(range > 6){
         ss << ts0.substr(6, 2) << std::endl;
         ss >> day;
         ss.str("");
         if(day < 1 || day > 31){
            std::cout << "date::set_time(): invalid day value" << std::endl;
            return -1;
         }
         if(range > 8){
            ss << ts0.substr(8, 2) << std::endl;
            ss >> hour;
            ss.str("");
            if(hour < 0 || hour > 24){
               std::cout << "date::set_time(): invalid hour value" << std::endl;
               return -1;
            }
            if(range > 10){
               ss << ts0.substr(10, 2) << std::endl;
               ss >> min;
               ss.str("");
               if(min < 0 || min > 60){
                  std::cout << "date::set_time(): invalid min value" << std::endl;
                  return -1;
               }
            }
         }
      }
   }

   ts.tm_year = year - 1900;
   ts.tm_mon = month - 1;
   ts.tm_mday = day;
   ts.tm_hour = hour;
   ts.tm_min = min;
   std::cout << "date::set_time() get_stime(): " << get_stime() << std::endl;
   return 0;

}

tm& date::get_time(){
   return ts;
}

std::string date::get_stime(){
   std::string stime;
   int range = get_range();
/*
#ifdef DEBUG
   std::cout << "get_stime()" << std::endl;
   std::cout << "s_year(): " << s_year() << std::endl;
   std::cout << "s_month(): " << s_month() << std::endl;
   std::cout << "s_day(): " << s_day() << std::endl;
   std::cout << "s_hour(): " << s_hour() << std::endl;
   std::cout << "s_min(): " << s_min() << std::endl;
#endif
*/
   stime += s_year();

   if(range > 4){
      stime += s_month();
      if(range > 6){
         stime += s_day();
         if(range > 8){
            stime += s_hour();
            if(range > 10){
               stime += s_min();
            }
         }
      }
   }

   return stime;
}

int date::get_range(){
   if(year() > 0){
      if(month() > 0){
         if(day() > 0){
            if(hour() >= 0){
               if(min() >= 0){
                  return 12;
               }
               return 10;
            }
            return 8;
         }
         return 6;
      }
      return 4;
   }
   return -1;
}

bool date::is_child(date d){
   int range = get_range();
   int d_range = d.get_range();
   if(range < 0 || d_range < 0){
      std::cout << "range is not a valid value" << std::endl;
      return false;
   }
/*
   std::cout << "range: " << range << ", d_range: " << d_range << std::endl;
   std::cout << "year(): "<< year() << ", d.year(): " << d.year() << std::endl;
*/
   if((d_range - range) == 2 && year() == d.year()){
      if(range == 4)
         return true;
      else if(range == 6){
         if(month() == d.month())
            return true;
      }else if(range == 8){
         if(month() == d.month() && day() == d.day())
            return true;
      }else if(range == 10){
         if(month() == d.month() && day() == d.day() && hour() == d.hour())
            return true;
      }
   } 

   return false;
}

int date::year(){
   return ts.tm_year + 1900;
}
int date::month(){
   return ts.tm_mon+1;
}
int date::day(){
   return ts.tm_mday;
}
int date::hour(){
   return ts.tm_hour;
}
int date::min(){
   return ts.tm_min;
}

std::string date::s_year(int offset){
   std::stringstream ss;
   std::string s;
   ss << (year() + offset);
   s = ss.str();
   ss.str("");
   return s;
}

std::string date::s_month(int offset){
   std::stringstream ss;
   std::string s;
   ss << (month() + offset);
   s = ss.str();
   if(s.length() == 1){
      s = "0" + s;
   }
   ss.str("");
   return s;
}

std::string date::s_day(int offset){
   std::stringstream ss;
   std::string s;
   ss << (day() + offset);
   s = ss.str();
   if(s.length() == 1){
      s = "0" + s;
   }
   ss.str("");
   return s;
}

std::string date::s_hour(int offset){
   std::stringstream ss;
   std::string s;
   ss << (hour() + offset);
   s = ss.str();
   if(s.length() == 1){
      s = "0" + s;
   }
   ss.str("");
   return s;
}

std::string date::s_min(int offset){
   std::stringstream ss;
   std::string s;
   ss << (min() + offset);
   s = ss.str();
   if(s.length() == 1){
      s = "0" + s;
   }
   ss.str("");
   return s;
}

bool date::operator==(date& rhs){
   return year() == rhs.year() &&
      month() == rhs.month() &&
      day() == rhs.day() &&
      hour() == rhs.hour() &&
      min() == rhs.min();
}

bool date::operator<(date& rhs){
   if(year() != rhs.year()){
      return year() < rhs.year();
   }else if(month() != rhs.month()){
      return month() < rhs.month();
   }else if(day() != rhs.day()){
      return day() < rhs.day();
   }else if(hour() != rhs.hour()){
      return hour() < rhs.hour();
   }else if(min() != rhs.min()){
      return min() < rhs.min();
   }else{
      return false;
   }
}

bool date::operator>(date& rhs){
   if(year() != rhs.year()){
      return year() > rhs.year();
   }else if(month() != rhs.month()){
      return month() > rhs.month();
   }else if(day() != rhs.day()){
      return day() > rhs.day();
   }else if(hour() != rhs.hour()){
      return hour() > rhs.hour();
   }else if(min() != rhs.min()){
      return min() > rhs.min();
   }else{
      return false;
   }
}


