#ifndef DATE_H
#define DATE_H

class date{
   tm ts;
public:
  
   date();
   date(tm ts0);
   date(std::string ts0);
   
   void set_time(tm ts0);
   int set_time(std::string ts0);
        
   tm& get_time();
   std::string get_stime();
   int get_range();

   bool is_child(date);
   
   int year();
   int month();
   int day();
   int hour();
   int min();
   
   std::string s_year(int offset = 0);
   std::string s_month(int offset = 0);
   std::string s_day(int offset = 0);
   std::string s_hour(int offset = 0);
   std::string s_min(int offset = 0);
   
   bool operator==(date& rhs);
   bool operator<(date& rhs);
   bool operator>(date& rhs);
};

#endif
