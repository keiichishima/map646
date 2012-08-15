#ifndef JSON_UTIL_H
#define JSON_UTIL_H

int json_merge(json_object* jobj);
tm find_lastupdate(json_object* jobj, json_object* jyear, json_object* jmonth, json_object* jday, json_object* jhour);
#endif
