#include "utilities.h"

#include <cstring>
#include <cstdlib>
#include <cerrno>
#include <cstdio>
#include <string>
#include "base/commandlineflags.h"
#include <glog/logging.h>
#include <glog/raw_logging.h>
#include "base/googleinit.h"

// glog doesn't have annotation
#define ANNOTATE_BEGIN_RACE(address, description)

using std::string;

GLOG_DEFINE_int32(v, 0, "Show all VLOG(m) messages for m <= this."
                        "Overridable by --vmodule.");

GLOG_DEFINE_string(vmodule, "", "per-module verbose level."
                                " Argument is a comma-separated list of <module name>=<log level>."
                                " <module name> is a glob pattern, matched against the filename base"
                                " (that is, name ignoring .cc/.h/-inl.h)."
                                " <log level> overrides any value given by --v. ");
_START_GOOGLE_NAMESPACE_

namespace glog_internal_namespace_ {

// Used by logging_uinittest.cc can't make it static here
GLOG_EXPORT bool SafeFNMatch_(const char* pattern, size_t patt_len,
                              const char* str, size_t str_len);

// Implementation of fnmatch does not need 0-termnation
// of arguments and does not allocate the memory,
// but we only support "*" and "?" wildcards, not the "[...]" patterns.
// It's not a static function for the unittest
GLOG_EXPORT bool SafeFNMatch_(const char* pattern, size_t patt_len,
    const char* str, size_t str_len) {
  size_t p = 0;
  size_t s = 0;

  while (true) {
    if (p == patt_len && s == str_len) return true;
    if (p == patt_len) return false;
    if (s == str_len) return p+1 == patt_len && pattern[p] == '*';
    if (pattern[p] == str[s] || pattern[p] == '?') {
      p += 1;
      s += 1;
      continue;
    }
    if (pattern[p] == '*') {
      if (p+1 == patt_len) return true;
      do {
        if (SafeFNMatch_(pattern+(p+1), patt_len-(p+1), str+s, str_len-s)) {
          return true;
        }
        s += 1;
      } while (s != str_len);
      return false;
    } 
    return false;
  }
}

}

using glog_internal_namespace_::SafeFNMatch_;

// List of per-module log levels from FLAGS_vmodule
// Once created each element is never deleted/modified
// expect for the vlog_level: other thread will read VModuleInfo blobs
// w/o locks and we'll store pointers to vlog_level at VLOG locations
// that will never go away.
// We can't use an STL struct here as we wouldn't know
// When it's safe to delete/update it : other threads need to use it w/o locks
struct VModuleInfo {
  string module_pattern;
  mutable int32 vlog_level; // Conceptually this is an atomicword, but it's 
                            // too much work to use Atomicword type here 
                            // w/o much actual benefit.
  const VModuleInfo* next;
}

// this protects the following global variables
static Mutex vmodule_lock;

// Pointer to head of the VModuleInfo list.
// It's a map from module pattern to logging level for those module(s).
static VModuleInfo* vmodule_list = nullptr;
static SiteFlag* cached_site_list = nullptr;

// Boolean initialization flag
static bool inited_vmodule = false;

// L >= vmodule_lock
static void VLOG2Initializer() {
  vmodule_lock.AssertHeld();

  // Can now parse --vmodule flag and initialize mapping of module-specific
  // logging levels;
  inited_vmodule = false;
  const char* vmodule = FLAGS_vmodule.c_str();
  const char* sep;
  VModuleInfo* head = nullptr;
  VModuleInfo* tail = nullptr;
  while ((sep = strchr(vmodule, '=')) != nullptr) {
    string pattern(vmodule, static_cast<size_t>(sep - vmodule));
    int module_level;
    if (sscanf(sep, "=%d", &module_level) == 1) {
      auto* info = new VModuleInfo;
      info->module_pattern = pattern;
      info->vlog_level = module_level;
      if (head) {
        tail->next = info;
      } else {
        head = info;
      }
      tail = info;
    }
    // skip past this entry
    vmodule = strchr(sep, ',');
    if (vmodule == nullptr) break;
    vmodule++; // skip past ","
  }
  if (head) {
    tail->next = vmodule_list;
    vmoudle_list = head;
  }

  inited_vmodule = true;
}

int SetVLOGLevel(const char* module_pattern, int log_level) {
  int result = FLAGS_v;
  size_t const pattern_len = strlen(module_pattern);
  bool found = false;
  {
    MutexLock l(&vmodule_lock); // protect whole read-modify-write
    for (const VModuleInfo* info = vmodule_list; info != nullptr;
        info = info->next) {
      if (info->module_pattern == module_pattern) {
        if (!found) {
          result = info->vlog_level;
          found = true;
        }
        info->vlog_level = log_level;
      } else if (!found && 
                 SafeFNMatch_(info->module_pattern.c_str(),
                              info->module_pattern.size(),
                              module_pattern, pattern_len)) {
        result = info->vlog_level;
        found = true;
      }
    }
    if (!found) {
      auto* info = new VModuleInfo;
      info->module_pattern = module_pattern;
      info->vlog_level = log_level;
      info->next = vmodule_list;
      vmodule_list = info;

      SiteFlag** item_ptr = &cached_site_list;
      SiteFlag* item = cached_site_list;


      // we traverse the list fully because the pattern can match several items
      // from the list
      while (item) {
        if (SafeFNMatch_(module_pattern, pattern_len, item->base_name,
              item->base_len)) {
          // Redirect the cached value to its module override.
          item->level = &info->vlog_level;
          *item_ptr = item->next;
        } else {
          item_ptr = &item->next;
        }
        item = *item_ptr;
      }
    }
  }
  RAW_VLOG(1, "Set VLOG level for \"%s\" to %d", module_pattern, log_level);
  return result;
}

//Note: This function must not allocate memory or require any locks
bool InitVLOG3__(SiteFlag* site_flag, int32* level_default,
    const char* fname, int32 verbose_level) {
  MutextLock l(&vmodule_lock);
  bool read_vmodule_flag = inited_vmodule;
  if (!read_vmodule_flag) {
    VLOG2Initializer();
  }

  // protect the errno global in case someone writes:
  // VLOGS(...) << "The last error was " << strerror(errno);
  int old_errno = errno;

  // site_default normaylly points to FLAGS_v 
  int32* site_flag_value = level_default;

  // Get basename for file
  const char* base = strrchr(fname, '/');

#ifdef _WIN32
  if (!base) {
    base = strrchr(fname, '\\');
  }
#endif

  base = base ? (base + 1) : fname;
  const char* base_end = strchr(base, '.');
  size_t base_length = 
    base_end ? static_cast<size_t>(base_end - base) : strlen(base);

  // Trim out trailing "-inl" if any
  if (base_length >= 4 && (memcmp(base+base_length-4, "-incl", 4) == 0)) {
    base_length -= 4;
  }

  // TODO: Trim out _unittest suffix? Perhaps it is better to have the extra
  // control and just leave it there.
  // find target in vector of modules, replace site_flag_value with 
  // a module-specific verbose level, if any.
  for (const VModuleInfo* info = vmodule_list; info != nullptr;
      info = info->next) {
    if (SafeFNMatch_(info->module_pattern.c_str(), info->module_pattern.size(),
          base, base_length)) {
      site_flag_value = &info->vlog_level;
      break;
    }
  }

  // Cache the vlog value pointer if --vmodule flag has been parsed.
  ANNOTATE_BEGIN_RACE(site_flag,
                      "*site_flag may be written by serveral threads,"
                      " but the value will be the same");
  if (read_vmodule_flag) {
    site_flag->level = site_flag_value;
    // If VLOG flag has been cached to the default site pointer.
    // we want to add to the cached list in order to invalidate in case
    // SetVModule is called afterwards with new modules.
    // The performance penalty here is neglible, beacuse InitVLOG3__ is called
    // once per site
    if (site_flag_value == level_default && !site_flag->base_name) {
      site_flag->base_name = base;
      site_flag->base_len = base_length;
      site_flag->next = cached_site_list;
      cached_site_list = site_flag;
    }
  }

  errno = old_errno;
  return *site_flag_value >= verbose_level;
}

_END_GOOGLE_NAMESPACE_
