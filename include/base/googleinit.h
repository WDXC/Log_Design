#ifndef _GOOGLEINIT_H
#define _GOOGLEINIT_H

class GoogleInitializer {
  public:
    using void_function = void(*)();
  GoogleInitializer(const char*, void_function f) {
    f();
  }
};

#define REGISTER_MODULE_INITIALIZER(name, body)                 \
  namespace {                                                   \
    static void google_init_module_##name () { body; }          \
    GoogleInitializer google_initializer_module_##name(#name,   \
        google_init_module_##name);                             \
  }

#endif
