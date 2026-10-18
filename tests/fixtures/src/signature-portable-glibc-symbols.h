#define __attribute_copy__(name)
#define weak_alias(name, aliasname) _weak_alias(name, aliasname)
#define _weak_alias(name, aliasname) \
  extern __typeof(name) aliasname __attribute__((weak, alias(#name))) __attribute_copy__(name);
#define libc_hidden_def(name)
