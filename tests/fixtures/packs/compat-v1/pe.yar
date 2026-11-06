rule compat_pe : format { strings: $mz = "MZ" condition: $mz at 0 }
