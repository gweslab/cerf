#include "host_input_method.h"

bool InputMethodReportsClose() { return true; }

Qt::InputMethodHints InputMethodHints() { return Qt::ImhNoPredictiveText | Qt::ImhNoAutoUppercase | Qt::ImhMultiLine; }
