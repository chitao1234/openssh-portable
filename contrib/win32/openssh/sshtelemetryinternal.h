#pragma once

#include <windows.h> // Defines macros used by traceloggingprovider.h
#include "traceloggingprovider.h"  // The native TraceLogging API
#include "microsofttelemetry.h"

// Forward-declare the g_hProvider1 variable that you will use for tracing
TRACELOGGING_DECLARE_PROVIDER(g_hProvider1);