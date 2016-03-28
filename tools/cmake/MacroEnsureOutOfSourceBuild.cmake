# - ensure_out_of_source_build(<errorMessage>)
# ensure_out_of_source_build(<errorMessage>)

# Copyright (c) 2006, Alexander Neundorf, <neundorf@kde.org>
#
# Redistribution and use is allowed according to the terms of the BSD license.
# For details see the accompanying COPYING-CMAKE-SCRIPTS file.

macro (ensure_out_of_source_build _errorMessage)

    if ("${CMAKE_SOURCE_DIR}" STREQUAL "${CMAKE_BINARY_DIR}")
        message(SEND_ERROR "${_errorMessage}")
        message(FATAL_ERROR "Remove the file CMakeCache.txt in ${CMAKE_SOURCE_DIR} first.")
    endif()

endmacro (ensure_out_of_source_build)
