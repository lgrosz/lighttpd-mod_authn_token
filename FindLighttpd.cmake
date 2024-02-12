# FindLighttpd - Find lighttpd headers and definitions
#
# Sample:
#
#   find_package(Lighttpd REQUIRED)
#   if(Lighttpd_FOUND)
#      target_include_directories(... ${Lighttpd_INCLUDE_DIRS})
#      target_compile_definitions(... ${Lighttpd_DEFINITIONS})
#   endif()
#
# Variables used by this modules need to be set before calling find_package
#
#   Lighttpd_VERSION
#
# Variables provided by this module
#
#   Lighttpd_FOUND
#
#   Lighttpd_INCLUDE_DIRS
#
#   Lighttpd_DEFINITIONS

# Looks for header files
unset(Lighttpd_INCLUDE_DIRS)
find_path(
    Lighttpd_INCLUDE_DIR
    NAMES
    first.h
    HINTS
    /usr/src/lighttpd
    /usr/src/lighttpd/src
    /usr/include/lighttpd
    /usr/src/lighttpd-${Lighttpd_VERSION}
    /usr/src/lighttpd/src-${Lighttpd_VERSION}
    /usr/include/lighttpd-${Lighttpd_VERSION}
    )

set(Lighttpd_INCLUDE_DIRS ${Lighttpd_INCLUDE_DIR})

find_package_handle_standard_args(Lighttpd DEFAULT_MSG Lighttpd_INCLUDE_DIRS)

if (Lighttpd_FOUND)
    if (EXISTS "${Lighttpd_INCLUDE_DIRS}/config.h")
        set(Lighttpd_DEFINITIONS "HAVE_CONFIG_H")
    else()
        set(Lighttpd_DEFINITIONS "")
    endif()
endif()

mark_as_advanced(
	Lighttpd_FOUND
	Lighttpd_INCLUDE_DIRS
	Lighttpd_DEFINITIONS
	)

