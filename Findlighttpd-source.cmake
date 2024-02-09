# Try to find the lighttpd source code
#
# May require LIGHTTPD_VERSION to be set
#
# The following are set after configuration is done: 
#  LIGHTTPD_SOURCE_DIR_FOUND
#  LIGHTTPD_INCLUDE_DIRS
#
# TODO
# - Set a variable for the compile options

find_path(
    LIGHTTPD_INCLUDE_DIR
    NAMES
    first.h
    HINTS
    /usr/src/lighttpd
    /usr/src/lighttpd-${LIGHTTPD_VERSION}
    )

message("LIGHTTPD_SOURCE include dir = ${LIGHTTPD_INCLUDE_DIR}")

set(LIGHTTPD_INCLUDE_DIRS ${LIGHTTPD_INCLUDE_DIR})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(
    LIGHTTPD_SOURCE
    DEFAULT_MSG
    LIGHTTPD_INCLUDE_DIR
    )

mark_as_advanced(LIGHTTPD_INCLUDE_DIR)

