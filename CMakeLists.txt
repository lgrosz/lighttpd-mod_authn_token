cmake_minimum_required(3.10.0)

project(lighttpd-mod_authn_token C)

set(Lighttpd_VERSION "1.4" CACHE STRING "Lighty version")

find_package(lighttpd-source REQUIRED)

add_library(mod_authn_token SHARED mod_authn_token.c)

if(Lighttpd_FOUND)
    target_include_directories(mod_authn_token PUBLIC ${Lighttpd_INCLUDE_DIRS})
    target_compile_definitions(mod_authn_token PUBLIC ${Lighttpd_DEFINITIONS} )
endif()

set_target_properties(
    mod_authn_token
    PROPERTIES
    PREFIX ""
    )

include(GNUInstallDirs)
install(
    TARGETS mod_authn_token
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    )
