cmake_minimum_required(VERSION 2.6)

project(iprotocluster)

option(BUILD_SHARED_LIBS "Build shared libraries" ON)
option(BUILD_LIBIPROTO "Build with libiproto from octopus project" ON)
option(WITH_GRAPHITE "Build with support of writting statistics to Graphite" OFF)
option(MY_MAIL_RU "my.mail.ru project customizations" OFF)

include(GNUInstallDirs)

if(BUILD_LIBIPROTO)
    include(ExternalProject)

    ExternalProject_Add(
        libiproto
        GIT_REPOSITORY https://github.com/delamonpansie/octopus.git
        PATCH_COMMAND cp ${PROJECT_SOURCE_DIR}/CMakeLists-libiproto.txt CMakeLists.txt
        CMAKE_ARGS -D CMAKE_INSTALL_PREFIX=${PROJECT_BINARY_DIR} -D CMAKE_POSITION_INDEPENDENT_CODE=ON
    )
endif()

configure_file(
    "${PROJECT_SOURCE_DIR}/iproto_config.h.in"
    "${PROJECT_BINARY_DIR}/include/iproto_config.h"
)

include_directories(${PROJECT_BINARY_DIR}/include ${LIBEV_INCLUDE_DIR})
link_directories(${PROJECT_BINARY_DIR}/lib)

set(iprotocluster_cflags "-std=gnu99 -Wall -Werror -ggdb3")

set(iprotocluster_sources iproto.c iproto_cluster.c iproto_shard.c
iproto_server.c iproto_message.c iproto_stat.c iproto_util.c
iproto_evapi.c iproto_server_ev.c iproto_message_ev.c)
if(WITH_GRAPHITE)
    set(iprotocluster_sources ${iprotocluster_sources} iproto_graphite.c)
endif()
if(MY_MAIL_RU)
    set(iprotocluster_sources ${iprotocluster_sources} iproto_my.c)
endif()

add_library(iprotocluster ${iprotocluster_sources})
if(BUILD_LIBIPROTO)
    add_dependencies(iprotocluster libiproto)
endif()
target_link_libraries(iprotocluster iproto pthread m rt dl)
set_target_properties(iprotocluster PROPERTIES COMPILE_FLAGS "${iprotocluster_cflags}")

add_library(iprotocluster_ev iproto_evapi_ev.c)
target_link_libraries(iprotocluster_ev ev)
set_target_properties(iprotocluster_ev PROPERTIES COMPILE_FLAGS "${iprotocluster_cflags}")

add_executable(iprotoclustertest test.c)
target_link_libraries(iprotoclustertest iprotocluster)
set_target_properties(iprotoclustertest PROPERTIES COMPILE_FLAGS "${iprotocluster_cflags}")

install(TARGETS iprotocluster
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)
install(TARGETS iprotocluster_ev
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)
install(FILES iprotocluster.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(FILES iproto_evapi.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(FILES iproto_util.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
if(BUILD_LIBIPROTO)
    install(FILES ${PROJECT_BINARY_DIR}/include/libiproto.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
    install(FILES ${PROJECT_BINARY_DIR}/include/iproto_def.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
endif()
