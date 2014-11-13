cmake_minimum_required(VERSION 2.6)

project(iprotocluster)

option(WITH_GRAPHITE "Build with support of writting statistics to Graphite" OFF)
option(MY_MAIL_RU "my.mail.ru project customizations" OFF)

configure_file(
    "${PROJECT_SOURCE_DIR}/iproto_config.h.in"
    "${PROJECT_BINARY_DIR}/iproto_config.h"
)

include_directories("${PROJECT_BINARY_DIR}")

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
target_link_libraries(iprotocluster iproto ev pthread m)
set_target_properties(iprotocluster PROPERTIES COMPILE_FLAGS "${iprotocluster_cflags}")

add_executable(iprotoclustertest test.c)
target_link_libraries(iprotoclustertest iprotocluster)
set_target_properties(iprotoclustertest PROPERTIES COMPILE_FLAGS "${iprotocluster_cflags}")

install(TARGETS iprotocluster
    LIBRARY DESTINATION ${LIB_INSTALL_DIR}
    ARCHIVE DESTINATION ${LIB_INSTALL_DIR}
)
install(FILES iprotocluster.h DESTINATION include)
install(FILES iproto_evapi.h DESTINATION include)
install(FILES iproto_util.h DESTINATION include)
