
SET(SRCS
	./src/account_ipc_marshal.c
	./src/account_free.c
)

INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/common/include)

INCLUDE(FindPkgConfig)
pkg_check_modules(clientpkgs REQUIRED
		dlog
		glib-2.0
		gio-unix-2.0
		capi-base-common
)

FOREACH(flag ${clientpkgs_CFLAGS})
	SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${flag}")
ENDFOREACH(flag)

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${EXTRA_CFLAGS} -Wall -Werror")
SET(CMAKE_LDFLAGS "-Wl,-zdefs")

ADD_DEFINITIONS("-DPREFIX=\"${CMAKE_INSTALL_PREFIX}\"")
ADD_DEFINITIONS("-DFACTORYFS=\"$ENV{FACTORYFS}\"")
ADD_DEFINITIONS("-DSLP_DEBUG")

ADD_CUSTOM_COMMAND(
	WORKING_DIRECTORY
	OUTPUT account-mgr-stub.c
	COMMAND gdbus-codegen --interface-prefix org.tizen.
	--generate-c-code account-mgr-stub ./account_mgr.xml
	COMMENT "Generating Account Client GDBus .c/.h")

ADD_LIBRARY(${PROJECT_NAME} SHARED ${SRCS} account-mgr-stub.c)
SET_TARGET_PROPERTIES(${PROJECT_NAME} PROPERTIES SOVERSION ${VERSION_MAJOR})
SET_TARGET_PROPERTIES(${PROJECT_NAME} PROPERTIES VERSION ${VERSION})

TARGET_LINK_LIBRARIES(${PROJECT_NAME} ${clientpkgs_LDFLAGS})

#INSTALL(TARGETS ${PROJECT_NAME} DESTINATION lib/account-common)
#INSTALL(TARGETS ${PROJECT_NAME} DESTINATION lib)

INSTALL(TARGETS ${PROJECT_NAME} DESTINATION ${LIBDIR}/account-common)
INSTALL(TARGETS ${PROJECT_NAME} DESTINATION ${LIBDIR})

INSTALL(FILES ${CMAKE_SOURCE_DIR}/common/account-mgr-stub.h DESTINATION include)
INSTALL(FILES ${CMAKE_SOURCE_DIR}/common/include/account_ipc_marshal.h DESTINATION include)
INSTALL(FILES ${CMAKE_SOURCE_DIR}/common/include/account_free.h DESTINATION include)
INSTALL(FILES ${CMAKE_SOURCE_DIR}/common/include/account-private.h DESTINATION include)
INSTALL(FILES ${CMAKE_SOURCE_DIR}/common/include/dbg.h DESTINATION include)

CONFIGURE_FILE(${CMAKE_SOURCE_DIR}/common/${PROJECT_NAME}.pc.in ${CMAKE_SOURCE_DIR}/common/${PROJECT_NAME}.pc @ONLY)
#INSTALL(FILES ${CMAKE_SOURCE_DIR}/common/${PROJECT_NAME}.pc DESTINATION lib/pkgconfig)
INSTALL(FILES ${CMAKE_SOURCE_DIR}/common/${PROJECT_NAME}.pc DESTINATION ${LIBDIR}/pkgconfig)
