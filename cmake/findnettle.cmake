# NETTLE_LIBRARIES - List of nettle libraries
# NETTLE_INCLUDE_DIRS - where to find nettle include files
# NETTLE_FOUND - True if libnettle found.

IF(NETTLE_INCLUDE_DIRS)
	SET(NETTLE_FIND_QUIETLY YES)
ENDIF()

FIND_LIBRARY(NETTLE_LIBRARY NAMES nettle.a libnettle.a)
FIND_PATH(NETTLE_INCLUDE_DIRS nettle/aes.h nettle/cbc.h nettle/gcm.h)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(NETTLE DEFAULT_MSG NETTLE_LIBRARY NETTLE_INCLUDE_DIRS)

if(NETTLE_FOUND)
	set(NETTLE_LIBRARIES ${NETTLE_LIBRARY})
  MARK_AS_ADVANCED(NETTLE_LIBRARIES NETTLE_INCLUDE_DIRS)
endif()

