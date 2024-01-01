cmake_minimum_required (VERSION 3.12)
set (CMAKE_C_STANDARD 23)
set (CMAKE_CXX_STANDARD 20)

# -------- Core Krakyn Library -----------------
# ----------------------------------------------

set (CORE_SRCS
    "krakyn/krakyn.cc"
    "krakyn/unix_socket.cc"
    "krakyn/authentication.cc"
    "krakyn/endpoints.cc")

set (CORE_INCS
    "krakyn/")

if (UNIX)
    set (CORE_INCS_PLATFORM "/usr/local/include")
else ()
    set (CORE_INCS_PLATFORM "")
endif ()

if (UNIX)
    set (CORE_LIB_PATHS "/usr/local/lib")
else ()
    set (CORE_LIB_PATHS "")
endif ()

project                    (krakyn)
add_library                (krakyn SHARED ${CORE_SRCS})
target_compile_definitions (krakyn PRIVATE KYN_BUILD_LIB)
target_include_directories (krakyn PRIVATE ${CORE_INCS} ${CORE_INCS_PLATFORM})
target_precompile_headers  (krakyn PUBLIC "krakyn/krakyn.hh")
target_link_directories    (krakyn PRIVATE ${CORE_LIB_PATHS})
target_link_libraries      (krakyn PRIVATE sodium)

# -------- Server Runtime ----------------------
# ----------------------------------------------

set (SERVER_SRCS
    "server/server.cc")

set (SERVER_INCS
    "server/"
    "./")

project                    (kserver)
add_executable             (kserver ${SERVER_SRCS})
target_include_directories (kserver PRIVATE ${SERVER_INCS})
target_link_libraries      (kserver krakyn)

# -------- Client Runtime ----------------------
# ----------------------------------------------

set (CLIENT_SRCS
    "client/launcher.cc")

set (CLIENT_INCS
    "client/"
    "./")

project                    (kclient)
add_executable             (kclient ${CLIENT_SRCS})
target_include_directories (kclient PRIVATE ${CLIENT_INCS})
target_link_libraries      (kclient krakyn)