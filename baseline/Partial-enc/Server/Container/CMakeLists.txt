aux_source_directory(. CONTAINER_SRC)

add_library(CONT ${CONTAINER_SRC})

target_link_libraries(CONT CommCore DatabaseCore)